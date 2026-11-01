import io
import os
import re
import tempfile
import unittest

from helpers import TODAY  # noqa: F401  (sets sys.path)
from app import create_app
from app.auth import create_user
from app.db import connect
from app.reports import csv_safe
from app.scanner import check_target, ScanRefused


class WebTests(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        self.app = create_app({"DATABASE": path, "TESTING": True, "SECRET_KEY": "test"})
        db = connect(path)
        create_user(db, "admin", "AdminPass12345", "admin")
        create_user(db, "viewer", "ViewerPass12345", "viewer")
        db.close()
        self.c = self.app.test_client()

    def token(self, client=None, url="/login"):
        html = (client or self.c).get(url).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def login(self, user="admin", pw="AdminPass12345"):
        t = self.token()
        return self.c.post("/login", data={"username": user, "password": pw, "csrf_token": t})

    def post(self, url, data, tok_url="/assets"):
        data = dict(data, csrf_token=self.token(url=tok_url))
        return self.c.post(url, data=data, follow_redirects=True)

    def test_login_required(self):
        self.assertEqual(self.c.get("/").status_code, 302)
        self.assertEqual(self.c.get("/findings").status_code, 302)

    def test_csrf_enforced(self):
        self.assertEqual(self.c.post("/login", data={"username": "admin", "password": "x"}).status_code, 400)

    def test_wrong_password_and_login_ok(self):
        self.assertIn(b"Invalid username", self.c.post("/login", data={"username": "admin", "password": "bad",
                      "csrf_token": self.token()}, follow_redirects=True).data)
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.c.get("/").status_code, 200)

    def test_open_redirect_blocked(self):
        t = self.token()
        r = self.c.post("/login?next=//evil.com", data={"username": "admin", "password": "AdminPass12345", "csrf_token": t})
        self.assertNotIn("evil.com", r.headers["Location"])

    def test_viewer_cannot_modify(self):
        self.login("viewer", "ViewerPass12345")
        self.assertEqual(self.c.get("/assets/new").status_code, 403)
        self.assertEqual(self.c.get("/import").status_code, 403)
        self.assertEqual(self.c.get("/users").status_code, 403)

    def test_full_flow_assets_import_report_resolve(self):
        self.login()
        self.assertIn(b"Asset registered", self.post("/assets/new", {"name": "web1", "criticality": "5", "ip": "10.0.0.9",
                      "asset_type": "Server"}, "/assets/new").data)
        csv = b"asset,cve,title,severity\nweb1,CVE-2021-44228,<script>alert(1)</script>,10\nnobody,CVE-2020-1234,x,5\n"
        data = {"file": (io.BytesIO(csv), "r.csv"), "csrf_token": self.token(url="/import")}
        r = self.c.post("/import", data=data, content_type="multipart/form-data")
        body = r.get_data(as_text=True)
        self.assertIn("not registered", body)
        self.assertNotIn("<script>alert(1)</script>", self.c.get("/findings").get_data(as_text=True))  # XSS escaped
        self.assertIn("CVE-2021-44228", self.c.get("/findings").get_data(as_text=True))
        r = self.post("/findings/1/update", {"status": "Resolved", "action": "patched", "assignee": "Ali"}, "/findings/1")
        self.assertIn(b"Finding updated", r.data)
        rep = self.c.get("/reports").get_data(as_text=True)
        self.assertIn("Fixed", rep)
        self.assertEqual(self.c.get("/reports/findings.csv").status_code, 200)

    def test_invalid_upload_rejected_cleanly(self):
        self.login()
        data = {"file": (io.BytesIO(b"not,valid\n1,2"), "bad.csv"), "csrf_token": self.token(url="/import")}
        r = self.c.post("/import", data=data, content_type="multipart/form-data")
        self.assertIn(b"Import rejected", r.data)

    def test_security_headers(self):
        h = self.c.get("/login").headers
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])

    def test_csv_formula_injection_neutralised(self):
        self.assertEqual(csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")

    def test_scanner_refuses_public_ip(self):
        for ip in ("8.8.8.8", "1.1.1.1", None):
            with self.assertRaises(ScanRefused):
                check_target(ip)
        self.assertEqual(check_target("127.0.0.1"), "127.0.0.1")

    def test_scanner_local_port(self):
        import socket
        from helpers import make_db, add_asset
        from app.scanner import scan_asset
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        db, _ = make_db(); aid = add_asset(db, "lab", 4, "127.0.0.1")
        out = scan_asset(db, aid, None, TODAY, services={port: ("TEST", "Test service exposed", 6.0)})
        srv.close()
        self.assertEqual(out["open_ports"], [port])
        self.assertEqual(out["result"]["imported"], 1)


if __name__ == "__main__":
    unittest.main()
