import json
import unittest
from helpers import make_db, add_asset, TODAY
from app.importer import import_file, ImportFileError

CSV = b"asset,cve,title,severity\nweb,CVE-2021-44228,Log4j,10\ndb,,Weak TLS,Medium\n"


class ImporterTests(unittest.TestCase):
    def setUp(self):
        self.db, _ = make_db()
        self.web = add_asset(self.db, "web", 5, "10.0.0.10")
        self.dbs = add_asset(self.db, "db", 4, "10.0.0.20")

    def count(self, t="findings"):
        return self.db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]

    def test_links_to_correct_assets(self):
        r = import_file(self.db, CSV, "a.csv", None, TODAY)
        self.assertEqual(r["imported"], 2)
        row = self.db.execute("SELECT a.name FROM findings f JOIN vulnerabilities v ON v.id=f.vuln_id "
                              "JOIN assets a ON a.id=f.asset_id WHERE v.cve_id='CVE-2021-44228'").fetchone()
        self.assertEqual(row[0], "web")

    def test_same_file_twice_no_duplicates(self):
        import_file(self.db, CSV, "a.csv", None, TODAY)
        r = import_file(self.db, CSV, "a.csv", None, TODAY)
        self.assertEqual((r["imported"], r["duplicates"]), (0, 2))
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.count("tasks_remediation"), 2)

    def test_duplicate_rows_inside_file(self):
        r = import_file(self.db, CSV + b"web,CVE-2021-44228,Log4j,10\n", "a.csv", None, TODAY)
        self.assertEqual((r["imported"], r["duplicates"]), (2, 1))

    def test_invalid_rows_reported(self):
        bad = CSV + b"ghost,CVE-2022-1111,X,5\nweb,CVE-BAD,X,5\nweb,CVE-2022-2222,X,99\nweb,CVE-2022-3333,,\n"
        r = import_file(self.db, bad, "a.csv", None, TODAY)
        self.assertEqual(len(r["rejected"]), 4)
        reasons = " ".join(w for _, w in r["rejected"])
        self.assertIn("not registered", reasons); self.assertIn("Invalid CVE", reasons)
        self.assertEqual(self.count(), 2)

    def test_invalid_files(self):
        for content, name in ((b"", "a.csv"), (b"foo,bar\n1,2\n", "a.csv"), (b"{bad", "a.json"),
                              (b"[]", "a.json"), (b"x", "a.txt"), (b"\xff\xfe\x00", "a.csv")):
            with self.assertRaises(ImportFileError, msg=name):
                import_file(self.db, content, name, None, TODAY)

    def test_json_formats(self):
        data = {"findings": [{"asset": "10.0.0.20", "title": "T", "severity": "high"}, "garbage"]}
        r = import_file(self.db, json.dumps(data).encode(), "a.json", None, TODAY)
        self.assertEqual((r["imported"], len(r["rejected"])), (1, 1))

    def test_resolved_finding_reopens_when_it_reappears(self):
        import_file(self.db, CSV, "a.csv", None, TODAY)
        self.db.execute("UPDATE findings SET status='Resolved'"); self.db.commit()
        r = import_file(self.db, CSV, "b.csv", None, TODAY)
        self.assertEqual(r["reopened"], 2)

    def test_rescan_verification(self):
        import_file(self.db, CSV, "a.csv", None, TODAY)
        r = import_file(self.db, b"asset,cve,title,severity\nweb,CVE-2021-44228,Log4j,10\n", "b.csv",
                        None, TODAY, auto_verify=True)
        self.assertEqual(r["verified"], 0)  # only 'web' touched, its single finding still present
        r = import_file(self.db, b"asset,cve,title,severity\nweb,CVE-2099-0001,New,5\n", "c.csv",
                        None, TODAY, auto_verify=True)
        self.assertEqual(r["verified"], 1)  # Log4j on web no longer present
        st = self.db.execute("SELECT status FROM findings f JOIN vulnerabilities v ON v.id=f.vuln_id "
                             "WHERE v.cve_id='CVE-2021-44228'").fetchone()[0]
        self.assertEqual(st, "Resolved")


if __name__ == "__main__":
    unittest.main()
