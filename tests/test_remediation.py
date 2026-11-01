import unittest
from helpers import make_db, add_asset, TODAY
from app.importer import ingest
from app.remediation import update_finding
from app.vulnerability_manager import dashboard, overdue_findings, get_finding


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.db, _ = make_db()
        add_asset(self.db, "srv", 5)
        ingest(self.db, [(1, {"asset": "srv", "title": "A", "severity": 10}),
                         (2, {"asset": "srv", "title": "B", "severity": 5})],
               filename="x.csv", fmt="CSV", user_id=None, today=TODAY)
        self.ids = [r[0] for r in self.db.execute("SELECT id FROM findings ORDER BY priority DESC")]

    def test_resolve_updates_status_and_dashboard(self):
        before = dashboard(self.db, TODAY)
        update_finding(self.db, self.ids[0], status="Resolved", assignee="Ali", action="Patched", user="t")
        after = dashboard(self.db, TODAY)
        self.assertEqual(get_finding(self.db, self.ids[0])["status"], "Resolved")
        self.assertEqual((before["open"], after["open"]), (2, 1))
        self.assertEqual(after["critical_open"], 0)
        self.assertGreater(after["risk_reduction_pct"], 0)
        self.assertEqual(after["remediation_rate"], 50.0)

    def test_risk_accepted_needs_justification(self):
        with self.assertRaises(ValueError):
            update_finding(self.db, self.ids[0], status="Risk Accepted")
        update_finding(self.db, self.ids[0], status="Risk Accepted", action="Legacy system, compensating control")

    def test_invalid_status_and_date(self):
        with self.assertRaises(ValueError):
            update_finding(self.db, self.ids[0], status="Done")
        with self.assertRaises(ValueError):
            update_finding(self.db, self.ids[0], status="Open", due_date="31/12/2026")
        with self.assertRaises(LookupError):
            update_finding(self.db, 9999, status="Open")

    def test_owner_and_due_date_stored(self):
        update_finding(self.db, self.ids[1], status="In Progress", assignee="Sara", due_date="2026-12-01")
        f = get_finding(self.db, self.ids[1])
        self.assertEqual((f["assignee"], f["due_date"], f["status"]), ("Sara", "2026-12-01", "In Progress"))

    def test_overdue_detection_uses_sla(self):
        self.assertEqual(len(overdue_findings(self.db, TODAY)), 0)
        self.assertEqual(len(overdue_findings(self.db, "2027-06-01")), 2)
        update_finding(self.db, self.ids[0], status="Resolved", action="ok")
        self.assertEqual(len(overdue_findings(self.db, "2027-06-01")), 1)


if __name__ == "__main__":
    unittest.main()
