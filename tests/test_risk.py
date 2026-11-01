import unittest
from helpers import make_db, add_asset, TODAY
from app import risk_engine as re_
from app.assets import update_asset, validate_asset
from app.importer import ingest
from app.vulnerability_manager import list_findings


def load(db, items):
    rows = [(i, {"asset": a, "title": t, "severity": s}) for i, (a, t, s) in enumerate(items, 1)]
    return ingest(db, rows, filename="t.csv", fmt="CSV", user_id=None, today=TODAY)


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.db, _ = make_db()

    def test_formula(self):
        self.assertEqual(re_.priority(9, 5), 45)
        self.assertEqual(re_.priority(8, 2), 16)
        self.assertEqual(re_.priority(5, 4), 20)

    def test_ordering_matches_pdf_example(self):
        add_asset(self.db, "a5", 5); add_asset(self.db, "a2", 2); add_asset(self.db, "a4", 4)
        load(self.db, [("a5", "V-001", 9), ("a2", "V-002", 8), ("a4", "V-003", 5)])
        self.assertEqual([r["title"] for r in list_findings(self.db)], ["V-001", "V-003", "V-002"])

    def test_invalid_inputs(self):
        for s in (0, -1, 11, "abc"):
            with self.assertRaises(ValueError):
                re_.validate_severity(s)
        with self.assertRaises(ValueError):
            re_.validate_criticality(6)

    def test_asset_criticality_change_recalculates(self):
        aid = add_asset(self.db, "srv", 2)
        load(self.db, [("srv", "V", 8)])
        self.assertEqual(list_findings(self.db)[0]["priority"], 16)
        clean, _ = validate_asset({"name": "srv", "criticality": 5})
        update_asset(self.db, aid, clean)
        self.assertEqual(list_findings(self.db)[0]["priority"], 40)
        self.assertGreaterEqual(self.db.execute("SELECT COUNT(*) FROM history_risk").fetchone()[0], 2)

    def test_severity_change_recalculates(self):
        add_asset(self.db, "srv", 4)
        load(self.db, [("srv", "V", 5)])
        load(self.db, [("srv", "V", 9)])
        self.assertEqual(list_findings(self.db)[0]["priority"], 36)

    def test_adjusted_priority_exposure_and_epss(self):
        self.assertEqual(re_.adjusted_priority(8, 5, True, 0.5), round(40 * 1.25 * 1.5, 2))
        self.assertEqual(re_.adjusted_priority(8, 5), 40)

    def test_bands(self):
        self.assertEqual([re_.severity_label(x) for x in (9.0, 7.0, 4.0, 3.9)], ["Critical", "High", "Medium", "Low"])


if __name__ == "__main__":
    unittest.main()
