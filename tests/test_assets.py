import unittest
from helpers import make_db, add_asset
from app.assets import validate_asset, create_asset, list_assets


class AssetTests(unittest.TestCase):
    def setUp(self):
        self.db, _ = make_db()

    def test_register_valid(self):
        aid = add_asset(self.db, "srv1", 5, "10.0.0.5")
        self.assertEqual(self.db.execute("SELECT criticality FROM assets WHERE id=?", (aid,)).fetchone()[0], 5)

    def test_invalid_criticality_and_ip(self):
        for bad in (0, 6, "x", 2.5, None):
            _, errs = validate_asset({"name": "a", "criticality": bad})
            self.assertTrue(errs, bad)
        _, errs = validate_asset({"name": "a", "criticality": 3, "ip": "999.1.1.1"})
        self.assertTrue(errs)
        _, errs = validate_asset({"name": "", "criticality": 3})
        self.assertTrue(errs)

    def test_duplicate_name_rejected_case_insensitive(self):
        add_asset(self.db, "Srv1")
        clean, _ = validate_asset({"name": "srv1", "criticality": 2})
        with self.assertRaises(ValueError):
            create_asset(self.db, clean)

    def test_list_sorted_by_risk(self):
        add_asset(self.db, "a"); add_asset(self.db, "b")
        self.assertEqual(len(list_assets(self.db)), 2)


if __name__ == "__main__":
    unittest.main()
