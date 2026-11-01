"""EnterpriseVMS entry point.

  python app.py                       run the web app on http://127.0.0.1:5000
  python app.py --demo                load sample assets + scan results first
  python app.py create-user NAME ROLE create a user (viewer/analyst/admin)
"""
import getpass
import os
import secrets
import sys

from app import create_app
from app.auth import create_user
from app.db import connect, today_iso
from app.importer import import_file


def seed_admin(db):
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        pw = os.environ.get("ADMIN_PASSWORD")
        generated = not pw or len(pw) < 10 or pw == "ChangeThisStrongPassword!"
        if generated:
            pw = secrets.token_urlsafe(12)
        create_user(db, "admin", pw, "admin")
        print("\n  First run: user 'admin' created." + (f"\n  Generated password (shown once): {pw}\n" if generated
                                                        else "\n  Password taken from ADMIN_PASSWORD.\n"))


def load_demo(db):
    import csv
    from app.assets import create_asset, validate_asset
    if db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]:
        return
    with open("sample_data/assets.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            clean, errs = validate_asset(row)
            if not errs:
                create_asset(db, clean)
    for fn in ("vulnerability_results.csv",):
        with open(f"sample_data/{fn}", "rb") as f:
            print("  Demo import:", {k: v for k, v in import_file(db, f.read(), fn, None, today_iso()).items() if k != "rejected"})


def main():
    app = create_app()
    db = connect(app.config["DATABASE"])
    if len(sys.argv) >= 4 and sys.argv[1] == "create-user":
        create_user(db, sys.argv[2], getpass.getpass("Password: "), sys.argv[3])
        print("User created.")
        return
    seed_admin(db)
    if "--demo" in sys.argv:
        load_demo(db)
    db.close()
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)


if __name__ == "__main__":
    main()
