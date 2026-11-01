import os
from app import create_app
from app.auth import create_user
from app.db import connect

app = create_app()

# Seed admin user if it's the first run
with app.app_context():
    db = connect(app.config["DATABASE"])
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        pw = os.environ.get("ADMIN_PASSWORD", "Admin@123456")
        create_user(db, "admin", pw, "admin")
        print("Admin user seeded.")
    db.close()

if __name__ == "__main__":
    app.run()
