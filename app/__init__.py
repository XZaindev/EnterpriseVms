"""EnterpriseVMS application factory (security foundation first)."""
import os
import secrets
from pathlib import Path

from flask import Flask, abort, request, session

from .db import close_db, init_db
from .risk_engine import severity_label

BASE_DIR = Path(__file__).resolve().parent.parent


def load_env(path=BASE_DIR / ".env"):
    """Tiny .env reader (no extra dependency)."""
    if Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _secret_key(instance_path):
    if os.environ.get("SECRET_KEY") and os.environ["SECRET_KEY"] != "change-me-to-a-long-random-string":
        return os.environ["SECRET_KEY"]
    f = Path(instance_path) / "secret.key"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
        try:
            f.chmod(0o600)
        except OSError:
            pass
    return f.read_text().strip()


def create_app(config=None):
    load_env()
    app = Flask(__name__, instance_path=str(BASE_DIR / "instance"))
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(
        DATABASE=str(Path(app.instance_path) / "vms.db"),
        SECRET_KEY=_secret_key(app.instance_path),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    )
    if config:
        app.config.update(config)
    init_db(app.config["DATABASE"]).close()
    app.teardown_appcontext(close_db)

    @app.before_request
    def csrf_protect():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not secrets.compare_digest(sent, session["csrf"]):
                abort(400, "Invalid or missing CSRF token.")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    app.jinja_env.globals["csrf_token"] = lambda: session.get("csrf", "")
    app.jinja_env.filters["band"] = severity_label
    from .db import today_iso
    app.jinja_env.globals["today_iso"] = today_iso

    from .views import bp
    app.register_blueprint(bp)
    return app
