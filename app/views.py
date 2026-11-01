from flask import (Blueprint, Response, abort, flash, g, redirect, render_template, request,
                   session, url_for)

from . import assets as assets_mod
from . import auth, remediation, reports, scanner
from .db import get_db, today_iso
from .importer import ImportFileError, import_file
from .models import ACTIVE, ASSET_TYPES, ROLES, STATUSES
from .vulnerability_manager import (dashboard, finding_history, get_finding, list_findings,
                                    overdue_findings)

bp = Blueprint("main", __name__)


@bp.app_context_processor
def inject():
    return {"STATUSES": STATUSES, "ASSET_TYPES": ASSET_TYPES, "ROLES": ROLES,
            "user": getattr(g, "user", None), "today": today_iso()}


def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else url_for("main.home")


# ---------------------------------------------------------------- auth
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        key = ((request.form.get("username") or "").lower(), request.remote_addr)
        if auth.throttled(key):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html"), 429
        u = auth.authenticate(db, request.form.get("username"), request.form.get("password"))
        if u:
            session.clear()
            session["uid"] = u["id"]
            session.permanent = True
            return redirect(safe_next(request.args.get("next")))
        auth.register_fail(key)
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/account", methods=["GET", "POST"])
@auth.login_required()
def account():
    if request.method == "POST":
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
        from werkzeug.security import check_password_hash, generate_password_hash
        try:
            if not check_password_hash(row["password_hash"], request.form.get("old", "")):
                raise ValueError("Current password is wrong.")
            auth.validate_password(request.form.get("new", ""))
            if request.form.get("new") != request.form.get("confirm"):
                raise ValueError("Passwords do not match.")
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(request.form["new"]), g.user["id"]))
            db.commit()
            flash("Password changed.", "ok")
        except ValueError as e:
            flash(str(e), "error")
    return render_template("account.html")


@bp.route("/users", methods=["GET", "POST"])
@auth.login_required("admin")
def users():
    db = get_db()
    if request.method == "POST":
        try:
            auth.create_user(db, request.form.get("username"), request.form.get("password"),
                             request.form.get("role"))
            flash("User created.", "ok")
        except ValueError as e:
            flash(str(e), "error")
    return render_template("users.html", rows=db.execute("SELECT id,username,role,created_at FROM users").fetchall())


# ----------------------------------------------------------- dashboard
@bp.route("/")
@auth.login_required()
def home():
    db = get_db()
    d = dashboard(db, today_iso())
    sev = d["severity"]
    total = sum(sev.values()) or 1
    colors = {"Critical": "#e5484d", "High": "#f76b15", "Medium": "#f5d90a", "Low": "#30a46c"}
    acc, parts = 0.0, []
    for k, v in sev.items():
        parts.append(f"{colors[k]} {acc:.1f}% {acc + 100 * v / total:.1f}%")
        acc += 100 * v / total
    donut = "conic-gradient(" + ", ".join(parts) + ")" if sum(sev.values()) else "#2a3550"
    return render_template("dashboard.html", d=d, donut=donut, colors=colors,
                           top_assets=assets_mod.list_assets(db)[:6],
                           top_findings=list_findings(db, limit=8),
                           overdue=overdue_findings(db, today_iso())[:5])


# -------------------------------------------------------------- assets
@bp.route("/assets")
@auth.login_required()
def assets():
    q = request.args.get("q", "").strip()
    return render_template("assets.html", rows=assets_mod.list_assets(get_db(), q), q=q)


@bp.route("/assets/new", methods=["GET", "POST"])
@auth.login_required("analyst")
def asset_new():
    form = request.form if request.method == "POST" else {"criticality": 3}
    if request.method == "POST":
        clean, errors = assets_mod.validate_asset(request.form)
        if not errors:
            try:
                aid = assets_mod.create_asset(get_db(), clean)
                flash("Asset registered.", "ok")
                return redirect(url_for("main.asset_detail", aid=aid))
            except ValueError as e:
                errors.append(str(e))
        for e in errors:
            flash(e, "error")
    return render_template("asset_form.html", a=form, title="Register asset")


@bp.route("/assets/<int:aid>")
@auth.login_required()
def asset_detail(aid):
    db = get_db()
    a = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone() or abort(404)
    from .risk_engine import asset_risk
    return render_template("asset_detail.html", a=a, risk=asset_risk(db, aid),
                           rows=list_findings(db, status="all", asset_id=aid))


@bp.route("/assets/<int:aid>/edit", methods=["GET", "POST"])
@auth.login_required("analyst")
def asset_edit(aid):
    db = get_db()
    a = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone() or abort(404)
    if request.method == "POST":
        clean, errors = assets_mod.validate_asset(request.form)
        if not errors:
            try:
                assets_mod.update_asset(db, aid, clean)
                flash("Asset updated; related priorities recalculated.", "ok")
                return redirect(url_for("main.asset_detail", aid=aid))
            except ValueError as e:
                errors.append(str(e))
        for e in errors:
            flash(e, "error")
        a = request.form
    return render_template("asset_form.html", a=a, title="Edit asset", edit=aid)


@bp.route("/assets/<int:aid>/delete", methods=["POST"])
@auth.login_required("admin")
def asset_delete(aid):
    assets_mod.delete_asset(get_db(), aid)
    flash("Asset and its findings deleted.", "ok")
    return redirect(url_for("main.assets"))


# ------------------------------------------------------------ findings
@bp.route("/findings")
@auth.login_required()
def findings():
    f = {k: request.args.get(k, d) for k, d in (("status", "active"), ("severity", ""), ("q", ""))}
    aid = request.args.get("asset", type=int)
    rows = list_findings(get_db(), f["status"], f["severity"] or None, aid, f["q"])
    return render_template("findings.html", rows=rows, f=f, aid=aid)


@bp.route("/findings/<int:fid>")
@auth.login_required()
def finding_detail(fid):
    db = get_db()
    row = get_finding(db, fid) or abort(404)
    return render_template("finding_detail.html", f=row, history=finding_history(db, fid))


@bp.route("/findings/<int:fid>/update", methods=["POST"])
@auth.login_required("analyst")
def finding_update(fid):
    try:
        remediation.update_finding(get_db(), fid, status=request.form.get("status"),
                                   assignee=request.form.get("assignee"),
                                   due_date=request.form.get("due_date"),
                                   action=request.form.get("action"), user=g.user["username"])
        flash("Finding updated.", "ok")
    except LookupError:
        abort(404)
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("main.finding_detail", fid=fid))


# -------------------------------------------------------------- import
@bp.route("/import", methods=["GET", "POST"])
@auth.login_required("analyst")
def import_view():
    result = None
    if request.method == "POST":
        up = request.files.get("file")
        if not up or not up.filename:
            flash("Choose a CSV or JSON file.", "error")
        else:
            try:
                result = import_file(get_db(), up.read(), up.filename, g.user["id"], today_iso(),
                                     auto_verify=request.form.get("auto_verify") == "on")
            except ImportFileError as e:
                flash(f"Import rejected: {e}", "error")
    return render_template("import.html", result=result)


@bp.route("/scans")
@auth.login_required()
def scans():
    rows = get_db().execute("""SELECT s.*, u.username FROM scans s LEFT JOIN users u ON u.id=s.created_by
                               ORDER BY s.id DESC LIMIT 200""").fetchall()
    return render_template("scans.html", rows=rows)


@bp.route("/scanner", methods=["GET", "POST"])
@auth.login_required("analyst")
def lab_scanner():
    db, out = get_db(), None
    if request.method == "POST":
        if request.form.get("confirm") != "on":
            flash("You must confirm that you are authorised to scan this lab asset.", "error")
        else:
            try:
                out = scanner.scan_asset(db, request.form.get("asset_id", type=int), g.user["id"], today_iso())
            except (scanner.ScanRefused, ValueError) as e:
                flash(str(e), "error")
    return render_template("scanner.html", out=out, rows=db.execute(
        "SELECT id,name,ip FROM assets WHERE ip IS NOT NULL ORDER BY name").fetchall())


# --------------------------------------------------------------- tasks
@bp.route("/tasks")
@auth.login_required()
def tasks():
    rows = [r for r in list_findings(get_db(), "active", limit=1000)]
    return render_template("tasks.html", rows=rows)


# ------------------------------------------------------------- reports
@bp.route("/reports")
@auth.login_required()
def report_view():
    return render_template("reports.html", r=reports.report_data(get_db(), today_iso()))


@bp.route("/reports/findings.csv")
@auth.login_required()
def report_csv():
    rows = list_findings(get_db(), request.args.get("status", "all"), limit=100000)
    return Response(reports.findings_csv(rows), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=findings.csv"})


@bp.route("/reports/report.pdf")
@auth.login_required()
def report_pdf():
    pdf = reports.report_pdf(reports.report_data(get_db(), today_iso()))
    if pdf is None:
        flash("PDF export needs the 'reportlab' package (pip install reportlab).", "error")
        return redirect(url_for("main.report_view"))
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=vulnerability_report.pdf"})
