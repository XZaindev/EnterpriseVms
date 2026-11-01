"""Management reports: what is fixed, what still needs fixing."""
import csv
import io

from .risk_engine import severity_label
from .vulnerability_manager import list_findings, dashboard, overdue_findings
from .assets import list_assets


def report_data(db, today):
    return {
        "today": today,
        "summary": dashboard(db, today),
        "open": list_findings(db, status="active", limit=5000),
        "resolved": list_findings(db, status="Resolved", limit=5000),
        "accepted": list_findings(db, status="Risk Accepted", limit=5000),
        "overdue": overdue_findings(db, today),
        "assets": list_assets(db),
    }


def csv_safe(value):
    """Neutralise spreadsheet formula injection."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def findings_csv(rows):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Priority(R)", "Severity(S)", "Band", "Asset", "Asset criticality(A)", "CVE", "Title",
                "Status", "Assignee", "Due date", "First seen", "Resolved at", "Corrective action"])
    for r in rows:
        w.writerow([csv_safe(x) for x in (
            r["priority"], r["severity"], severity_label(r["severity"]), r["asset_name"], r["criticality"],
            r["cve_id"], r["title"], r["status"], r["assignee"], r["due_date"], r["first_seen"],
            r["resolved_at"], r["action"])])
    return out.getvalue()


def report_pdf(data):
    """Return PDF bytes, or None if reportlab is not installed."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        return None
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), title="Vulnerability Report")
    st = getSampleStyleSheet()
    s = data["summary"]
    el = [Paragraph("Enterprise Vulnerability Management - Report", st["Title"]),
          Paragraph(f"Date: {data['today']}", st["Normal"]), Spacer(1, 10),
          Paragraph(f"Open: {s['open']} | Critical open: {s['critical_open']} | Overdue: {s['overdue']} | "
                    f"Resolved: {s['resolved']} | Remediation rate: {s['remediation_rate']}% | "
                    f"Risk before/after: {s['risk_before']} / {s['risk_after']}", st["Normal"]),
          Spacer(1, 12), Paragraph("Open findings (by priority R = S x A)", st["Heading2"])]

    def table(rows, head):
        t = Table([head] + rows, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a44")),
                               ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("FONTSIZE", (0, 0), (-1, -1), 7),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]))
        return t

    def cut(x, n=42):
        return (str(x) if x is not None else "")[:n]

    head = ["R", "S", "Asset", "CVE", "Title", "Status", "Owner", "Due"]
    el.append(table([[r["priority"], r["severity"], cut(r["asset_name"], 24), r["cve_id"] or "-",
                      cut(r["title"]), r["status"], cut(r["assignee"], 18), r["due_date"]]
                     for r in data["open"][:300]], head))
    el += [Spacer(1, 14), Paragraph("Resolved findings", st["Heading2"])]
    el.append(table([[r["priority"], r["severity"], cut(r["asset_name"], 24), r["cve_id"] or "-",
                      cut(r["title"]), r["status"], cut(r["assignee"], 18), (r["resolved_at"] or "")[:10]]
                     for r in data["resolved"][:300]], head[:-1] + ["Resolved"]))
    doc.build(el)
    return buf.getvalue()
