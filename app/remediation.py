"""Remediation workflow: status, owner, due date, corrective action."""
from datetime import date

from .db import now_iso
from .models import STATUSES
from .risk_engine import recalc_finding


def update_finding(db, finding_id, *, status, assignee=None, due_date=None, action=None, user="system"):
    f = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if f is None:
        raise LookupError("Finding not found.")
    if status not in STATUSES:
        raise ValueError("Invalid status.")
    assignee = (assignee or "").strip()[:120] or None
    action = (action or "").strip()[:2000] or None
    due = (due_date or "").strip() or None
    if due:
        try:
            date.fromisoformat(due)
        except ValueError:
            raise ValueError("Due date must be YYYY-MM-DD.")
    if status == "Risk Accepted" and not action:
        raise ValueError("Accepting a risk requires a written justification in the action field.")
    if status == "Resolved" and not action and not f["resolved_at"]:
        action = "Marked resolved"
    resolved_at = now_iso() if status == "Resolved" and f["status"] != "Resolved" else (
        f["resolved_at"] if status == "Resolved" else None)
    db.execute("UPDATE findings SET status=?, resolved_at=?, due_date=COALESCE(?,due_date) WHERE id=?",
               (status, resolved_at, due, finding_id))
    db.execute("""UPDATE tasks_remediation SET status=?, assignee=?, due_date=COALESCE(?,due_date),
                  action=COALESCE(?,action), updated_at=?, updated_by=? WHERE finding_id=?""",
               (status, assignee, due, action, now_iso(), user, finding_id))
    if status != f["status"]:
        recalc_finding(db, finding_id, f"status {f['status']} -> {status} by {user}", force=True)
    db.commit()
