"""Risk assessment and prioritisation engine.

Educational, publicly documented formula (NOT a replacement for CVSS):

    R = S * A
      S = vulnerability severity, 0 < S <= 10  (CVSS base score or mapped label)
      A = asset criticality, integer 1..5

Example: V-001 (9,5)=45  >  V-003 (5,4)=20  >  V-002 (8,2)=16

Optional "adjusted" priority (professional tier) used only as a tie-breaker:

    R_adj = R * 1.25 (if asset is internet-exposed) * (1 + EPSS)   (EPSS in 0..1)

Limits: the score ignores exploit availability, compensating controls and
business context beyond A. It supports triage; it does not measure real risk.
"""
from .db import now_iso
from .models import ACTIVE

EXPOSURE_FACTOR = 1.25
SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 60, "Low": 90}


def severity_label(s):
    s = float(s)
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"


def sla_days(severity):
    return SLA_DAYS[severity_label(severity)]


def validate_severity(s):
    try:
        s = float(s)
    except (TypeError, ValueError):
        raise ValueError("severity must be a number between 1 and 10")
    if not (0 < s <= 10):
        raise ValueError("severity must be between 1 and 10")
    return s


def validate_criticality(a):
    try:
        if isinstance(a, float) and not a.is_integer():
            raise ValueError
        a = int(a)
    except (TypeError, ValueError):
        raise ValueError("criticality must be an integer between 1 and 5")
    if not (1 <= a <= 5):
        raise ValueError("criticality must be between 1 and 5")
    return a


def priority(s, a):
    return round(validate_severity(s) * validate_criticality(a), 2)


def adjusted_priority(s, a, exposed=False, epss=None):
    p = priority(s, a)
    if exposed:
        p *= EXPOSURE_FACTOR
    if epss is not None:
        p *= 1 + max(0.0, min(1.0, float(epss)))
    return round(p, 2)


def recalc_finding(db, finding_id, reason, force=False):
    r = db.execute(
        """SELECT f.id, f.asset_id, f.priority, f.priority_adj,
                  v.severity, v.epss, a.criticality, a.internet_exposed
           FROM findings f JOIN vulnerabilities v ON v.id=f.vuln_id
           JOIN assets a ON a.id=f.asset_id WHERE f.id=?""", (finding_id,)).fetchone()
    if r is None:
        return None
    p = priority(r["severity"], r["criticality"])
    adj = adjusted_priority(r["severity"], r["criticality"],
                            bool(r["internet_exposed"]), r["epss"])
    if force or p != r["priority"] or adj != r["priority_adj"]:
        db.execute("UPDATE findings SET priority=?, priority_adj=? WHERE id=?",
                   (p, adj, finding_id))
        db.execute(
            """INSERT INTO history_risk(finding_id,asset_id,severity,criticality,score,reason,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (finding_id, r["asset_id"], r["severity"], r["criticality"], p, reason, now_iso()))
    return p


def recalc_asset(db, asset_id, reason="asset changed"):
    ids = [r["id"] for r in db.execute("SELECT id FROM findings WHERE asset_id=?", (asset_id,))]
    for fid in ids:
        recalc_finding(db, fid, reason)
    return len(ids)


def recalc_vuln(db, vuln_id, reason="severity changed"):
    ids = [r["id"] for r in db.execute("SELECT id FROM findings WHERE vuln_id=?", (vuln_id,))]
    for fid in ids:
        recalc_finding(db, fid, reason)
    return len(ids)


def asset_risk(db, asset_id):
    q = ",".join("?" * len(ACTIVE))
    row = db.execute(
        f"SELECT COALESCE(SUM(priority),0) s FROM findings WHERE asset_id=? AND status IN ({q})",
        (asset_id, *ACTIVE)).fetchone()
    return round(row["s"], 2)
