"""Import vulnerability-scan results (CSV / JSON): validate, link to assets, de-duplicate."""
import csv
import io
import json
import re

from .db import now_iso
from .risk_engine import validate_severity, recalc_finding
from .vulnerability_manager import upsert_vuln, add_finding

MAX_ROWS = 20000
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
SEV_LABELS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "moderate": 5.5,
              "low": 2.5, "info": 1.0, "informational": 1.0}
ALIASES = {
    "asset": ("asset", "hostname", "host", "asset_name", "ip", "ip_address", "target"),
    "cve": ("cve", "cve_id", "cveid"),
    "title": ("title", "name", "vulnerability", "plugin_name", "summary"),
    "severity": ("severity", "cvss", "cvss_score", "score", "risk"),
    "description": ("description", "synopsis", "details"),
    "source": ("source", "scanner", "tool"),
    "epss": ("epss", "epss_score"),
}


class ImportFileError(ValueError):
    """The whole file is unusable (not just single rows)."""


def _decode(content):
    if isinstance(content, str):
        return content
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportFileError("File is not valid UTF-8 text.")


def parse_csv(content):
    text = _decode(content)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ImportFileError("File is empty or has no header row.")
    heads = {h.strip().lower() for h in reader.fieldnames if h}
    if not (heads & set(ALIASES["asset"])) or not (heads & set(ALIASES["severity"])):
        raise ImportFileError("Missing required columns: an asset column (asset/hostname/ip) "
                              "and a severity column (severity/cvss).")
    rows = []
    try:
        for i, r in enumerate(reader, start=2):
            if len(rows) >= MAX_ROWS:
                raise ImportFileError(f"Too many rows (max {MAX_ROWS}).")
            rows.append((i, {(k or "").strip().lower(): v for k, v in r.items()}))
    except csv.Error as e:
        raise ImportFileError(f"Malformed CSV: {e}")
    return rows


def parse_json(content):
    try:
        data = json.loads(_decode(content))
    except json.JSONDecodeError as e:
        raise ImportFileError(f"Malformed JSON: {e.msg} (line {e.lineno}).")
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list):
        raise ImportFileError("JSON must be a list of findings or an object with a 'findings' list.")
    if len(data) > MAX_ROWS:
        raise ImportFileError(f"Too many rows (max {MAX_ROWS}).")
    return [(i, {str(k).strip().lower(): v for k, v in item.items()} if isinstance(item, dict) else item)
            for i, item in enumerate(data, start=1)]


def _pick(row, field):
    for key in ALIASES[field]:
        v = row.get(key)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return None


def normalize(raw, default_source):
    """Return (clean_row, error). Never raises."""
    if not isinstance(raw, dict):
        return None, "Row is not an object."
    asset = _pick(raw, "asset")
    if not asset:
        return None, "Missing asset name/IP."
    sev_raw = _pick(raw, "severity")
    if sev_raw is None:
        return None, "Missing severity."
    try:
        severity = validate_severity(sev_raw)
    except ValueError:
        label = SEV_LABELS.get(sev_raw.lower())
        if label is None:
            return None, f"Invalid severity '{sev_raw[:30]}' (use 1-10 or Critical/High/Medium/Low)."
        severity = label
    cve = _pick(raw, "cve")
    if cve and not CVE_RE.match(cve):
        return None, f"Invalid CVE id '{cve[:30]}'."
    title = _pick(raw, "title") or cve
    if not title:
        return None, "Missing title or CVE id."
    epss = _pick(raw, "epss")
    if epss is not None:
        try:
            epss = float(epss)
            if not 0 <= epss <= 1:
                raise ValueError
        except ValueError:
            return None, "EPSS must be a number between 0 and 1."
    return {"asset": asset, "cve": cve, "title": title[:255],
            "description": (_pick(raw, "description") or "")[:2000] or None,
            "severity": severity, "epss": epss,
            "source": (_pick(raw, "source") or default_source)[:80]}, None


def find_asset(db, ref):
    return db.execute("SELECT id FROM assets WHERE name=? OR ip=? LIMIT 1", (ref, ref)).fetchone()


def ingest(db, rows, *, filename, fmt, user_id, today, source="import", kind="import", auto_verify=False):
    """rows: list of (line_no, raw_dict). Returns summary dict."""
    cur = db.execute("INSERT INTO scans(filename,kind,fmt,created_by,created_at) VALUES (?,?,?,?,?)",
                     (filename[:200], kind, fmt, user_id, now_iso()))
    scan_id = cur.lastrowid
    res = {"scan_id": scan_id, "total": len(rows), "imported": 0, "duplicates": 0,
           "reopened": 0, "verified": 0, "rejected": []}
    seen, touched_assets = set(), set()
    try:
        for line, raw in rows:
            row, err = normalize(raw, source)
            if err:
                res["rejected"].append((line, err))
                continue
            asset = find_asset(db, row["asset"])
            if asset is None:
                res["rejected"].append((line, f"Asset '{row['asset'][:60]}' is not registered."))
                continue
            vid = upsert_vuln(db, cve=row["cve"], title=row["title"], description=row["description"],
                              severity=row["severity"], source=row["source"], epss=row["epss"])
            touched_assets.add(asset["id"])
            key = (asset["id"], vid)
            if key in seen:
                res["duplicates"] += 1
                continue
            seen.add(key)
            f = db.execute("SELECT id,status FROM findings WHERE asset_id=? AND vuln_id=?", key).fetchone()
            if f is None:
                add_finding(db, asset["id"], vid, scan_id, today, row["severity"])
                res["imported"] += 1
                continue
            res["duplicates"] += 1
            db.execute("UPDATE findings SET last_seen=?, last_scan_id=? WHERE id=?", (today, scan_id, f["id"]))
            if f["status"] == "Resolved":
                db.execute("UPDATE findings SET status='Open', resolved_at=NULL WHERE id=?", (f["id"],))
                db.execute("UPDATE tasks_remediation SET status='Open', updated_at=? WHERE finding_id=?",
                           (now_iso(), f["id"]))
                recalc_finding(db, f["id"], "reappeared in a later scan (reopened)", force=True)
                res["reopened"] += 1
        if auto_verify and touched_assets:
            q = ",".join("?" * len(touched_assets))
            stale = db.execute(
                f"""SELECT id FROM findings WHERE asset_id IN ({q})
                    AND status IN ('Open','In Progress') AND COALESCE(last_scan_id,0)<>?""",
                (*touched_assets, scan_id)).fetchall()
            for s in stale:
                db.execute("UPDATE findings SET status='Resolved', resolved_at=? WHERE id=?", (now_iso(), s["id"]))
                db.execute("UPDATE tasks_remediation SET status='Resolved', updated_at=?, updated_by=? "
                           "WHERE finding_id=?", (now_iso(), "rescan-verification", s["id"]))
                recalc_finding(db, s["id"], "not present in rescan: verified resolved", force=True)
            res["verified"] = len(stale)
        db.execute("""UPDATE scans SET total_rows=?, imported=?, duplicates=?, rejected=?, verified_resolved=?
                      WHERE id=?""", (res["total"], res["imported"], res["duplicates"],
                                      len(res["rejected"]), res["verified"], scan_id))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return res


def import_file(db, content, filename, user_id, today, auto_verify=False):
    name = (filename or "upload").lower()
    if name.endswith(".csv"):
        fmt, rows = "CSV", parse_csv(content)
    elif name.endswith(".json"):
        fmt, rows = "JSON", parse_json(content)
    else:
        raise ImportFileError("Only .csv and .json files are supported.")
    if not rows:
        raise ImportFileError("File contains no data rows.")
    return ingest(db, rows, filename=filename, fmt=fmt, user_id=user_id, today=today,
                  source="import", auto_verify=auto_verify)
