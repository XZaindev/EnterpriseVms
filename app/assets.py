"""Asset register: validation and CRUD."""
import ipaddress

from .db import now_iso
from .models import ASSET_TYPES
from .risk_engine import validate_criticality, recalc_asset


def validate_asset(data):
    errors, clean = [], {}
    name = (data.get("name") or "").strip()
    if not name or len(name) > 120:
        errors.append("Name is required (max 120 characters).")
    clean["name"] = name
    ip = (data.get("ip") or "").strip()
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            errors.append("IP address is not valid.")
    clean["ip"] = ip or None
    atype = (data.get("asset_type") or "Server").strip()
    if atype not in ASSET_TYPES:
        errors.append("Unknown asset type.")
    clean["asset_type"] = atype
    clean["os"] = (data.get("os") or "").strip()[:120] or None
    try:
        clean["criticality"] = validate_criticality(data.get("criticality"))
    except ValueError as e:
        errors.append(str(e))
    exposed = data.get("internet_exposed")
    clean["internet_exposed"] = 1 if str(exposed).lower() in ("1", "true", "on", "yes") else 0
    clean["owner"] = (data.get("owner") or "").strip()[:120] or None
    return clean, errors


def create_asset(db, clean):
    if db.execute("SELECT 1 FROM assets WHERE name=?", (clean["name"],)).fetchone():
        raise ValueError("An asset with this name already exists.")
    t = now_iso()
    cur = db.execute(
        """INSERT INTO assets(name,ip,asset_type,os,criticality,internet_exposed,owner,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (clean["name"], clean["ip"], clean["asset_type"], clean["os"], clean["criticality"],
         clean["internet_exposed"], clean["owner"], t, t))
    db.commit()
    return cur.lastrowid


def update_asset(db, asset_id, clean):
    old = db.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
    if old is None:
        raise LookupError("Asset not found.")
    dup = db.execute("SELECT id FROM assets WHERE name=? AND id<>?", (clean["name"], asset_id)).fetchone()
    if dup:
        raise ValueError("An asset with this name already exists.")
    db.execute(
        """UPDATE assets SET name=?,ip=?,asset_type=?,os=?,criticality=?,internet_exposed=?,owner=?,updated_at=?
           WHERE id=?""",
        (clean["name"], clean["ip"], clean["asset_type"], clean["os"], clean["criticality"],
         clean["internet_exposed"], clean["owner"], now_iso(), asset_id))
    if old["criticality"] != clean["criticality"] or old["internet_exposed"] != clean["internet_exposed"]:
        recalc_asset(db, asset_id, f"asset criticality/exposure changed (A={clean['criticality']})")
    db.commit()


def delete_asset(db, asset_id):
    db.execute("DELETE FROM history_risk WHERE asset_id=?", (asset_id,))
    db.execute("DELETE FROM findings WHERE asset_id=?", (asset_id,))
    db.execute("DELETE FROM assets WHERE id=?", (asset_id,))
    db.commit()


def list_assets(db, q=""):
    sql = """SELECT a.*,
        COALESCE(SUM(CASE WHEN f.status IN ('Open','In Progress') THEN f.priority END),0) AS risk,
        COUNT(CASE WHEN f.status IN ('Open','In Progress') THEN 1 END) AS open_count
        FROM assets a LEFT JOIN findings f ON f.asset_id=a.id """
    args = []
    if q:
        sql += "WHERE a.name LIKE ? OR a.ip LIKE ? OR a.owner LIKE ? "
        args = [f"%{q}%"] * 3
    sql += "GROUP BY a.id ORDER BY risk DESC, a.criticality DESC, a.name"
    return db.execute(sql, args).fetchall()
