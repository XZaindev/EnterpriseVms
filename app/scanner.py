"""Limited TCP-connect check for AUTHORISED LAB assets only.

Safety rules (enforced in code, not just documented):
  * the target must be a REGISTERED asset with an IP address;
  * the IP must be loopback or private (RFC 1918 / link-local) - public IPs are refused;
  * only a short fixed list of well-known ports is checked, with a short timeout;
  * no exploitation, no banner grabbing, no brute force: connect() only.
The project does NOT depend on this module; the importer is the main data source.
"""
import ipaddress
import socket

from .importer import ingest

# port -> (service, title, severity used as a *heuristic* exposure rating)
RISKY_SERVICES = {
    21: ("FTP", "Cleartext FTP service exposed", 5.5),
    23: ("Telnet", "Cleartext Telnet service exposed", 7.5),
    445: ("SMB", "SMB file-sharing service exposed", 6.5),
    3389: ("RDP", "Remote Desktop service exposed", 6.5),
    5900: ("VNC", "VNC remote-control service exposed", 6.5),
    3306: ("MySQL", "Database service reachable over the network", 5.0),
    6379: ("Redis", "Redis service reachable over the network", 7.0),
}
INFO_PORTS = {22: "SSH", 80: "HTTP", 443: "HTTPS"}


class ScanRefused(ValueError):
    pass


def check_target(ip):
    if not ip:
        raise ScanRefused("Asset has no IP address.")
    addr = ipaddress.ip_address(ip)
    if not (addr.is_loopback or addr.is_private or addr.is_link_local):
        raise ScanRefused("Refused: only loopback/private lab addresses may be scanned.")
    return str(addr)


def scan_asset(db, asset_id, user_id, today, services=None, timeout=0.4):
    asset = db.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
    if asset is None:
        raise ScanRefused("Asset is not registered.")
    ip = check_target(asset["ip"])
    services = services if services is not None else {**RISKY_SERVICES}
    open_ports, rows = [], []
    for port, (svc, title, sev) in services.items():
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
                rows.append((len(rows) + 1, {"asset": asset["name"], "title": f"{title} (port {port})",
                                             "severity": sev, "source": "LabScanner",
                                             "description": f"TCP port {port}/{svc} accepted a connection."}))
        except OSError:
            pass
    res = ingest(db, rows, filename=f"lab-scan:{asset['name']}", fmt="TCP", user_id=user_id,
                 today=today, source="LabScanner", kind="lab-scan") if rows else None
    if res is None:  # still record that the check happened
        from .db import now_iso
        db.execute("INSERT INTO scans(filename,kind,fmt,created_by,created_at) VALUES (?,?,?,?,?)",
                   (f"lab-scan:{asset['name']}", "lab-scan", "TCP", user_id, now_iso()))
        db.commit()
    return {"ip": ip, "open_ports": open_ports, "result": res}
