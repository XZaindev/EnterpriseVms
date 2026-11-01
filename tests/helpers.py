import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.db import init_db
from app.assets import create_asset, validate_asset

TODAY = "2026-11-01"


def make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return init_db(path), path


def add_asset(db, name, crit=3, ip=None, exposed=0):
    clean, errs = validate_asset({"name": name, "criticality": crit, "ip": ip, "internet_exposed": exposed})
    assert not errs, errs
    return create_asset(db, clean)
