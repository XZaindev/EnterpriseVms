# EnterpriseVMS — Enterprise Vulnerability Management & Security Assessment System

Python 3.10+ · Flask · SQLite · works on Windows and Linux · no internet needed at runtime (no CDN).

## Run
```
pip install -r requirements.txt
python app.py --demo          # --demo loads sample assets + scan results
```
Open http://127.0.0.1:5000 — user `admin`. The password is printed once on first run
(or set `ADMIN_PASSWORD` in `.env`, copy from `.env.example`).
Create more users: Users page (admin) or `python app.py create-user NAME analyst`.

## Tests
```
python -m unittest discover -s tests -v
```

## Risk engine (documented, educational)
`R = S × A`  (S = severity 1–10, A = asset criticality 1–5). Example: V-001 (9,5)=45 > V-003 (5,4)=20 > V-002 (8,2)=16.
Optional tie-breaker `R_adj = R × 1.25 (Internet-exposed) × (1+EPSS)`. SLA by band: Critical 7d, High 30d, Medium 60d, Low 90d.
It is a triage aid, **not** a replacement for CVSS and does not measure complete real-world risk.

## Modules (spec structure)
`assets.py` register · `importer.py` CSV/JSON import + validation + de-duplication + rescan verification ·
`scanner.py` limited lab TCP check (registered asset + private/loopback IP only) · `vulnerability_manager.py` catalogue/findings/dashboard ·
`risk_engine.py` · `remediation.py` · `reports.py` (HTML/CSV/PDF) · `auth.py` · `models.py` (7 tables: assets, scans, vulnerabilities, findings, tasks_remediation, history_risk, users).

## Security built in
Password hashing (scrypt), CSRF tokens on all POSTs, role-based access (viewer/analyst/admin), login throttling, parameterised SQL only,
Jinja auto-escaping (XSS), CSP + security headers, upload limit 2 MB and row limit, CSV formula-injection protection, open-redirect protection,
HttpOnly/SameSite cookies, scanner restricted to private addresses.

## Import format
CSV or JSON. Columns: `asset` (name or IP, must be registered), `severity` (1–10 or Critical/High/Medium/Low), `title`, `cve`, `description`, `source`, `epss`.
See `sample_data/`. Rejected rows are listed with the reason; importing the same file twice creates no duplicates.

## Known limits
SQLite (single server; the SQL is portable if you later move to MySQL). Dev server by default — use waitress/gunicorn behind HTTPS for real deployment.
Rescan verification only sees assets that appear in the uploaded file.
