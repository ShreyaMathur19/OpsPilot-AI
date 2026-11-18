"""SQLite persistence and synthetic internal IT-operations dataset."""
from __future__ import annotations
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv('OPSPILOT_DB', str(ROOT / 'data' / 'opspilot.db')))

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def new_id(prefix):
    return f'{prefix}-{uuid.uuid4().hex[:10].upper()}'

@contextmanager
def connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def init_db():
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, owner_id TEXT,
            status TEXT NOT NULL, compliance TEXT NOT NULL, os TEXT NOT NULL,
            last_seen TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY, device_id TEXT NOT NULL, category TEXT NOT NULL,
            severity TEXT NOT NULL, description TEXT NOT NULL, observed_at TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES devices(device_id));
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, device_id TEXT NOT NULL, severity TEXT NOT NULL,
            title TEXT NOT NULL, details TEXT NOT NULL, state TEXT NOT NULL,
            created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY, device_id TEXT NOT NULL, recipient TEXT NOT NULL,
            message TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, objective TEXT NOT NULL, status TEXT NOT NULL,
            messages TEXT NOT NULL, result TEXT NOT NULL DEFAULT '',
            steps INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY, run_id TEXT NOT NULL, tool TEXT NOT NULL,
            arguments TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            reviewer_note TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, resolved_at TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(id));
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, tool TEXT NOT NULL,
            arguments TEXT NOT NULL, outcome TEXT NOT NULL, created_at TEXT NOT NULL);
        ''')
        if db.execute('SELECT COUNT(*) FROM devices').fetchone()[0] == 0:
            devices = [
                ('DEV-104','finance-laptop-04','EMP-004','active','noncompliant','Windows 11',now()),
                ('DEV-207','marketing-laptop-07','EMP-002','active','compliant','Ubuntu 24.04',now()),
                ('DEV-312','server-prod-02','EMP-003','active','noncompliant','Ubuntu 22.04',now()),
                ('DEV-401','hr-laptop-01','EMP-001','active','compliant','Windows 11',now()),
                ('DEV-512','engineering-ws-12','EMP-005','active','compliant','macOS 15',now()),
            ]
            db.executemany('INSERT INTO devices VALUES (?,?,?,?,?,?,?)', devices)
            alerts = [
                ('ALT-001','DEV-104','malware','critical','Unsigned executable detected by endpoint scanner; execution blocked',now()),
                ('ALT-002','DEV-104','authentication','high','19 failed login attempts in 10 minutes',now()),
                ('ALT-003','DEV-312','configuration','high','Remote management service exposed on an unauthorized port',now()),
                ('ALT-004','DEV-207','patching','low','Optional package update available',now()),
                ('ALT-005','DEV-312','authentication','medium','Unusual login time detected; no confirmed compromise',now()),
            ]
            db.executemany('INSERT INTO alerts VALUES (?,?,?,?,?,?)', alerts)

def query(sql, params=()):
    with connection() as db:
        return [dict(r) for r in db.execute(sql, params).fetchall()]

def execute(sql, params=()):
    with connection() as db:
        return db.execute(sql, params).rowcount

def audit(run_id, tool, args, outcome):
    with connection() as db:
        db.execute('INSERT INTO audit (run_id,tool,arguments,outcome,created_at) VALUES (?,?,?,?,?)',
                   (run_id, tool, json.dumps(args,ensure_ascii=False), json.dumps(outcome,ensure_ascii=False), now()))

def get_run(run_id):
    rows=query('SELECT * FROM runs WHERE id=?',(run_id,))
    return rows[0] if rows else None

def save_run(run_id, messages, status, result='', steps=None):
    with connection() as db:
        if steps is None:
            db.execute('UPDATE runs SET messages=?,status=?,result=?,updated_at=? WHERE id=?',
                       (json.dumps(messages),status,result,now(),run_id))
        else:
            db.execute('UPDATE runs SET messages=?,status=?,result=?,steps=?,updated_at=? WHERE id=?',
                       (json.dumps(messages),status,result,steps,now(),run_id))
