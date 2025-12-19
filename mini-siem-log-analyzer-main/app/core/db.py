import os
import sqlite3
from typing import List, Dict, Any

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    channel TEXT,
    event_id INTEGER,
    user TEXT,
    ip TEXT,
    command TEXT,
    message TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT,
    severity TEXT,
    title TEXT,
    description TEXT
);
"""


class Database:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self._init()

    def _init(self):
        conn = sqlite3.connect(self.path)
        try:
            conn.executescript(SCHEMA_SQL)
        finally:
            conn.close()

    def insert_events(self, events: List[Dict[str, Any]]):
        if not events:
            return
        conn = sqlite3.connect(self.path)
        try:
            cur = conn.cursor()
            cur.executemany(
                "INSERT INTO events(timestamp, channel, event_id, user, ip, command, message) VALUES(?,?,?,?,?,?,?)",
                [(
                    e.get('timestamp'), e.get('channel'), e.get('event_id'),
                    e.get('user'), e.get('ip'), e.get('command'), e.get('message')
                ) for e in events]
            )
            conn.commit()
        finally:
            conn.close()

    def insert_alert(self, severity: str, title: str, description: str, created_at: str):
        conn = sqlite3.connect(self.path)
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO alerts(created_at, severity, title, description) VALUES(?,?,?,?)",
                (created_at, severity, title, description)
            )
            conn.commit()
        finally:
            conn.close()
