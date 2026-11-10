"""Minimal persistent state: fingerprints of items already seen (no content) + bot settings."""
import json
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen(uid TEXT PRIMARY KEY, title_key TEXT, at INTEGER);
CREATE INDEX IF NOT EXISTS idx_seen_title ON seen(title_key);
CREATE INDEX IF NOT EXISTS idx_seen_at ON seen(at);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""
RETENTION = 7 * 86400  # must stay well above max_age_hours


class State:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)

    def mark(self, uid: str, title_key: str) -> bool:
        """Record an item; True if neither its URL nor its title was seen before."""
        if self.conn.execute("SELECT 1 FROM seen WHERE uid = ? OR title_key = ?", (uid, title_key)).fetchone():
            return False
        self.conn.execute("INSERT INTO seen VALUES(?,?,?)", (uid, title_key, int(time.time())))
        return True

    def commit(self) -> None:
        self.conn.execute("DELETE FROM seen WHERE at < ?", (int(time.time()) - RETENTION,))
        self.conn.commit()

    # First successful fetch of a source only records fingerprints, so new sources don't flood the chat.
    def seeded(self, source: str) -> bool:
        return self.get(f"seeded:{source}", False)

    def set_seeded(self, source: str) -> None:
        self.set(f"seeded:{source}", True)

    def get(self, key: str, default):
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key: str, value) -> None:
        self.conn.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, json.dumps(value)))
        self.conn.commit()
