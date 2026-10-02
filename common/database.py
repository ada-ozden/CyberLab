import json
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "cyberlab.db"

# "IF NOT EXISTS" means this is safe to run every time we connect.
SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY,
    source      TEXT    NOT NULL,   -- which .pcap file this row came from
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    src_port    INTEGER NOT NULL,
    dst_port    INTEGER NOT NULL,
    protocol    TEXT    NOT NULL,
    packets     INTEGER NOT NULL,
    byte_count  INTEGER NOT NULL,
    first_seen  REAL    NOT NULL,   -- Unix time (seconds since 1970)
    last_seen   REAL    NOT NULL,
    syn_count   INTEGER NOT NULL,
    tcp_flags   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip     ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_first_seen ON flows(first_seen);
CREATE INDEX IF NOT EXISTS idx_flows_source     ON flows(source);

CREATE TABLE IF NOT EXISTS honeypot_events (
    id        INTEGER PRIMARY KEY,
    ts        REAL    NOT NULL,
    event     TEXT    NOT NULL,     -- connection / data / timeout / error
    src_ip    TEXT    NOT NULL,
    src_port  INTEGER,
    data      TEXT
);
CREATE INDEX IF NOT EXISTS idx_honeypot_ts     ON honeypot_events(ts);
CREATE INDEX IF NOT EXISTS idx_honeypot_src_ip ON honeypot_events(src_ip);

-- Remembers how far into each log file we have already read.
CREATE TABLE IF NOT EXISTS ingest_state (
    path    TEXT PRIMARY KEY,
    "offset" INTEGER NOT NULL
);

-- Filled by the threat detector (next step).
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY,
    ts           REAL NOT NULL,
    rule         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    src_ip       TEXT,
    description  TEXT NOT NULL,
    evidence     TEXT NOT NULL DEFAULT '{}'   -- JSON text with the details
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
-- The same activity must never produce the same alert twice, however often we run the detector.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique ON alerts(rule, src_ip, ts, description);
"""


def connect(db_path=DEFAULT_DB_PATH):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row  # rows can be read by column name

    # WAL lets the dashboard READ while the analyzer WRITES, without "database is locked".
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(SCHEMA)

    return connection


def insert_flows(connection, flows, source):
    rows = [
        (
            source,
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
            flow.packets,
            flow.byte_count,
            flow.first_seen,
            flow.last_seen,
            flow.syn_count,
            flow.tcp_flags,
        )
        for flow in flows
    ]

    # "with connection" = ONE transaction: either everything is saved or nothing is.
    with connection:
        # Re-ingesting the same capture replaces it instead of duplicating it.
        connection.execute("DELETE FROM flows WHERE source = ?", (source,))
        connection.executemany(
            """
            INSERT INTO flows (source, src_ip, dst_ip, src_port, dst_port, protocol,
                               packets, byte_count, first_seen, last_seen,
                               syn_count, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    return len(rows)


def count_rows(connection):
    return {
        table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("flows", "honeypot_events", "alerts")
    }

def save_alerts(connection, alerts):
    rows = [
        (
            alert.ts,
            alert.rule,
            alert.severity,
            alert.src_ip,
            alert.description,
            json.dumps(alert.evidence, sort_keys=True),
        )
        for alert in alerts
    ]

    changes_before = connection.total_changes

    with connection:
        # OR IGNORE: an alert that already exists (same unique index) is skipped silently.
        connection.executemany(
            """
            INSERT OR IGNORE INTO alerts (ts, rule, severity, src_ip, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    return connection.total_changes - changes_before  # how many were actually new