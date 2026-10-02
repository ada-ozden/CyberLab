import json
from datetime import datetime
from pathlib import Path

from common.database import PROJECT_ROOT

DEFAULT_HONEYPOT_LOG = PROJECT_ROOT / "data" / "logs" / "honeypot.log"


def parse_line(line):
    # Turns one JSON log line into a database row, or None if the line is not valid.
    try:
        record = json.loads(line)

        return (
            datetime.fromisoformat(record["ts"]).timestamp(),
            record["event"],
            record["src_ip"],
            record.get("src_port"),
            record.get("data"),
        )
    except (ValueError, KeyError, TypeError):
        return None  # not JSON, a missing field, or a bad timestamp


def ingest_honeypot_log(connection, path=DEFAULT_HONEYPOT_LOG):
    # Reads only the lines added since the last run. Returns (stored, skipped).
    path = Path(path)

    if not path.is_file():
        return 0, 0

    key = str(path.resolve())

    row = connection.execute(
        'SELECT "offset" FROM ingest_state WHERE path = ?', (key,)
    ).fetchone()

    offset = row["offset"] if row else 0

    if offset > path.stat().st_size:
        offset = 0  # the file was emptied or replaced: start over

    events = []
    skipped = 0

    with path.open("rb") as file:
        file.seek(offset)

        for raw_line in file:
            if not raw_line.endswith(b"\n"):
                break  # the honeypot is half-way through writing this line: next time

            offset += len(raw_line)

            event = parse_line(raw_line.decode("utf-8", errors="replace"))

            if event is None:
                skipped += 1
            else:
                events.append(event)

    with connection:
        connection.executemany(
            """
            INSERT INTO honeypot_events (ts, event, src_ip, src_port, data)
            VALUES (?, ?, ?, ?, ?)
            """,
            events,
        )
        connection.execute(
            """
            INSERT INTO ingest_state (path, "offset") VALUES (?, ?)
            ON CONFLICT(path) DO UPDATE SET "offset" = excluded."offset"
            """,
            (key, offset),
        )

    return len(events), skipped