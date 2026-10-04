from contextlib import closing
from pathlib import Path

from common.payloads import describe_payload
from common.database import connect_readonly

from . import queries

# Traffic between Docker Desktop's VM and Windows: not lab traffic, so hidden by default.
DOCKER_DESKTOP_PREFIXES = ("192.168.65.",)

PORT_LABELS = {80: "DVWA", 2222: "Honeypot", 3000: "Juice Shop", 8080: "DVWA (host port)"}


def port_label(port):
    name = PORT_LABELS.get(port)
    return f"{port} - {name}" if name else str(port)

PAYLOAD_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\ufffd": "\\ufffd"}


def display_payload(value, limit=None):
    # Honeypot payloads are raw network bytes. Show control characters as escapes (\x00, \r\n)
    # instead of blanks or "?", so binary protocols stay readable and nothing can move the
    # cursor or flip the text direction. "\ufffd" marks a byte that was not valid text.
    pieces = []

    for ch in "" if value is None else str(value):
        if ch in PAYLOAD_ESCAPES:
            pieces.append(PAYLOAD_ESCAPES[ch])
        elif ch.isprintable():
            pieces.append(ch)
        elif ord(ch) < 256:
            pieces.append(f"\\x{ord(ch):02x}")
        elif ord(ch) <= 0xFFFF:
            pieces.append(f"\\u{ord(ch):04x}")
        else:
            pieces.append(f"\\U{ord(ch):08x}")

    if limit and sum(len(piece) for piece in pieces) > limit:
        kept, used = [], 0

        for piece in pieces:
            if used + len(piece) > limit - 3:
                break

            kept.append(piece)
            used += len(piece)

        return "".join(kept) + "..."

    return "".join(pieces)

def enrich_payloads(rows):
    # Add a human description to every payload row (see common/payloads.py).
    enriched = []

    for row in rows:
        description = describe_payload(row["data"])
        enriched.append(
            {
                **row,
                "label": description.label,
                "detail": description.detail,
                "service_probe": description.service_probe,
                "known": description.known,
            }
        )

    return enriched


def summarise_payloads(rows):
    return {
        "total": len(rows),
        "probes": sum(1 for row in rows if row["service_probe"]),
        "unrecognised": sum(1 for row in rows if not row["known"]),
    }

def db_signature(db_path):
    # Changes whenever the database changes. SQLite in WAL mode writes to the "-wal" file first,
    # so the main file's timestamp alone would not notice new data.
    path = Path(db_path)
    parts = []

    for suffix in ("", "-wal"):
        try:
            parts.append(Path(str(path) + suffix).stat().st_mtime_ns)
        except OSError:
            parts.append(0)

    return tuple(parts)


def _empty():
    return {
        "empty": True,
        "since": None,
        "until": None,
        "bucket": 60,
        "hide_docker_desktop": True,
        "overview": {"flows": 0, "honeypot_events": 0, "alerts": 0, "high_alerts": 0},
        "alerts_over_time": [],
        "alerts": [],
        "sources": [],
        "ports": [],
        "attempts_over_time": [],
        "honeypot_over_time": [],
        "honeypot_sources": [],
        "payloads": [],
        "payload_summary": {"total": 0, "probes": 0, "unrecognised": 0},
    }


def load_dashboard_data(db_path, window_seconds=None, hide_docker_desktop=True, top=10):
    # One read-only pass that gathers everything every page (and the PDF report) needs.
    hide = DOCKER_DESKTOP_PREFIXES if hide_docker_desktop else ()

    with closing(connect_readonly(db_path)) as conn:
        bounds = queries.time_bounds(conn)

        if bounds is None:
            data = _empty()
            data["hide_docker_desktop"] = hide_docker_desktop
            return data

        low, high = bounds
        until = None
        since = max(low, high - window_seconds) if window_seconds else None
        start = since if since is not None else low
        bucket = queries.pick_bucket(high - start)
        payloads = enrich_payloads(queries.honeypot_payloads(conn, since, until, limit=500))

        return {
            "empty": False,
            "since": start,
            "until": high,
            "bucket": bucket,
            "hide_docker_desktop": hide_docker_desktop,
            "overview": queries.overview(conn, since, until, hide),
            "alerts_over_time": queries.alerts_over_time(conn, since, until, bucket),
            "alerts": queries.list_alerts(conn, since, until),
            "sources": queries.top_sources(conn, since, until, hide, top),
            "ports": queries.top_ports(conn, since, until, hide, top),
            "attempts_over_time": queries.attempts_over_time(conn, since, until, hide, bucket),
            "honeypot_over_time": queries.honeypot_over_time(conn, since, until, bucket),
            "honeypot_sources": queries.honeypot_sources(conn, since, until, top),
            "payloads": payloads[:50],
            "payload_summary": summarise_payloads(payloads),
        }