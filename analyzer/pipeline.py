from dataclasses import dataclass, field
from pathlib import Path

from common.database import PROJECT_ROOT, insert_flows, save_alerts

from .detector import run_detectors
from .log_parser import DEFAULT_HONEYPOT_LOG, ingest_honeypot_log
from .models import Alert
from .pcap_parser import parse_pcap

DEFAULT_PCAP_DIRECTORY = PROJECT_ROOT / "data" / "pcaps"
CAPTURE_PATTERNS = ("*.pcap", "*.pcapng")


@dataclass
class UpdateSummary:
    captures_new: int = 0          # never read before
    captures_changed: int = 0      # read before, but the file has grown since
    captures_unchanged: int = 0    # skipped: nothing new in them
    captures_failed: list = field(default_factory=list)   # [(file name, error text)]
    flows_stored: int = 0
    honeypot_events: int = 0
    honeypot_skipped: int = 0
    alerts: list[Alert] = field(default_factory=list)
    alerts_new: int = 0


def _remembered_size(connection, key):
    row = connection.execute('SELECT "offset" FROM ingest_state WHERE path = ?', (key,)).fetchone()
    return None if row is None else row["offset"]


def _remember_size(connection, key, size):
    with connection:
        connection.execute(
            """
            INSERT INTO ingest_state (path, "offset") VALUES (?, ?)
            ON CONFLICT(path) DO UPDATE SET "offset" = excluded."offset"
            """,
            (key, size),
        )


def ingest_captures(connection, pcap_directory, summary):
    directory = Path(pcap_directory)

    if not directory.is_dir():
        return

    paths = sorted({path for pattern in CAPTURE_PATTERNS for path in directory.glob(pattern)})

    for path in paths:
        key = f"pcap:{path.resolve()}"

        # Read the size BEFORE parsing. If tcpdump adds more while we read, the stored size is
        # smaller than the file, so the next run notices the difference and reads it again.
        size = path.stat().st_size
        remembered = _remembered_size(connection, key)

        if remembered == size:
            summary.captures_unchanged += 1
            continue

        try:
            result = parse_pcap(path)
        except Exception as error:  # empty, garbage, or cut inside the file header
            # Not remembered, so the next run tries again (the file may just be brand new).
            summary.captures_failed.append((path.name, str(error)))
            continue

        summary.flows_stored += insert_flows(connection, result.flows, source=path.name)
        _remember_size(connection, key, size)

        if remembered is None:
            summary.captures_new += 1
        else:
            summary.captures_changed += 1


def update_all(connection, pcap_directory=DEFAULT_PCAP_DIRECTORY, log_path=DEFAULT_HONEYPOT_LOG, detector_options=None):
    # The whole routine in one call: read new captures, read new honeypot log lines, run the detector.
    summary = UpdateSummary()

    ingest_captures(connection, pcap_directory, summary)

    summary.honeypot_events, summary.honeypot_skipped = ingest_honeypot_log(connection, log_path)

    summary.alerts = run_detectors(connection, **(detector_options or {}))
    summary.alerts_new = save_alerts(connection, summary.alerts)

    return summary