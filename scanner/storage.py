import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import Host, Port

# Always resolve relative to the project, not to the folder you ran the command from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCAN_DIRECTORY = PROJECT_ROOT / "data" / "scans"


def save_scan_results(hosts: list[Host], output_directory=DEFAULT_SCAN_DIRECTORY):
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)

    # %f = microseconds, so two scans in the same second don't overwrite each other.
    filename = timestamp.strftime("scan_%Y%m%d_%H%M%S_%f.json")

    file_path = output_directory / filename

    data = {
        "timestamp": timestamp.isoformat(),
        "hosts": [asdict(host) for host in hosts],
    }

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return file_path


def load_scan_results(file_path) -> tuple[str, list[Host]]:
    # Reverse of save_scan_results: returns (timestamp, hosts).
    with Path(file_path).open("r", encoding="utf-8") as file:
        data = json.load(file)

    hosts = [
        Host(
            ip=host["ip"],
            hostname=host.get("hostname"),
            ports=[Port(**port) for port in host.get("ports", [])],
        )
        for host in data["hosts"]
    ]

    return data["timestamp"], hosts