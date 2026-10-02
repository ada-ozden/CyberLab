import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import ParsedPcap


def save_parsed_pcap(result: ParsedPcap, output_directory="data/flows"):
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    filename = timestamp.strftime("flows_%Y%m%d_%H%M%S.json")

    file_path = output_directory / filename

    data = {
        "timestamp": timestamp.isoformat(),
        **asdict(result),
    }

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return file_path
