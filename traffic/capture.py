import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class TrafficCapture:

    def __init__(self):
        self.tcpdump_path = shutil.which("tcpdump")

        if self.tcpdump_path is None:
            raise RuntimeError(
                "tcpdump was not found. Install it (e.g. 'sudo apt install tcpdump'), "
                "or capture with Wireshark and save the file into data/pcaps/."
            )

    def capture(
        self,
        interface,
        duration=30,
        bpf_filter=None,
        output_directory="data/pcaps",
    ):
        # An interface starting with "-" would be read as a tcpdump option.
        if not interface or interface.startswith("-"):
            raise ValueError(f"Invalid interface: {interface!r}")

        if duration <= 0:
            raise ValueError("Duration must be greater than 0 seconds.")

        output_directory = Path(output_directory)
        output_directory.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc)
        filename = timestamp.strftime("capture_%Y%m%d_%H%M%S.pcap")
        file_path = output_directory / filename

        command = [
            self.tcpdump_path,
            "-i", interface,
            "-U",                  # write each packet to disk immediately
            "-w", str(file_path),
        ]

        if bpf_filter:
            command.extend(shlex.split(bpf_filter))

        print(f"Running: {' '.join(command)}")
        print(f"Capturing for {duration} seconds...")

        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # If tcpdump exits before the time is up, something went wrong
            # (wrong interface name, missing permissions, bad filter...).
            process.wait(timeout=duration)
            raise RuntimeError(process.stderr.read() or "tcpdump exited early.")

        except subprocess.TimeoutExpired:
            # Time is up: ask tcpdump to stop cleanly so the file is finished.
            process.terminate()

            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()

        return file_path
