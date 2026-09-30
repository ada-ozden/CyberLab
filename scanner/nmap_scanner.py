import shutil
import subprocess

from .models import Host
from .parser import parse_nmap_xml


class NmapScanner:

    def __init__(self, timeout=3600):
        # timeout is in seconds. If Nmap runs longer than this, we stop it.
        self.timeout = timeout
        self.nmap_path = shutil.which("nmap")

        if self.nmap_path is None:
            raise RuntimeError(
                "Nmap was not found. Make sure Nmap is installed and added to PATH."
            )

    def _validate_target(self, target):
        # A target starting with "-" would be treated by Nmap as an option
        # (for example "--script ..."), not as an address to scan.
        if not target or target.startswith("-"):
            raise ValueError(f"Invalid target: {target!r}")

    def _run_nmap(self, arguments):
        command = [
            self.nmap_path,
            *arguments,
            "-oX",
            "-",
        ]

        print(f"Running: {' '.join(command)}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Nmap did not finish within {self.timeout} seconds."
            )

        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        return result.stdout

    def discover(self, target):
        self._validate_target(target)

        xml_output = self._run_nmap([
            "-sn",
            target,
        ])

        return parse_nmap_xml(xml_output)

    def scan(self, target):
        # Scan a single target (an IP, hostname, or range like 192.168.1.0/24).
        return self.scan_many([target])

    def scan_many(self, targets):
        # Scan several targets in ONE Nmap run, so Nmap can scan them
        # in parallel instead of us launching one process per host.
        if not targets:
            return []

        for target in targets:
            self._validate_target(target)

        xml_output = self._run_nmap([
            "-sV",
            *targets,
        ])

        return parse_nmap_xml(xml_output)


def print_results(hosts: list[Host]):
    if not hosts:
        print("No hosts found.")
        return

    for host in hosts:
        print()
        print("=" * 50)
        print(f"Host: {host.ip}")

        if host.hostname:
            print(f"Hostname: {host.hostname}")

        print("=" * 50)

        if not host.ports:
            print("No ports detected.")
            continue

        for port in host.ports:
            service = port.service or "unknown"

            if port.product:
                service += f" ({port.product}"

                if port.version:
                    service += f" {port.version}"

                service += ")"

            print(
                f"{port.number}/{port.protocol} "
                f"{port.state:<10} "
                f"{service}"
            )