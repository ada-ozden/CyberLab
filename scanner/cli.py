import argparse
import xml.etree.ElementTree as ET

from .nmap_scanner import NmapScanner, print_results
from .storage import save_scan_results


def main():
    parser = argparse.ArgumentParser(
        description="CyberLab Nmap scanner"
    )

    # Options shared by every subcommand, so they work AFTER the command:
    #   python -m scanner.cli scan 192.168.1.1 --timeout 60
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Maximum seconds to let Nmap run (default: 3600)",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for name in ("scan", "discover", "full"):
        sub = subparsers.add_parser(name, parents=[common])
        sub.add_argument("target")

    args = parser.parse_args()

    try:
        scanner = NmapScanner(timeout=args.timeout)

        if args.command == "scan":
            hosts = scanner.scan(args.target)

        elif args.command == "discover":
            hosts = scanner.discover(args.target)

        else:
            # Step 1: quickly find which hosts are alive.
            live_hosts = scanner.discover(args.target)
            ips = [host.ip for host in live_hosts]

            # Step 2: scan ALL of them in a single Nmap run.
            hosts = scanner.scan_many(ips)

    except (RuntimeError, ValueError) as error:
        print(f"Error: {error}")
        return 1

    except ET.ParseError as error:
        print(f"Error: could not read Nmap's output ({error})")
        return 1

    print_results(hosts)

    output_file = save_scan_results(hosts)

    print(f"\nResults saved to: {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())