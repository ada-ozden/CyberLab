import argparse
import sqlite3
from pathlib import Path

from common.database import DEFAULT_DB_PATH, connect, count_rows, insert_flows, save_alerts

from .detector import DEFAULT_IGNORED_NETWORKS, run_detectors
from .log_parser import DEFAULT_HONEYPOT_LOG, ingest_honeypot_log
from .pcap_parser import parse_pcap
from .pipeline import DEFAULT_PCAP_DIRECTORY, update_all


def print_summary(result, top=10):
    print(f"Packets read:    {result.total_packets}")
    print(f"Packets skipped: {result.skipped_packets} (no IP layer)")
    print(f"Flows found:     {len(result.flows)}")

    if not result.flows:
        return

    print(f"\nTop {top} flows by bytes:")

    biggest = sorted(result.flows, key=lambda flow: flow.byte_count, reverse=True)

    for flow in biggest[:top]:
        print(
            f"  {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
            f"{flow.protocol:<4} {flow.packets:>5} pkts {flow.byte_count:>8} bytes "
            f"flags={flow.tcp_flags or '-'}"
        )


def run_pcap(args):
    path = Path(args.file)

    if not path.is_file():
        print(f"Error: file not found: {path}")
        return 1

    try:
        result = parse_pcap(path)
    except Exception as error:  # scapy raises different errors for bad/corrupt files
        print(f"Error: could not read {path.name} as a capture file ({error})")
        return 1

    print_summary(result)

    with connect(args.db) as connection:
        stored = insert_flows(connection, result.flows, source=path.name)

    print(f"\nStored {stored} flows in {args.db}")
    return 0


def run_logs(args):
    with connect(args.db) as connection:
        stored, skipped = ingest_honeypot_log(connection, args.file)

    print(f"Honeypot log: {stored} new events stored, {skipped} lines skipped")
    return 0


def run_stats(args):
    with connect(args.db) as connection:
        for table, count in count_rows(connection).items():
            print(f"{table:<16} {count}")

    return 0


def detector_options(args):
    # The same detector settings are used by `detect` and `update`.
    return {
        "min_ports": args.min_ports,
        "min_connections": args.min_connections,
        "min_protocols": args.min_protocols,
        "window_seconds": args.window,
        "ignored_networks": args.ignore or DEFAULT_IGNORED_NETWORKS,
    }


def print_alerts(alerts):
    for alert in alerts:
        print(f"  [{alert.severity.upper():<6}] {alert.rule:<15} {alert.description}")


def run_detect(args):
    with connect(args.db) as connection:
        alerts = run_detectors(connection, **detector_options(args))
        new = save_alerts(connection, alerts)

    print(f"{len(alerts)} alerts found ({new} new)")
    print_alerts(alerts)

    return 0


def run_update(args):
    with connect(args.db) as connection:
        summary = update_all(connection, args.pcaps, args.logs, detector_options(args))

    failed = len(summary.captures_failed)

    print(
        f"Captures:  {summary.captures_new} new, {summary.captures_changed} grown, "
        f"{summary.captures_unchanged} unchanged, {failed} unreadable"
    )
    print(f"Flows:     {summary.flows_stored:,} stored")
    print(f"Honeypot:  {summary.honeypot_events:,} new events ({summary.honeypot_skipped} lines skipped)")
    print(f"Alerts:    {len(summary.alerts)} found, {summary.alerts_new} new")

    if summary.alerts_new:
        print("\nAll alerts (new ones were just added):")
        print_alerts(summary.alerts)

    for name, error in summary.captures_failed:
        print(f"\nCould not read {name}: {error}\n  (it will be tried again next time)")

    return 0


def run_sql(args):
    query = args.query.strip()

    # A convenience guard against typos, not a security feature.
    if not query.lower().startswith("select"):
        print("Only SELECT queries are allowed here.")
        return 1

    try:
        with connect(args.db) as connection:
            rows = connection.execute(query).fetchall()
    except sqlite3.Error as error:
        print(f"SQL error: {error}")
        return 1

    if not rows:
        print("(no rows)")
        return 0

    print(" | ".join(rows[0].keys()))

    for row in rows:
        print(" | ".join(str(value) for value in row))

    return 0


def main():
    # Options shared by every command, so they work AFTER the command name.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=DEFAULT_DB_PATH, help="database file")

    parser = argparse.ArgumentParser(description="CyberLab analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pcap = subparsers.add_parser("pcap", parents=[common], help="parse a .pcap into flows")
    pcap.add_argument("file")
    pcap.set_defaults(run=run_pcap)

    logs = subparsers.add_parser("logs", parents=[common], help="load new honeypot log lines")
    logs.add_argument("file", nargs="?", default=DEFAULT_HONEYPOT_LOG)
    logs.set_defaults(run=run_logs)

    stats = subparsers.add_parser("stats", parents=[common], help="show row counts")
    stats.set_defaults(run=run_stats)

    # Detector settings shared by `detect` and `update`.
    detector = argparse.ArgumentParser(add_help=False)
    detector.add_argument("--min-ports", type=int, default=10, help="ports probed to call it a scan")
    detector.add_argument("--min-connections", type=int, default=10, help="honeypot connections to call it a burst")
    detector.add_argument("--min-protocols", type=int, default=3, help="different protocols probed to call it service scanning")
    detector.add_argument("--window", type=int, default=60, help="window length in seconds")
    detector.add_argument(
        "--ignore", action="append", metavar="CIDR",
        help="network to ignore, e.g. 192.168.65.0/24 (repeatable; replaces the default)",
    )

    detect = subparsers.add_parser("detect", parents=[common, detector], help="run the threat detector")
    detect.set_defaults(run=run_detect)

    update = subparsers.add_parser(
        "update", parents=[common, detector], help="load new captures and logs, then run the detector"
    )
    update.add_argument("--pcaps", default=DEFAULT_PCAP_DIRECTORY, help="folder with .pcap files")
    update.add_argument("--logs", default=DEFAULT_HONEYPOT_LOG, help="honeypot log file")
    update.set_defaults(run=run_update)

    sql = subparsers.add_parser("sql", parents=[common], help="run a SELECT query")
    sql.add_argument("query")
    sql.set_defaults(run=run_sql)

    args = parser.parse_args()
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())