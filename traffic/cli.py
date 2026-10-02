import argparse

from .capture import TrafficCapture
from .pcap_parser import parse_pcap, print_flows
from .storage import save_parsed_pcap


def main():
    parser = argparse.ArgumentParser(
        description="CyberLab traffic capture and PCAP parser"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    capture_parser = subparsers.add_parser(
        "capture",
        help="Record traffic from a network interface into data/pcaps/",
    )
    capture_parser.add_argument("interface")
    capture_parser.add_argument("--duration", type=int, default=30)
    capture_parser.add_argument(
        "--filter",
        dest="bpf_filter",
        help='Optional tcpdump filter, e.g. "port 8080"',
    )

    parse_parser = subparsers.add_parser(
        "parse",
        help="Read a PCAP file and summarise its traffic",
    )
    parse_parser.add_argument("pcap_file")
    parse_parser.add_argument("--limit", type=int, default=20)
    parse_parser.add_argument("--max-packets", type=int, default=None)

    args = parser.parse_args()

    try:
        if args.command == "capture":
            capturer = TrafficCapture()
            pcap_file = capturer.capture(
                args.interface,
                duration=args.duration,
                bpf_filter=args.bpf_filter,
            )

            print(f"\nCapture saved to: {pcap_file}")
            print(f"Parse it with: python -m traffic.cli parse {pcap_file}")
            return 0

        result = parse_pcap(args.pcap_file, max_packets=args.max_packets)

    except (RuntimeError, ValueError, FileNotFoundError) as error:
        print(f"Error: {error}")
        return 1

    print_flows(result, limit=args.limit)

    output_file = save_parsed_pcap(result)

    print(f"\nResults saved to: {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
