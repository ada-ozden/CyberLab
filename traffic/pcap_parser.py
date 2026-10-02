from datetime import datetime, timezone
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from .models import Flow, ParsedPcap


def _describe_packet(packet):
    """
    Pull out the fields we care about from one packet.

    Returns (src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags),
    or None if the packet has no IP layer (for example ARP).
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
    else:
        return None

    # Look only at what sits directly inside the IP layer. Checking the whole
    # packet would be fooled by ICMP errors, which carry a copy of the
    # original TCP/UDP header inside them.
    inner = ip_layer.payload

    protocol = "OTHER"
    src_port = None
    dst_port = None
    flags = ""

    if isinstance(inner, TCP):
        protocol = "TCP"
        src_port = int(inner.sport)
        dst_port = int(inner.dport)
        flags = str(inner.flags)
    elif isinstance(inner, UDP):
        protocol = "UDP"
        src_port = int(inner.sport)
        dst_port = int(inner.dport)
    elif isinstance(inner, ICMP):
        protocol = "ICMP"

    return ip_layer.src, ip_layer.dst, protocol, src_port, dst_port, flags


def _merge_flags(existing: str, new: str) -> str:
    if not new:
        return existing

    return "".join(sorted(set(existing) | set(new)))


def parse_pcap(pcap_path, max_packets=None) -> ParsedPcap:
    path = Path(pcap_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    result = ParsedPcap(source_file=str(path))
    flows = {}

    try:
        # PcapReader reads one packet at a time instead of loading the whole
        # file into memory, so large captures are fine.
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if max_packets is not None and result.total_packets >= max_packets:
                    break

                result.total_packets += 1

                details = _describe_packet(packet)

                if details is None:
                    result.skipped_packets += 1
                    continue

                src_ip, dst_ip, protocol, src_port, dst_port, flags = details
                timestamp = float(packet.time)

                key = (src_ip, dst_ip, src_port, dst_port, protocol)
                flow = flows.get(key)

                if flow is None:
                    flow = Flow(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                        src_port=src_port,
                        dst_port=dst_port,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                    flows[key] = flow

                flow.packet_count += 1
                flow.byte_count += len(packet)
                flow.first_seen = min(flow.first_seen, timestamp)
                flow.last_seen = max(flow.last_seen, timestamp)
                flow.tcp_flags = _merge_flags(flow.tcp_flags, flags)

    except Scapy_Exception as error:
        raise ValueError(f"Could not read {path} as a PCAP file: {error}")

    result.flows = list(flows.values())

    return result


def _endpoint(ip, port):
    if port is None:
        return ip

    if ":" in ip:  # IPv6 addresses contain colons, so wrap them in brackets
        return f"[{ip}]:{port}"

    return f"{ip}:{port}"


def print_flows(result: ParsedPcap, limit=20):
    print()
    print("=" * 70)
    print(f"File:    {result.source_file}")
    print(f"Packets: {result.total_packets} "
          f"({result.skipped_packets} without IP skipped)")
    print(f"Flows:   {len(result.flows)}")

    if result.flows:
        start = min(flow.first_seen for flow in result.flows)
        end = max(flow.last_seen for flow in result.flows)
        fmt = "%Y-%m-%d %H:%M:%S"
        print(f"Time:    {datetime.fromtimestamp(start, timezone.utc):{fmt}} "
              f"-> {datetime.fromtimestamp(end, timezone.utc):{fmt}} UTC")

    print("=" * 70)

    if not result.flows:
        print("No IP traffic found.")
        return

    top = sorted(result.flows, key=lambda f: f.byte_count, reverse=True)[:limit]

    print(f"Top {len(top)} flows by bytes:")
    print()

    for flow in top:
        source = _endpoint(flow.src_ip, flow.src_port)
        destination = _endpoint(flow.dst_ip, flow.dst_port)

        print(
            f"{flow.protocol:<5} "
            f"{source:<22} -> {destination:<22} "
            f"{flow.packet_count:>6} pkts "
            f"{flow.byte_count:>9} B "
            f"{flow.tcp_flags}"
        )
