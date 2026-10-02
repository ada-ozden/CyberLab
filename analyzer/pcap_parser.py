from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from .models import Flow, ParseResult


def _extract(packet):
    # Returns (flow_key, size, timestamp, tcp_flags) or None if the packet has no IP layer.
    if packet.haslayer(IP):
        ip = packet[IP]
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
    else:
        return None  # ARP, STP, ... have no IP addresses to build a flow from

    src_port = 0
    dst_port = 0
    flags = ""

    if packet.haslayer(TCP):
        protocol = "tcp"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)  # e.g. "S", "SA", "RA"
    elif packet.haslayer(UDP):
        protocol = "udp"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "icmp"
    else:
        protocol = "other"

    key = (ip.src, ip.dst, src_port, dst_port, protocol)

    return key, len(packet), float(packet.time), flags


def parse_pcap(path) -> ParseResult:
    flows: dict[tuple, Flow] = {}
    flag_sets: dict[tuple, set] = {}
    total_packets = 0
    skipped_packets = 0

    # PcapReader yields ONE packet at a time, so memory use stays small even for
    # huge captures (rdpcap would load every packet into memory first).
    with PcapReader(str(path)) as reader:
        for packet in reader:
            total_packets += 1

            extracted = _extract(packet)

            if extracted is None:
                skipped_packets += 1
                continue

            key, size, timestamp, flags = extracted

            flow = flows.get(key)

            if flow is None:
                src_ip, dst_ip, src_port, dst_port, protocol = key
                flow = Flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                flows[key] = flow
                flag_sets[key] = set()

            flow.packets += 1
            flow.byte_count += size
            flow.first_seen = min(flow.first_seen, timestamp)
            flow.last_seen = max(flow.last_seen, timestamp)
            
            # A SYN without ACK is a connection ATTEMPT. Servers only ever send SYN+ACK,
            # so syn_count > 0 tells us this side started the connection.
            if "S" in flags and "A" not in flags:
                flow.syn_count += 1

            # str(flags) is like "SA": add each letter. A SYN-only flow stays "S".
            flag_sets[key].update(flags)

    for key, flow in flows.items():
        flow.tcp_flags = "".join(sorted(flag_sets[key]))

    ordered = sorted(flows.values(), key=lambda flow: flow.first_seen)

    return ParseResult(
        flows=ordered,
        total_packets=total_packets,
        skipped_packets=skipped_packets,
    )