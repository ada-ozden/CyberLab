import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, CookedLinux, Ether
from scapy.utils import wrpcap

from analyzer.pcap_parser import parse_pcap

ATTACKER = "10.0.0.9"
TARGET = "10.0.0.5"


def make(packet, time):
    packet.time = time
    return packet


def tcp(src, dst, sport, dport, flags, time, payload=b""):
    packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload
    return make(packet, time)


@pytest.fixture
def pcap(tmp_path):
    # A tiny "port scan": SYNs to ports 22/80/443, answered by SYN-ACK and RST.
    packets = [
        tcp(ATTACKER, TARGET, 40000, 22, "S", 100.0),
        tcp(TARGET, ATTACKER, 22, 40000, "SA", 100.1),
        tcp(ATTACKER, TARGET, 40000, 80, "S", 100.2),
        tcp(TARGET, ATTACKER, 80, 40000, "RA", 100.3),
        tcp(ATTACKER, TARGET, 40000, 443, "S", 100.4),
        # same flow as the first SYN, seen again later
        tcp(ATTACKER, TARGET, 40000, 22, "S", 105.0, payload=b"x" * 10),
        make(Ether() / IP(src=ATTACKER, dst=TARGET) / UDP(sport=5000, dport=53), 106.0),
        make(Ether() / IP(src=ATTACKER, dst=TARGET) / ICMP(), 107.0),
        make(Ether() / ARP(), 108.0),
        make(Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=1, dport=2), 109.0),
    ]
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), packets)
    return path


def find(result, **wanted):
    matches = [
        flow for flow in result.flows
        if all(getattr(flow, name) == value for name, value in wanted.items())
    ]
    assert len(matches) == 1, f"expected one flow matching {wanted}, got {len(matches)}"
    return matches[0]


def test_packet_counts(pcap):
    result = parse_pcap(pcap)

    assert result.total_packets == 10
    assert result.skipped_packets == 1  # the ARP packet


def test_syn_scan_flows_have_syn_only_flags(pcap):
    result = parse_pcap(pcap)

    probe = find(result, src_ip=ATTACKER, dst_port=80)
    reply = find(result, src_ip=TARGET, src_port=80)

    assert probe.tcp_flags == "S"
    assert reply.tcp_flags == "AR"  # RST + ACK = "port closed"


def test_packets_of_one_flow_are_aggregated(pcap):
    result = parse_pcap(pcap)

    flow = find(result, src_ip=ATTACKER, dst_port=22)

    assert flow.packets == 2
    assert flow.first_seen == 100.0
    assert flow.last_seen == 105.0
    assert flow.byte_count > 2 * 54  # two frames, one carries 10 payload bytes


def test_other_protocols(pcap):
    result = parse_pcap(pcap)

    assert find(result, protocol="udp", dst_port=53).src_port == 5000
    assert find(result, protocol="icmp").dst_port == 0
    assert find(result, src_ip="fe80::1").protocol == "udp"  # IPv6 works too


def test_flows_are_sorted_by_first_seen(pcap):
    times = [flow.first_seen for flow in parse_pcap(pcap).flows]

    assert times == sorted(times)


def test_linux_cooked_capture_is_supported(tmp_path):
    # `tcpdump -i any` (used in Docker) produces this format instead of Ethernet.
    packet = CookedLinux() / IP(src=ATTACKER, dst=TARGET) / TCP(sport=1, dport=2, flags="S")
    packet.time = 1.0
    path = tmp_path / "any.pcap"
    wrpcap(str(path), [packet])

    result = parse_pcap(path)

    assert [flow.dst_port for flow in result.flows] == [2]


def test_empty_capture(tmp_path):
    path = tmp_path / "empty.pcap"
    wrpcap(str(path), [])

    result = parse_pcap(path)

    assert (result.total_packets, result.flows) == (0, [])

def test_syn_count_tells_client_from_server(pcap):
    result = parse_pcap(pcap)

    client = find(result, src_ip=ATTACKER, dst_port=22)
    server = find(result, src_ip=TARGET, src_port=22)

    assert client.syn_count == 2  # two connection attempts
    assert server.syn_count == 0  # SYN+ACK is a reply, not an attempt


def test_client_and_server_flags_look_the_same_but_syn_count_differs(tmp_path):
    # A full conversation: both directions end up with the same flag letters ("AFPS"),
    # so only syn_count can tell who started it.
    packets = [
        tcp("1.1.1.1", "2.2.2.2", 5000, 3000, "S", 1.0),
        tcp("2.2.2.2", "1.1.1.1", 3000, 5000, "SA", 2.0),
        tcp("1.1.1.1", "2.2.2.2", 5000, 3000, "PA", 3.0),
        tcp("2.2.2.2", "1.1.1.1", 3000, 5000, "PA", 4.0),
        tcp("1.1.1.1", "2.2.2.2", 5000, 3000, "FA", 5.0),
        tcp("2.2.2.2", "1.1.1.1", 3000, 5000, "FA", 6.0),
    ]
    path = tmp_path / "conversation.pcap"
    wrpcap(str(path), packets)

    result = parse_pcap(path)
    client = find(result, src_ip="1.1.1.1")
    server = find(result, src_ip="2.2.2.2")

    assert client.tcp_flags == server.tcp_flags == "AFPS"
    assert (client.syn_count, server.syn_count) == (1, 0)