import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from traffic.pcap_parser import parse_pcap


def make_packet(layers, timestamp):
    packet = Ether() / layers
    packet.time = timestamp
    return packet


@pytest.fixture
def sample_pcap(tmp_path):
    attacker = "10.0.0.1"
    server = "10.0.0.2"

    packets = [
        # Two SYN packets from the same source port -> one flow
        make_packet(IP(src=attacker, dst=server) / TCP(sport=50000, dport=80, flags="S"), 100.0),
        make_packet(IP(src=attacker, dst=server) / TCP(sport=50000, dport=80, flags="A"), 101.0),
        # Reply from the server -> a separate flow (opposite direction)
        make_packet(IP(src=server, dst=attacker) / TCP(sport=80, dport=50000, flags="SA"), 100.5),
        # UDP and ICMP
        make_packet(IP(src=attacker, dst=server) / UDP(sport=5353, dport=53), 102.0),
        make_packet(IP(src=attacker, dst=server) / ICMP(), 103.0),
        # ARP has no IP layer, so it should be skipped
        Ether() / ARP(),
    ]

    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)
    return path


def test_counts_packets_and_skips_non_ip(sample_pcap):
    result = parse_pcap(sample_pcap)

    assert result.total_packets == 6
    assert result.skipped_packets == 1
    assert len(result.flows) == 4


def test_tcp_packets_are_grouped_into_one_flow(sample_pcap):
    result = parse_pcap(sample_pcap)

    flow = next(
        f for f in result.flows
        if f.protocol == "TCP" and f.src_ip == "10.0.0.1"
    )

    assert flow.dst_port == 80
    assert flow.packet_count == 2
    assert flow.first_seen == 100.0
    assert flow.last_seen == 101.0
    assert flow.tcp_flags == "AS"


def test_icmp_flow_has_no_ports(sample_pcap):
    result = parse_pcap(sample_pcap)

    flow = next(f for f in result.flows if f.protocol == "ICMP")

    assert flow.src_port is None
    assert flow.dst_port is None


def test_max_packets_limits_reading(sample_pcap):
    result = parse_pcap(sample_pcap, max_packets=2)

    assert result.total_packets == 2


def test_missing_file_raises_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_pcap(tmp_path / "does_not_exist.pcap")
