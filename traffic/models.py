from dataclasses import dataclass, field


@dataclass
class Flow:
    """All packets going one way between two endpoints, using one protocol."""

    src_ip: str
    dst_ip: str
    protocol: str                  # "TCP", "UDP", "ICMP" or "OTHER"
    src_port: int | None = None    # None for protocols without ports (ICMP)
    dst_port: int | None = None
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0        # Unix timestamp (seconds since 1970, UTC)
    last_seen: float = 0.0
    tcp_flags: str = ""            # every TCP flag seen, e.g. "AS" = ACK + SYN


@dataclass
class ParsedPcap:
    """The result of reading one PCAP file."""

    source_file: str
    total_packets: int = 0
    skipped_packets: int = 0       # packets with no IP layer, e.g. ARP
    flows: list[Flow] = field(default_factory=list)
