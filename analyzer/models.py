from dataclasses import dataclass
@dataclass
class Flow:
    # One direction of a conversation: everything sent from
    # src_ip:src_port to dst_ip:dst_port with the same protocol.
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str            # "tcp", "udp", "icmp" or "other"
    packets: int = 0
    byte_count: int = 0
    first_seen: float = 0.0  # seconds since 1970 (Unix time)
    last_seen: float = 0.0
    syn_count: int = 0       # packets that are a pure SYN (SYN without ACK) = "I want to connect"
    tcp_flags: str = ""      # every TCP flag seen in this flow, e.g. "S" or "ACKP"


@dataclass
class ParseResult:
    flows: list[Flow]
    total_packets: int
    skipped_packets: int     # packets without an IP layer (e.g. ARP)


@dataclass
class Alert:
    ts: float                # when the suspicious activity started (Unix time)
    rule: str                # which detector rule fired, e.g. "port_scan"
    severity: str            # "medium" or "high"
    src_ip: str
    description: str
    evidence: dict = field(default_factory=dict)