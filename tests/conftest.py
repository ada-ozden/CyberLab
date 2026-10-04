import pytest

from analyzer.detector import run_detectors
from analyzer.models import Flow
from common.database import connect, insert_flows, save_alerts

T0 = 1_790_000_000.0  # an arbitrary "now" for the seeded data


def _flow(src, dst, dst_port, first_seen, syn_count=1, src_port=40000, packets=1, tcp_flags="S"):
    return Flow(
        src_ip=src, dst_ip=dst, src_port=src_port, dst_port=dst_port, protocol="tcp",
        packets=packets, byte_count=54 * packets, first_seen=first_seen,
        last_seen=first_seen, syn_count=syn_count, tcp_flags=tcp_flags,
    )


@pytest.fixture
def seeded_db(tmp_path):
    # A small, realistic lab: one scanner, one browsing user, Docker Desktop noise,
    # honeypot visitors (one sends a payload), and the alerts the detector derives from it.
    path = tmp_path / "lab.db"
    connection = connect(path)

    flows = [_flow("172.18.0.5", "172.18.0.2", port, T0 + port * 0.01) for port in range(1, 201)]
    flows += [_flow("172.18.0.1", "172.18.0.2", 3000, T0 + 30 + i, src_port=50000 + i, tcp_flags="AS") for i in range(40)]
    flows += [_flow("192.168.65.1", "192.168.65.7", 2376, T0 + i, src_port=20000 + i) for i in range(300)]
    flows += [_flow("172.18.0.2", "172.18.0.5", 40000, T0, syn_count=0, src_port=22)]  # a server reply
    insert_flows(connection, flows, "lab.pcap")

    with connection:
        connection.executemany(
            "INSERT INTO honeypot_events (ts, event, src_ip, src_port, data) VALUES (?, ?, ?, ?, ?)",
            [(T0 + 100 + i, "connection", "172.18.0.1", 40000 + i, None) for i in range(15)]
            + [(T0 + 200, "data", "172.18.0.1", 40000, "SSH-2.0-OpenSSH_9.6\r\n")]
            + [(T0 + 300, "data", "10.9.9.9", 1234, "GET /é中文 \U0001F600 HTTP/1.1")],
        )

    save_alerts(connection, run_detectors(connection))
    connection.close()

    return path