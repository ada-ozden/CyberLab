import pytest

from analyzer.detector import (
    DEFAULT_IGNORED_NETWORKS,
    detect_honeypot_bursts,
    detect_port_scans,
    detect_service_probing,
    is_ignored,
    parse_networks,
    run_detectors,
    strongest_window,
)
from analyzer.models import Alert, Flow
from common.database import connect, count_rows, insert_flows, save_alerts
from .test_payloads import NMAP_SCAN_PAYLOADS, UNKNOWN_PROBES

SCANNER = "172.18.0.9"
TARGET = "172.18.0.2"


@pytest.fixture
def db(tmp_path):
    connection = connect(tmp_path / "test.db")
    yield connection
    connection.close()


def flow(src_ip, dst_ip, dst_port, first_seen, syn_count=1, src_port=40000):
    return Flow(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        protocol="tcp", packets=1, byte_count=54, first_seen=first_seen,
        last_seen=first_seen, syn_count=syn_count, tcp_flags="S",
    )


def add_honeypot_events(db, src_ip, times):
    with db:
        db.executemany(
            "INSERT INTO honeypot_events (ts, event, src_ip, src_port, data) "
            "VALUES (?, 'connection', ?, 1, NULL)",
            [(time, src_ip) for time in times],
        )


# ---------- strongest_window ----------

def test_strongest_window_counts_distinct_keys():
    points = [(0, "a"), (1, "b"), (2, "a"), (3, "c")]

    assert strongest_window(points, 10) == (3, 0, 3)


def test_strongest_window_ignores_points_outside_the_window():
    # Ten different keys, but spread 100 seconds apart: never more than 1 per 60s window.
    points = [(i * 100.0, i) for i in range(10)]

    count, start, end = strongest_window(points, 60)

    assert count == 1


def test_strongest_window_finds_the_dense_part():
    sparse = [(i * 100.0, i) for i in range(5)]
    dense = [(1000.0 + i * 0.1, 100 + i) for i in range(20)]

    count, start, end = strongest_window(sparse + dense, 60)

    assert (count, start) == (20, 1000.0)


def test_strongest_window_of_nothing():
    assert strongest_window([], 60) == (0, 0.0, 0.0)


# ---------- ignored networks ----------

def test_is_ignored():
    networks = parse_networks(DEFAULT_IGNORED_NETWORKS)

    assert is_ignored("192.168.65.1", networks)
    assert not is_ignored("172.18.0.1", networks)
    assert not is_ignored("not-an-ip", networks)


# ---------- port scans ----------

def test_fast_scan_of_many_ports_is_detected(db):
    insert_flows(db, [flow(SCANNER, TARGET, port, 100.0 + port * 0.01) for port in range(1, 51)], "x")

    [alert] = detect_port_scans(db, min_ports=10, window_seconds=60)

    assert alert.rule == "port_scan"
    assert alert.src_ip == SCANNER
    assert alert.evidence["distinct_ports"] == 50
    assert alert.evidence["dst_ip"] == TARGET
    assert alert.evidence["sample_ports"][:3] == [1, 2, 3]


def test_normal_client_is_not_flagged(db):
    # Many connections, but all to the same web port.
    insert_flows(db, [flow("172.18.0.1", TARGET, 3000, 100.0 + i, src_port=50000 + i) for i in range(200)], "x")

    assert detect_port_scans(db, min_ports=10, window_seconds=60) == []


def test_server_replies_are_not_counted(db):
    # A busy server answering many client ports: syn_count is 0 on every reply flow.
    insert_flows(db, [flow(TARGET, "172.18.0.1", 50000 + i, 100.0 + i, syn_count=0, src_port=3000) for i in range(200)], "x")

    assert detect_port_scans(db, min_ports=10, window_seconds=60) == []


def test_slow_scan_outside_the_window_is_not_flagged(db):
    insert_flows(db, [flow(SCANNER, TARGET, port, port * 100.0) for port in range(1, 30)], "x")

    assert detect_port_scans(db, min_ports=10, window_seconds=60) == []


def test_ignored_network_is_skipped(db):
    insert_flows(db, [flow("192.168.65.1", "192.168.65.7", port, 100.0 + port * 0.01) for port in range(1, 51)], "x")
    networks = parse_networks(DEFAULT_IGNORED_NETWORKS)

    assert detect_port_scans(db, min_ports=10, window_seconds=60, ignored=networks) == []
    assert len(detect_port_scans(db, min_ports=10, window_seconds=60)) == 1  # not ignored by default arg


def test_huge_scan_is_high_severity(db):
    insert_flows(db, [flow(SCANNER, TARGET, port, 100.0 + port * 0.001) for port in range(1, 201)], "x")

    [alert] = detect_port_scans(db, min_ports=10, window_seconds=60)

    assert alert.severity == "high"  # 200 >= 10 * 10


def test_each_target_gets_its_own_alert(db):
    flows = [flow(SCANNER, target, port, 100.0 + port * 0.01) for target in ("172.18.0.2", "172.18.0.3") for port in range(1, 21)]
    insert_flows(db, flows, "x")

    assert len(detect_port_scans(db, min_ports=10, window_seconds=60)) == 2


# ---------- honeypot bursts ----------

def test_honeypot_burst_is_detected(db):
    add_honeypot_events(db, "172.18.0.9", [100.0 + i for i in range(15)])
    add_honeypot_events(db, "172.18.0.5", [100.0, 500.0])  # a quiet visitor

    [alert] = detect_honeypot_bursts(db, min_connections=10, window_seconds=60)

    assert alert.src_ip == "172.18.0.9"
    assert alert.evidence["connections"] == 15


def test_spread_out_connections_are_not_a_burst(db):
    add_honeypot_events(db, "172.18.0.9", [i * 100.0 for i in range(20)])

    assert detect_honeypot_bursts(db, min_connections=10, window_seconds=60) == []

# ---------- service probing ----------

JDWP = "JDWP-Handshake\x00\x00\x00\x0b"
RMI = "JRMI\x00\x02K"
MSSQL = "\x12\x01\x004\x00\x00"
SIP = "OPTIONS sip:nm SIP/2.0\r\nFrom: <sip:nm@nm>;tag=root\r\n"


def add_payloads(db, src_ip, messages, start=100.0, step=0.5):
    with db:
        db.executemany(
            "INSERT INTO honeypot_events (ts, event, src_ip, src_port, data) VALUES (?, 'data', ?, 1, ?)",
            [(start + i * step, src_ip, text) for i, text in enumerate(messages)],
        )


def test_several_different_protocols_in_a_short_time_is_service_probing(db):
    add_payloads(db, "172.18.0.9", [JDWP, RMI, MSSQL, SIP])

    [alert] = detect_service_probing(db, min_protocols=3, window_seconds=60)

    assert alert.rule == "service_probing"
    assert alert.src_ip == "172.18.0.9"
    assert alert.severity == "medium"
    assert alert.evidence["distinct_protocols"] == 4
    assert "Java RMI call" in alert.evidence["protocols"]
    assert "Nmap" in alert.description


def test_repeating_the_same_probe_is_not_service_probing(db):
    add_payloads(db, "172.18.0.9", [RMI] * 30)

    assert detect_service_probing(db, min_protocols=3, window_seconds=60) == []


def test_probes_spread_over_a_long_time_are_not_flagged(db):
    add_payloads(db, "172.18.0.9", [JDWP, RMI, MSSQL, SIP], step=500.0)

    assert detect_service_probing(db, min_protocols=3, window_seconds=60) == []


def test_ordinary_visitors_are_not_flagged(db):
    ordinary = ["GET / HTTP/1.1\r\nHost: lab\r\n\r\n", "SSH-2.0-OpenSSH_9.6\r\n", "hello\n", "POST /login HTTP/1.1\r\n"]
    add_payloads(db, "172.18.0.9", ordinary)

    assert detect_service_probing(db, min_protocols=3, window_seconds=60) == []


def test_unrecognised_data_is_never_counted_as_a_probe(db):
    add_payloads(db, "172.18.0.9", UNKNOWN_PROBES)

    assert detect_service_probing(db, min_protocols=1, window_seconds=60) == []


def test_each_visitor_is_judged_separately(db):
    add_payloads(db, "172.18.0.9", [JDWP, RMI])
    add_payloads(db, "172.18.0.8", [MSSQL, SIP])   # two protocols each: below the limit of 3

    assert detect_service_probing(db, min_protocols=3, window_seconds=60) == []


def test_service_probing_from_an_ignored_network_is_skipped(db):
    add_payloads(db, "192.168.65.1", [JDWP, RMI, MSSQL, SIP])
    networks = parse_networks(DEFAULT_IGNORED_NETWORKS)

    assert detect_service_probing(db, min_protocols=3, window_seconds=60, ignored=networks) == []


def test_the_real_nmap_scan_captured_in_the_lab_is_detected(db):
    # The 15 messages the honeypot received from `nmap -sV` (see tests/test_payloads.py).
    messages = [text for text, _ in NMAP_SCAN_PAYLOADS] + UNKNOWN_PROBES
    add_payloads(db, "172.18.0.1", messages, step=0.3)

    alerts = run_detectors(db)
    [alert] = [alert for alert in alerts if alert.rule == "service_probing"]

    assert alert.evidence["distinct_protocols"] == 9
    assert alert.evidence["messages"] == len(NMAP_SCAN_PAYLOADS)   # only the recognised ones count


def test_service_probing_alerts_are_not_duplicated(db):
    add_payloads(db, "172.18.0.9", [JDWP, RMI, MSSQL, SIP])

    assert save_alerts(db, run_detectors(db)) == 1
    assert save_alerts(db, run_detectors(db)) == 0

# ---------- saving alerts ----------

def test_running_the_detector_twice_does_not_duplicate_alerts(db):
    insert_flows(db, [flow(SCANNER, TARGET, port, 100.0 + port * 0.01) for port in range(1, 51)], "x")

    first = save_alerts(db, run_detectors(db))
    second = save_alerts(db, run_detectors(db))

    assert (first, second) == (1, 0)
    assert count_rows(db)["alerts"] == 1


def test_evidence_is_stored_as_json(db):
    save_alerts(db, [Alert(ts=1.0, rule="r", severity="medium", src_ip="1.1.1.1", description="d", evidence={"a": 1})])

    assert db.execute("SELECT evidence FROM alerts").fetchone()["evidence"] == '{"a": 1}'


def test_run_detectors_ignores_docker_desktop_by_default(db):
    insert_flows(db, [flow("192.168.65.1", "192.168.65.7", port, 100.0 + port * 0.01) for port in range(1, 51)], "x")

    assert run_detectors(db) == []