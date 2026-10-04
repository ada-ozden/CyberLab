import pytest

from common.database import connect, connect_readonly
from dashboard import queries
from dashboard.data import DOCKER_DESKTOP_PREFIXES, db_signature, display_payload, load_dashboard_data, port_label

from .conftest import T0


@pytest.fixture
def conn(seeded_db):
    connection = connect_readonly(seeded_db)
    yield connection
    connection.close()


def test_pick_bucket_keeps_charts_small():
    assert queries.pick_bucket(60) == 1
    assert queries.pick_bucket(3600) == 30          # exactly 120 bars: still within the target
    assert queries.pick_bucket(7200) == 60          # 30s buckets would give 240 bars, so step up
    assert queries.pick_bucket(30 * 86400) == 21600  # 6-hour buckets = exactly 120 bars
    assert queries.pick_bucket(100 * 86400) == 86400  # 100 daily bars
    assert queries.pick_bucket(10 ** 9) == 86400     # never goes beyond the biggest bucket


def test_time_bounds(conn):
    low, high = queries.time_bounds(conn)

    assert low == pytest.approx(T0 + 0.01) or low == pytest.approx(T0)
    assert high >= T0 + 300


def test_time_bounds_of_an_empty_database(tmp_path):
    connect(tmp_path / "empty.db").close()

    with connect_readonly(tmp_path / "empty.db") as connection:
        assert queries.time_bounds(connection) is None


def test_overview_counts(conn):
    counts = queries.overview(conn, None, None, ())

    assert counts["flows"] == 541
    assert counts["honeypot_events"] == 17
    assert counts["alerts"] >= 2
    assert counts["high_alerts"] >= 1


def test_hiding_docker_desktop_removes_its_flows(conn):
    shown = queries.overview(conn, None, None, ())["flows"]
    hidden = queries.overview(conn, None, None, DOCKER_DESKTOP_PREFIXES)["flows"]

    assert shown - hidden == 300


def test_top_sources_ranks_by_connection_attempts_not_replies(conn):
    sources = queries.top_sources(conn, None, None, DOCKER_DESKTOP_PREFIXES)

    assert [row["src_ip"] for row in sources] == ["172.18.0.5", "172.18.0.1"]
    assert sources[0]["ports_tried"] == 200
    assert "172.18.0.2" not in [row["src_ip"] for row in sources]  # the server only replied


def test_top_sources_would_be_dominated_by_docker_noise_if_not_hidden(conn):
    sources = queries.top_sources(conn, None, None, ())

    assert sources[0]["src_ip"] == "192.168.65.1"


def test_top_ports_counts_completed_connections_and_ignores_scanned_ports(conn):
    ports = queries.top_ports(conn, None, None, DOCKER_DESKTOP_PREFIXES)

    assert [(row["dst_port"], row["connections"]) for row in ports] == [(3000, 40)]
    # The scanner probed ports 1-200 with SYN-only flows: none of them completed.


def test_time_filter(conn):
    everything = queries.overview(conn, None, None, ())["flows"]
    later_only = queries.overview(conn, T0 + 60, None, ())["flows"]

    assert 0 < later_only < everything


def test_bucketing_groups_events(conn):
    rows = queries.attempts_over_time(conn, None, None, DOCKER_DESKTOP_PREFIXES, 60)

    assert sum(row["attempts"] for row in rows) == 240        # 200 scan + 40 browsing
    assert all(row["bucket"] % 60 == 0 for row in rows)


def test_alerts_are_listed_high_first_with_parsed_evidence(conn):
    alerts = queries.list_alerts(conn, None, None)

    assert alerts[0]["severity"] == "high"
    assert isinstance(alerts[0]["evidence"], dict)
    assert any(alert["rule"] == "port_scan" for alert in alerts)


def test_honeypot_queries(conn):
    assert queries.honeypot_over_time(conn, None, None, 60)[0]["connections"] > 0

    [visitor] = [row for row in queries.honeypot_sources(conn, None, None) if row["src_ip"] == "172.18.0.1"]
    assert (visitor["connections"], visitor["payloads"]) == (15, 1)

    payloads = queries.honeypot_payloads(conn, None, None)
    assert payloads[0]["src_ip"] == "10.9.9.9"      # newest first


def test_dashboard_connection_cannot_write(seeded_db):
    with connect_readonly(seeded_db) as connection:
        with pytest.raises(Exception, match="readonly"):
            connection.execute("DELETE FROM flows")


def test_missing_database_is_reported(tmp_path):
    with pytest.raises(FileNotFoundError):
        connect_readonly(tmp_path / "nope.db")


def test_load_dashboard_data_bundles_everything(seeded_db):
    data = load_dashboard_data(seeded_db)

    assert data["empty"] is False
    assert data["overview"]["alerts"] >= 2
    assert data["sources"][0]["src_ip"] == "172.18.0.5"
    assert data["bucket"] in queries.BUCKETS


def test_load_dashboard_data_window(seeded_db):
    everything = load_dashboard_data(seeded_db)
    recent = load_dashboard_data(seeded_db, window_seconds=120)

    assert recent["since"] > everything["since"]
    assert recent["overview"]["flows"] < everything["overview"]["flows"]


def test_load_dashboard_data_of_an_empty_database(tmp_path):
    connect(tmp_path / "empty.db").close()

    data = load_dashboard_data(tmp_path / "empty.db")

    assert data["empty"] is True
    assert data["overview"]["flows"] == 0


def test_db_signature_changes_when_data_is_written(seeded_db):
    before = db_signature(seeded_db)

    connection = connect(seeded_db)
    with connection:
        connection.execute("INSERT INTO honeypot_events (ts, event, src_ip) VALUES (1, 'connection', '1.1.1.1')")
    after = db_signature(seeded_db)
    connection.close()

    assert before != after


def test_port_label():
    assert port_label(3000) == "3000 - Juice Shop"
    assert port_label(12345) == "12345"

def test_display_payload_makes_binary_readable():
    assert display_payload("GET / HTTP/1.1\r\n\r\n") == "GET / HTTP/1.1\\r\\n\\r\\n"
    assert display_payload("N\x00S\x00P\x00") == "N\\x00S\\x00P\\x00"
    assert display_payload("bad\ufffdbyte") == "bad\\ufffdbyte"
    assert display_payload("\u202e") == "\\u202e"        # right-to-left override can't flip the text
    assert display_payload("\U000E0001") == "\\U000e0001"  # an invisible character outside the BMP
    assert display_payload("\U0001F600") == "\U0001F600"   # an emoji is real text: kept as it is
    assert display_payload("caf\u00e9") == "caf\u00e9"     # normal text is untouched
    assert display_payload(None) == ""


def test_display_payload_truncates_without_cutting_an_escape():
    result = display_payload("\x00" * 50, 10)

    assert result == "\\x00..."
    assert len(result) <= 10
    assert display_payload("short", 10) == "short"