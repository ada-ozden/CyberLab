import json
from datetime import datetime, timezone

import pytest

from analyzer.log_parser import ingest_honeypot_log, parse_line
from analyzer.models import Flow
from common.database import connect, count_rows, insert_flows


@pytest.fixture
def db(tmp_path):
    connection = connect(tmp_path / "test.db")
    yield connection
    connection.close()


def flow(dst_port=22, **overrides):
    values = dict(
        src_ip="10.0.0.9", dst_ip="10.0.0.5", src_port=40000, dst_port=dst_port,
        protocol="tcp", packets=1, byte_count=54, first_seen=1.0, last_seen=1.0,
        syn_count=1, tcp_flags="S",
    )
    values.update(overrides)
    return Flow(**values)


def line(event="connection", ts="2026-10-02T15:28:47.695656+00:00", **extra):
    record = {"ts": ts, "event": event, "src_ip": "172.18.0.1", "src_port": 42006}
    record.update(extra)
    return json.dumps(record) + "\n"


# ---------- database ----------

def test_connect_twice_is_safe(tmp_path):
    connect(tmp_path / "a.db").close()
    connection = connect(tmp_path / "a.db")  # schema already exists

    assert count_rows(connection) == {"flows": 0, "honeypot_events": 0, "alerts": 0}


def test_insert_flows_and_query_them(db):
    insert_flows(db, [flow(22), flow(80), flow(443)], source="scan.pcap")

    row = db.execute(
        "SELECT COUNT(DISTINCT dst_port) AS ports FROM flows WHERE syn_count > 0"
    ).fetchone()

    assert row["ports"] == 3


def test_reingesting_same_capture_replaces_it(db):
    insert_flows(db, [flow(22), flow(80)], source="scan.pcap")
    insert_flows(db, [flow(22), flow(80)], source="scan.pcap")
    insert_flows(db, [flow(22)], source="other.pcap")

    assert count_rows(db)["flows"] == 3  # 2 (not 4) + 1


# ---------- honeypot log ----------

def test_parse_line_converts_timestamp_to_unix_time():
    ts, event, src_ip, src_port, data = parse_line(line(data="hi"))

    expected = datetime(2026, 10, 2, 15, 28, 47, 695656, tzinfo=timezone.utc).timestamp()
    assert ts == pytest.approx(expected)
    assert (event, src_ip, src_port, data) == ("connection", "172.18.0.1", 42006, "hi")


@pytest.mark.parametrize("bad", ["not json", "{}", '{"ts": "yesterday", "event": "x", "src_ip": "1"}', "[]"])
def test_parse_line_rejects_bad_lines(bad):
    assert parse_line(bad) is None


def test_only_new_lines_are_ingested(db, tmp_path):
    log = tmp_path / "honeypot.log"
    log.write_text(line() + line("data", data="x"), encoding="utf-8")

    assert ingest_honeypot_log(db, log) == (2, 0)
    assert ingest_honeypot_log(db, log) == (0, 0)  # nothing new

    with log.open("a", encoding="utf-8") as file:
        file.write(line("timeout"))

    assert ingest_honeypot_log(db, log) == (1, 0)
    assert count_rows(db)["honeypot_events"] == 3


def test_half_written_line_is_left_for_next_time(db, tmp_path):
    log = tmp_path / "honeypot.log"
    full = line()
    log.write_text(full + line("data", data="x")[:20], encoding="utf-8")  # cut off, no newline

    assert ingest_honeypot_log(db, log) == (1, 0)

    with log.open("a", encoding="utf-8") as file:
        file.write(line("data", data="x")[20:])  # the honeypot finishes the line

    assert ingest_honeypot_log(db, log) == (1, 0)
    assert count_rows(db)["honeypot_events"] == 2


def test_invalid_lines_are_skipped_and_counted(db, tmp_path):
    log = tmp_path / "honeypot.log"
    log.write_text("2026-01-01 old plain text line\n" + line(), encoding="utf-8")

    assert ingest_honeypot_log(db, log) == (1, 1)


def test_replaced_log_file_is_read_from_the_start(db, tmp_path):
    log = tmp_path / "honeypot.log"
    log.write_text(line() * 3, encoding="utf-8")
    ingest_honeypot_log(db, log)

    log.write_text(line(), encoding="utf-8")  # shorter than before = new file

    assert ingest_honeypot_log(db, log) == (1, 0)


def test_missing_log_file_is_not_an_error(db, tmp_path):
    assert ingest_honeypot_log(db, tmp_path / "nope.log") == (0, 0)