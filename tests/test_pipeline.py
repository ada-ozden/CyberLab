import json
import sys
from datetime import datetime, timezone

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter, wrpcap

from analyzer import cli
from analyzer.pipeline import update_all
from common.database import connect, count_rows


@pytest.fixture
def db(tmp_path):
    connection = connect(tmp_path / "test.db")
    yield connection
    connection.close()


@pytest.fixture
def folder(tmp_path):
    path = tmp_path / "pcaps"
    path.mkdir()
    return path


def syn_packets(count, start_port=1, source="172.18.0.9", target="172.18.0.2", t0=1000.0):
    # `count` connection attempts from one source to `count` different ports.
    packets = []

    for i in range(count):
        packet = Ether() / IP(src=source, dst=target) / TCP(sport=44444, dport=start_port + i, flags="S")
        packet.time = t0 + i * 0.01
        packets.append(packet)

    return packets


def write_capture(path, packets):
    wrpcap(str(path), packets)
    return path


def write_log(path, lines):
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    return path


def iso(seconds):
    return datetime.fromtimestamp(1_790_000_000 + seconds, timezone.utc).isoformat()


def probe_log(path, src="172.18.0.1"):
    probes = ["JDWP-Handshake\x00\x00\x00\x0b", "JRMI\x00\x02K", "\x12\x01\x004\x00\x00", "OPTIONS sip:nm SIP/2.0\r\n"]
    return write_log(
        path,
        [
            {"ts": iso(i * 0.5), "event": "data", "src_ip": src, "src_port": 40000 + i, "data": text}
            for i, text in enumerate(probes)
        ],
    )


def run(db, folder, log, **options):
    return update_all(db, folder, log, options)


# ---------- captures ----------

def test_a_new_capture_is_read(db, folder, tmp_path):
    write_capture(folder / "a.pcap", syn_packets(30))

    summary = run(db, folder, tmp_path / "none.log")

    assert (summary.captures_new, summary.captures_changed, summary.captures_unchanged) == (1, 0, 0)
    assert summary.flows_stored == 30
    assert count_rows(db)["flows"] == 30


def test_the_second_run_skips_captures_it_has_already_read(db, folder, tmp_path):
    write_capture(folder / "a.pcap", syn_packets(30))
    run(db, folder, tmp_path / "none.log")

    summary = run(db, folder, tmp_path / "none.log")

    assert (summary.captures_new, summary.captures_changed, summary.captures_unchanged) == (0, 0, 1)
    assert summary.flows_stored == 0
    assert count_rows(db)["flows"] == 30


def test_a_capture_that_has_grown_is_read_again_without_duplicates(db, folder, tmp_path):
    write_capture(folder / "live.pcap", syn_packets(10))
    run(db, folder, tmp_path / "none.log")

    write_capture(folder / "live.pcap", syn_packets(25))   # tcpdump kept writing to the same file
    summary = run(db, folder, tmp_path / "none.log")

    assert (summary.captures_new, summary.captures_changed) == (0, 1)
    assert count_rows(db)["flows"] == 25                   # replaced, not 10 + 25


def test_only_the_capture_that_changed_is_read_again(db, folder, tmp_path):
    write_capture(folder / "a.pcap", syn_packets(10))
    write_capture(folder / "b.pcap", syn_packets(10, start_port=500))
    run(db, folder, tmp_path / "none.log")

    write_capture(folder / "b.pcap", syn_packets(20, start_port=500))
    summary = run(db, folder, tmp_path / "none.log")

    assert (summary.captures_changed, summary.captures_unchanged) == (1, 1)
    assert count_rows(db)["flows"] == 10 + 20


def test_a_capture_cut_in_the_middle_of_a_packet_is_still_read(db, folder, tmp_path):
    # tcpdump may be half-way through writing a packet when we look.
    path = write_capture(folder / "live.pcap", syn_packets(20))
    path.write_bytes(path.read_bytes()[:-20])

    summary = run(db, folder, tmp_path / "none.log")

    assert summary.captures_failed == []
    assert summary.captures_new == 1
    assert count_rows(db)["flows"] >= 19


def test_an_unreadable_capture_is_reported_and_tried_again_later(db, folder, tmp_path):
    write_capture(folder / "good.pcap", syn_packets(10))
    (folder / "new.pcap").write_bytes(b"")                 # tcpdump has created it but written nothing yet

    first = run(db, folder, tmp_path / "none.log")

    assert [name for name, _ in first.captures_failed] == ["new.pcap"]
    assert first.captures_new == 1                         # the good one was still read
    assert count_rows(db)["flows"] == 10

    write_capture(folder / "new.pcap", syn_packets(5, start_port=900))
    second = run(db, folder, tmp_path / "none.log")

    assert second.captures_failed == []
    assert (second.captures_new, second.captures_unchanged) == (1, 1)
    assert count_rows(db)["flows"] == 15


def test_a_garbage_file_never_stops_the_update(db, folder, tmp_path):
    (folder / "bad.pcap").write_bytes(b"this is not a capture" * 10)
    write_capture(folder / "good.pcap", syn_packets(10))

    summary = run(db, folder, tmp_path / "none.log")

    assert len(summary.captures_failed) == 1
    assert count_rows(db)["flows"] == 10


def test_a_missing_or_empty_folder_is_not_an_error(db, tmp_path):
    for folder in (tmp_path / "does_not_exist", tmp_path):
        summary = run(db, folder, tmp_path / "none.log")

        assert summary.captures_new == 0
        assert summary.alerts == []


def test_files_that_are_not_captures_are_ignored(db, folder, tmp_path):
    (folder / "notes.txt").write_text("hello", encoding="utf-8")
    write_capture(folder / "a.pcap", syn_packets(5))

    summary = run(db, folder, tmp_path / "none.log")

    assert summary.captures_new == 1
    assert summary.captures_failed == []


def test_pcapng_files_are_read_too(db, folder, tmp_path):
    writer = PcapNgWriter(str(folder / "b.pcapng"))
    for packet in syn_packets(8):
        writer.write(packet)
    writer.close()

    summary = run(db, folder, tmp_path / "none.log")

    assert summary.captures_new == 1
    assert count_rows(db)["flows"] == 8


# ---------- honeypot log ----------

def test_honeypot_lines_are_loaded_once(db, folder, tmp_path):
    log = probe_log(tmp_path / "honeypot.log")

    first = run(db, folder, log)
    second = run(db, folder, log)

    assert first.honeypot_events == 4
    assert second.honeypot_events == 0
    assert count_rows(db)["honeypot_events"] == 4


# ---------- detector ----------

def test_a_scan_and_a_probing_visitor_both_raise_alerts_exactly_once(db, folder, tmp_path):
    write_capture(folder / "scan.pcap", syn_packets(50))
    log = probe_log(tmp_path / "honeypot.log")

    first = run(db, folder, log)
    second = run(db, folder, log)

    assert sorted(alert.rule for alert in first.alerts) == ["port_scan", "service_probing"]
    assert first.alerts_new == 2
    assert len(second.alerts) == 2 and second.alerts_new == 0
    assert count_rows(db)["alerts"] == 2


def test_detector_settings_are_passed_on(db, folder, tmp_path):
    write_capture(folder / "scan.pcap", syn_packets(50))

    relaxed = run(db, folder, tmp_path / "none.log", min_ports=100)
    strict = run(db, folder, tmp_path / "none.log", min_ports=10)

    assert relaxed.alerts == []
    assert [alert.rule for alert in strict.alerts] == ["port_scan"]


# ---------- the command ----------

def test_the_update_command_prints_a_summary(db, folder, tmp_path, monkeypatch, capsys):
    write_capture(folder / "scan.pcap", syn_packets(50))
    log = probe_log(tmp_path / "honeypot.log")
    database = str(tmp_path / "cli.db")
    arguments = ["cyberlab", "update", "--db", database, "--pcaps", str(folder), "--logs", str(log)]

    monkeypatch.setattr(sys, "argv", arguments)
    assert cli.main() == 0
    first = capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", arguments)
    assert cli.main() == 0
    second = capsys.readouterr().out

    assert "Captures:  1 new, 0 grown, 0 unchanged, 0 unreadable" in first
    assert "Alerts:    2 found, 2 new" in first
    assert "port_scan" in first and "service_probing" in first
    assert "Captures:  0 new, 0 grown, 1 unchanged, 0 unreadable" in second
    assert "Alerts:    2 found, 0 new" in second