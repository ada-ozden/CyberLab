from pathlib import Path

import pytest

from scanner.parser import parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


@pytest.fixture
def hosts():
    return parse_nmap_xml(FIXTURE.read_text(encoding="utf-8"))


def test_down_hosts_are_skipped(hosts):
    assert len(hosts) == 1


def test_ip_is_chosen_over_mac_address(hosts):
    assert hosts[0].ip == "192.168.1.10"


def test_hostname_is_read(hosts):
    assert hosts[0].hostname == "lab-server"


def test_ports_are_parsed(hosts):
    ssh, http = hosts[0].ports

    assert (ssh.number, ssh.protocol, ssh.state) == (22, "tcp", "open")
    assert (ssh.service, ssh.product, ssh.version) == ("ssh", "OpenSSH", "9.6")

    assert http.state == "closed"
    assert http.product is None


def test_empty_scan_returns_no_hosts():
    assert parse_nmap_xml("<nmaprun></nmaprun>") == []