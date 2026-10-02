import subprocess
from types import SimpleNamespace

import pytest

from scanner import nmap_scanner
from scanner.nmap_scanner import NmapScanner


@pytest.fixture
def scanner(monkeypatch):
    # Pretend Nmap is installed, so the tests also work on a PC without it.
    monkeypatch.setattr(nmap_scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    return NmapScanner(timeout=5)


def test_missing_nmap_raises(monkeypatch):
    monkeypatch.setattr(nmap_scanner.shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match="Nmap was not found"):
        NmapScanner()


@pytest.mark.parametrize("target", ["", "-oN", "--script=vuln"])
def test_invalid_targets_are_rejected(scanner, target):
    with pytest.raises(ValueError):
        scanner.scan(target)


def test_scan_many_with_no_targets_does_not_run_nmap(scanner, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("nmap should not be run")

    monkeypatch.setattr(nmap_scanner.subprocess, "run", fail)

    assert scanner.scan_many([]) == []


def test_timeout_becomes_runtime_error(scanner, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=5)

    monkeypatch.setattr(nmap_scanner.subprocess, "run", timeout)

    with pytest.raises(RuntimeError, match="did not finish"):
        scanner.scan("127.0.0.1")


def test_nonzero_exit_becomes_runtime_error(scanner, monkeypatch):
    result = SimpleNamespace(returncode=1, stderr="boom", stdout="")
    monkeypatch.setattr(nmap_scanner.subprocess, "run", lambda *a, **k: result)

    with pytest.raises(RuntimeError, match="boom"):
        scanner.scan("127.0.0.1")


def test_successful_scan_is_parsed(scanner, monkeypatch):
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>'
    )
    result = SimpleNamespace(returncode=0, stderr="", stdout=xml)
    monkeypatch.setattr(nmap_scanner.subprocess, "run", lambda *a, **k: result)

    hosts = scanner.scan("10.0.0.9")

    assert [host.ip for host in hosts] == ["10.0.0.9"]