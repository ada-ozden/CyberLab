import importlib.util
import json
import socket
import threading
import time
from pathlib import Path

import pytest

HONEYPOT_FILE = (
    Path(__file__).resolve().parent.parent / "docker" / "honeypot" / "honeypot.py"
)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_lines(log_file, count, seconds=3):
    # The honeypot works in other threads, so give it a moment to write.
    deadline = time.time() + seconds

    while time.time() < deadline:
        if log_file.exists():
            lines = log_file.read_text(encoding="utf-8").splitlines()
            if len(lines) >= count:
                return [json.loads(line) for line in lines]
        time.sleep(0.05)

    pytest.fail(f"expected {count} log lines within {seconds}s")


@pytest.fixture
def honeypot(tmp_path, monkeypatch):
    port = free_port()
    log_file = tmp_path / "honeypot.log"

    # honeypot.py reads these when it is imported.
    monkeypatch.setenv("PORT", str(port))
    monkeypatch.setenv("LOG_FILE", str(log_file))

    spec = importlib.util.spec_from_file_location("honeypot_under_test", HONEYPOT_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    threading.Thread(target=module.start_honeypot, daemon=True).start()

    # Wait until the port accepts connections.
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)

    # Our readiness probe was logged too: wait for that line, then forget it.
    wait_for_lines(log_file, 1)
    log_file.unlink()

    return port, log_file


def test_connection_and_data_are_logged_as_json(honeypot):
    port, log_file = honeypot

    with socket.create_connection(("127.0.0.1", port)) as client:
        client.sendall(b"SSH-2.0-test\r\n")

    events = wait_for_lines(log_file, 2)

    assert [event["event"] for event in events] == ["connection", "data"]
    assert events[1]["data"] == "SSH-2.0-test\r\n"
    assert events[0]["src_ip"] == "127.0.0.1"


def test_idle_client_does_not_block_others(honeypot):
    port, log_file = honeypot

    idle = socket.create_connection(("127.0.0.1", port))  # connects, says nothing

    with socket.create_connection(("127.0.0.1", port)) as client:
        client.sendall(b"hello")

    events = wait_for_lines(log_file, 3)  # idle connect + connect + data
    idle.close()

    assert any(event.get("data") == "hello" for event in events)