import json
import os
import socket
import threading
from datetime import datetime, timezone

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "2222"))
LOG_FILE = os.environ.get("LOG_FILE", "/app/logs/honeypot.log")

MAX_BYTES = 4096        # never read more than this from one client
CLIENT_TIMEOUT = 5      # seconds to wait for a client to send something

# Several threads write to the same file, so only one may write at a time.
log_lock = threading.Lock()


def log_event(event, src_ip, src_port, **extra):
    # One JSON object per line ("JSON Lines"): easy for the analyzer to parse later.
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "src_ip": src_ip,
        "src_port": src_port,
        **extra,
    }

    line = json.dumps(record)

    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(line + "\n")

    print(line, flush=True)


def handle_client(client, address):
    src_ip, src_port = address

    log_event("connection", src_ip, src_port)

    try:
        client.settimeout(CLIENT_TIMEOUT)
        data = client.recv(MAX_BYTES)

        if data:
            log_event(
                "data",
                src_ip,
                src_port,
                data=data.decode("utf-8", errors="replace"),
            )

    except socket.timeout:
        log_event("timeout", src_ip, src_port)

    except OSError as error:
        # e.g. the client reset the connection
        log_event("error", src_ip, src_port, error=str(error))

    finally:
        client.close()


def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    print(f"Honeypot listening on {HOST}:{PORT}", flush=True)

    while True:
        client, address = server.accept()

        # One thread per client, so a slow client can't block the others.
        threading.Thread(
            target=handle_client,
            args=(client, address),
            daemon=True,
        ).start()


if __name__ == "__main__":
    start_honeypot()