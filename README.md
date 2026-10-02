# CyberLab

A learning lab for network scanning and traffic analysis: an Nmap scanner,
a Docker lab (Juice Shop, DVWA, honeypot), and (coming) a PCAP parser,
analyzer and Streamlit dashboard.

> Only scan machines you own or have permission to test.

## Requirements (Windows)

- Python 3.10+
- [Nmap](https://nmap.org/download.html), added to PATH (check: `nmap --version`)
- Docker Desktop

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

## Start the lab

```powershell
docker compose -f docker/docker-compose.yml up --build -d
```

| Service    | Address                 |
|------------|-------------------------|
| Juice Shop | http://localhost:3000   |
| DVWA       | http://localhost:8080   |
| Honeypot   | localhost:2222 (TCP)    |

Honeypot events are written as JSON lines to `data/logs/honeypot.log`.
Stop the lab with `docker compose -f docker/docker-compose.yml down`.

## Scan

```powershell
python -m scanner.cli discover 192.168.1.0/24   # find live hosts
python -m scanner.cli scan 127.0.0.1            # scan one target
python -m scanner.cli full 192.168.1.0/24       # discover, then scan all live hosts
```

Results are saved to `data/scans/`.

## Tests

```powershell
pytest -v
```