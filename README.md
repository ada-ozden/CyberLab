# CyberLab

A small home lab I built to learn Nmap, packet captures and Docker. It runs three targets in
containers (a honeypot, DVWA and Juice Shop), records the network traffic and the honeypot's log,
flags port scans and similar probing, and shows the results in a Streamlit dashboard.

Only point this at machines you own.

```
 honeypot, DVWA, Juice Shop (Docker)
        |                       |
  tcpdump container        honeypot.log
        |                       |
    pcap parser            log parser
          \                    /
           data/cyberlab.db (SQLite)
                    |
           detector -> alerts
                    |
         dashboard + PDF report

 Nmap scanner -> data/scans/*.json   (kept separate for now)
```

- `scanner/` runs Nmap and saves the results as JSON
- `analyzer/` loads captures and logs into the database and runs the detector
- `common/` database code and the payload recogniser
- `dashboard/` the Streamlit app and the PDF report
- `docker/` the lab, plus optional capture and attacker containers

## Setup

Written for Windows. You need Python 3.10 or newer, Nmap on your PATH (`nmap --version` should
work) and Docker Desktop.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest
```

I run everything as `python -m <tool>` because Application Control on my machine blocks the small
`.exe` launchers (`pytest.exe`, `streamlit.exe`, `pip.exe`) but lets Python through.

## The lab

```powershell
docker compose -f docker/docker-compose.yml up --build -d
```

Juice Shop is at http://localhost:3000, DVWA at http://localhost:8080 and the honeypot on port
2222. Juice Shop and DVWA only listen on this PC. The honeypot listens on every interface because
it has to be reachable to be any use. Stop it all with
`docker compose -f docker/docker-compose.yml down`.

## A normal run

```powershell
# record traffic (the port scan rule needs this)
docker compose -f docker/docker-compose.yml --profile capture up -d capture

# make something happen: a scan from inside the lab network, or from this PC
docker compose -f docker/docker-compose.yml --profile attack run --rm attacker
python -m scanner.cli scan 127.0.0.1

# stop recording
docker compose -f docker/docker-compose.yml stop capture

# load new captures and honeypot lines, then run the detector
python -m analyzer.cli update

# dashboard at http://localhost:8501
python -m streamlit run dashboard\app.py
```

Stopping the capture is optional. A file that's still being written is read as far as it goes and
picked up again next time. `update` remembers what it has already read and never duplicates
alerts, so run it as often as you like. The first start of the dashboard can take a minute while
Windows scans the freshly installed packages.

## Other commands

```powershell
python -m scanner.cli discover <target>   # find live hosts
python -m scanner.cli scan <target>       # ports and services of one target
python -m scanner.cli full <target>       # discover, then scan every live host
python -m analyzer.cli pcap <file>        # load one capture
python -m analyzer.cli logs [file]        # load new honeypot lines
python -m analyzer.cli detect             # run the detector on what's in the database
python -m analyzer.cli stats              # row counts
python -m analyzer.cli sql "SELECT ..."   # read-only query
```

`detect` and `update` also take `--min-ports`, `--min-connections`, `--min-protocols`, `--window`
(seconds) and `--ignore <network>`. The last one can be repeated and replaces the default.

## Detection

Three rules, all with a 60 second window by default.

- `port_scan`: one address starts connections to 10 or more different TCP ports on one target.
  Only connection attempts count (a SYN without an ACK), so a busy server's replies never
  trigger it. Medium, or high from 100 ports.
- `honeypot_burst`: 10 or more connections to the honeypot from one address. Medium, or high
  from 50.
- `service_probing`: one address sends the honeypot messages in 3 or more different protocols,
  which is what Nmap's `-sV` does. Medium.

Traffic between Docker Desktop and Windows (192.168.65.0/24) is ignored unless you pass your own
`--ignore`. A SYN scan never completes a connection, so the honeypot doesn't see it but the
capture does. A version scan makes real connections, so the honeypot sees it. That's why there
are two data sources.

## Where things live

- `data/pcaps/` captures from the capture container
- `data/logs/honeypot.log` honeypot events, one JSON object per line
- `data/cyberlab.db` the SQLite database with flows, honeypot events and alerts. Delete it to
  start over, `update` rebuilds it from the captures and logs.
- `data/scans/` Nmap results as JSON

All times are UTC.

## Tests

`python -m pytest`. They build their own captures and databases, so they need neither Docker nor
Nmap. The dashboard tests start the app without a browser, and the first run can be slow for the
same reason the dashboard's first start is.

## Known limits

- Everything coming from this PC shows up as 172.18.0.1, because of how Docker Desktop
  forwards traffic. My own tests and a real visitor look the same.
- The dashboard has no login. `.streamlit/config.toml` makes it listen on localhost only; leave
  that alone unless you add authentication.
- Honeypot payloads are stored as text, so bytes that aren't valid text become `\ufffd` and are
  lost. Keeping the raw bytes would be better.
- Payload recognition is a lookup table in `common/payloads.py` covering about ten protocols.
  Anything else shows as "Unrecognised data". Add a protocol by adding an entry.
- Capturing with `-i any` may record some packets twice. Counts can be inflated; the port scan
  rule isn't affected.
- Nmap results aren't in the database, so the dashboard doesn't show them.
- The thresholds are defaults for a small lab. Tune them with the options above.

## Next

Put scan results in the database and the dashboard, keep the raw honeypot bytes, add more rules
(repeated failed logins, web attack requests), notifications, more honeypot services.