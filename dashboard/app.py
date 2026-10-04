import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Streamlit runs this file as a script, so the project root is not importable by default.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st  # noqa: E402

from common.database import DEFAULT_DB_PATH  # noqa: E402
from dashboard import charts  # noqa: E402
from dashboard.data import db_signature, display_payload, load_dashboard_data, port_label  # noqa: E402
from dashboard.report import build_report  # noqa: E402

DB_PATH = Path(os.environ.get("CYBERLAB_DB", DEFAULT_DB_PATH))

PAGES = ("Overview", "Alerts", "Network traffic", "Honeypot activity")

WINDOWS = {
    "All data": None,
    "Latest 1 hour": 3600,
    "Latest 6 hours": 6 * 3600,
    "Latest 24 hours": 24 * 3600,
    "Latest 7 days": 7 * 24 * 3600,
}

SEVERITY_MARK = {"high": "\u25B2 HIGH", "medium": "\u25CF MEDIUM"}  # shape + word, never colour alone

st.set_page_config(page_title="CyberLab", page_icon="\U0001F6E1\uFE0F", layout="wide")


@st.cache_data(show_spinner=False)
def cached_load(db_path, signature, window_seconds, hide_docker_desktop):
    # `signature` is not used inside: it only makes the cache notice when the database changes.
    return load_dashboard_data(db_path, window_seconds, hide_docker_desktop)


def is_dark():
    try:
        return st.context.theme.type == "dark"
    except Exception:  # older Streamlit, or running outside a browser session
        return False


def fmt_time(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def show_chart(figure, empty_message):
    if figure is None:
        st.info(empty_message)
    else:
        st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})


def show_table(rows, caption=None, **options):
    # Tables are the accessible twin of every chart: the same numbers as plain text.
    if caption:
        st.caption(caption)

    st.dataframe(rows, hide_index=True, width="stretch", **options)


def alert_rows(alerts):
    return [
        {
            "Severity": SEVERITY_MARK.get(alert["severity"], alert["severity"]),
            "Time (UTC)": fmt_time(alert["ts"]),
            "Rule": alert["rule"],
            "Source": alert["src_ip"],
            "Description": alert["description"],
        }
        for alert in alerts
    ]


# ---------------------------------------------------------------- pages

def page_overview(data, dark):
    counts = data["overview"]
    columns = st.columns(4)
    columns[0].metric("Network flows", f"{counts['flows']:,}")
    columns[1].metric("Honeypot events", f"{counts['honeypot_events']:,}")
    columns[2].metric("Alerts", f"{counts['alerts']:,}")
    columns[3].metric("High severity", f"{counts['high_alerts']:,}")

    st.subheader("Alerts over time")
    show_chart(
        charts.alerts_over_time(data["alerts_over_time"], data["bucket"], dark),
        "No alerts in this period. Run `python -m analyzer.cli detect` after loading new data.",
    )

    st.subheader("Most serious alerts")

    if data["alerts"]:
        show_table(alert_rows(data["alerts"][:5]))
    else:
        st.success("No alerts in this period.")


def page_alerts(data):
    alerts = data["alerts"]

    if not alerts:
        st.info("No alerts in this period.")
        return

    left, right = st.columns(2)
    severities = left.multiselect("Severity", ["high", "medium"], default=["high", "medium"])
    rules = right.multiselect("Rule", sorted({alert["rule"] for alert in alerts}), default=sorted({alert["rule"] for alert in alerts}))

    shown = [alert for alert in alerts if alert["severity"] in severities and alert["rule"] in rules]

    st.caption(f"{len(shown)} of {len(alerts)} alerts")
    show_table(alert_rows(shown))

    st.subheader("Evidence")

    for alert in shown[:10]:
        with st.expander(f"{SEVERITY_MARK.get(alert['severity'], alert['severity'])} - {alert['description']}"):
            st.json(alert["evidence"])

    if len(shown) > 10:
        st.caption("Evidence is shown for the first 10 alerts; the table above lists all of them.")


def page_network(data, dark):
    if data["hide_docker_desktop"]:
        st.caption("Docker Desktop internal traffic (192.168.65.0/24) is hidden. Untick the box in the sidebar to see it.")

    left, right = st.columns(2)

    with left:
        st.subheader("Top sources")
        st.caption("Who started the most connections")
        sources = data["sources"]
        show_chart(
            charts.bars_horizontal([row["src_ip"] for row in sources], [row["attempts"] for row in sources], "connection attempts", dark),
            "No connection attempts in this period.",
        )

        with st.expander("Show data"):
            show_table(
                [
                    {"Source": r["src_ip"], "Attempts": r["attempts"], "Ports tried": r["ports_tried"], "Targets": r["targets"]}
                    for r in sources
                ]
            )

    with right:
        st.subheader("Busiest ports")
        st.caption("Completed connections (a port scan does not complete them)")
        ports = data["ports"]
        show_chart(
            charts.bars_horizontal([port_label(row["dst_port"]) for row in ports], [row["connections"] for row in ports], "connections", dark),
            "No completed connections in this period.",
        )

        with st.expander("Show data"):
            show_table(
                [{"Port": port_label(r["dst_port"]), "Connections": r["connections"], "Sources": r["sources"]} for r in ports]
            )

    st.subheader("Connection attempts over time")
    show_chart(charts.time_line(data["attempts_over_time"], "attempts", "connection attempts", dark), "No connection attempts in this period.")

    with st.expander("Show data"):
        show_table([{"Time (UTC)": fmt_time(r["bucket"]), "Attempts": r["attempts"]} for r in data["attempts_over_time"]])


def page_honeypot(data, dark):
    left, right = st.columns(2)

    with left:
        st.subheader("Connections over time")
        show_chart(
            charts.time_bars(data["honeypot_over_time"], "connections", data["bucket"], "connections", dark),
            "The honeypot received no connections in this period.",
        )

    with right:
        st.subheader("Top visitors")
        visitors = data["honeypot_sources"]
        show_chart(
            charts.bars_horizontal([r["src_ip"] for r in visitors], [r["connections"] for r in visitors], "connections", dark),
            "No visitors in this period.",
        )

        with st.expander("Show data"):
            show_table([{"Source": r["src_ip"], "Connections": r["connections"], "Payloads": r["payloads"]} for r in visitors])

        st.subheader("What visitors sent")

    summary = data["payload_summary"]

    if not data["payloads"]:
        st.info("No payloads were sent in this period.")
        return

    if summary["probes"]:
        st.info(
            f"{summary['probes']} of the latest {summary['total']} messages are **protocol probes**: each one "
            "asks a service \"what are you?\" using a different protocol (Java, SQL Server, Oracle, "
            "remote desktop and others). This is what a scanner's version detection does, for example "
            "Nmap with `-sV`. They are looking around, not trying to break in."
        )

    if summary["unrecognised"]:
        st.caption(
            f"{summary['unrecognised']} messages are in a format this dashboard does not recognise yet. "
            "They are listed as \"Unrecognised data\"; the raw view below shows them in full."
        )

    show_table(
        [
            {
                "Time (UTC)": fmt_time(r["ts"]),
                "From": r["src_ip"],
                "What it looks like": r["label"],
                "Details": r["detail"],
            }
            for r in data["payloads"]
        ],
        column_config={"What it looks like": st.column_config.TextColumn(width="large")},
    )

    with st.expander("Raw view (technical)"):
        st.caption(
            "The exact text the honeypot stored. Control characters are shown as escapes: "
            "\\x00 is a zero byte, \\ufffd a byte that was not valid text. Visitors control this "
            "content, so it is shown as plain text and never interpreted."
        )
        show_table(
            [
                {"Time (UTC)": fmt_time(r["ts"]), "From": r["src_ip"], "Port": r["src_port"], "Raw": display_payload(r["data"], 500)}
                for r in data["payloads"]
            ]
        )


# ---------------------------------------------------------------- layout

with st.sidebar:
    st.title("CyberLab")
    page = st.radio("View", PAGES)
    window_label = st.selectbox("Time range", list(WINDOWS))
    hide_docker = st.checkbox("Hide Docker Desktop traffic", value=True)

    if st.button("Refresh data"):
        st.cache_data.clear()
        st.rerun()

    st.caption(f"Database: {DB_PATH.name}")

if not DB_PATH.is_file():
    st.error(f"No database found at {DB_PATH}.")
    st.markdown(
        "Create it by loading some data first:\n\n"
        "```\npython -m analyzer.cli pcap data\\pcaps\\<file>.pcap\n"
        "python -m analyzer.cli logs\npython -m analyzer.cli detect\n```"
    )
    st.stop()

data = cached_load(str(DB_PATH), db_signature(DB_PATH), WINDOWS[window_label], hide_docker)

if data["empty"]:
    st.warning("The database is empty. Load some data with the analyzer commands first (see the README).")
    st.stop()

st.caption(
    f"Showing {fmt_time(data['since'])} to {fmt_time(data['until'])} UTC "
    f"(grouped in {data['bucket']}-second buckets)"
)

dark = is_dark()

if page == "Overview":
    page_overview(data, dark)
elif page == "Alerts":
    page_alerts(data)
elif page == "Network traffic":
    page_network(data, dark)
else:
    page_honeypot(data, dark)

with st.sidebar:
    st.divider()
    report_key = (window_label, hide_docker, db_signature(DB_PATH))

    if st.button("Prepare PDF report"):
        st.session_state["report"] = (report_key, build_report(data))

    prepared = st.session_state.get("report")

    if prepared and prepared[0] == report_key:
        st.download_button(
            "Download PDF report",
            data=prepared[1],
            file_name=f"cyberlab_report_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.pdf",
            mime="application/pdf",
        )