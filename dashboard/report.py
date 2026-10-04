from datetime import datetime, timezone

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from .data import display_payload, port_label

BLUE = (42, 120, 214)   # chart series colour
INK = (30, 30, 30)
MUTED = (110, 110, 105)


def safe(value, limit=None):
    # The built-in PDF fonts only know Latin-1, and attackers control the honeypot text:
    # drop control characters, replace anything else unknown, and cut long strings.
    text = "" if value is None else str(value)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = text.encode("latin-1", "replace").decode("latin-1")

    if limit and len(text) > limit:
        text = text[: limit - 3] + "..."

    return text


def fmt_time(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Report(FPDF):
    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", size=8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, f"CyberLab report - page {self.page_no()}", align="C")


def _heading(pdf, text):
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _note(pdf, text):
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(0, 5, safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _bar_chart(pdf, title, items):
    # items: [(label, value), ...]. Bars are drawn directly (no image libraries needed).
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, safe(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if not items:
        _note(pdf, "No data in this period.")
        return

    if pdf.will_page_break(6 * len(items) + 4):
        pdf.add_page()

    label_width, max_bar = 58, 95
    biggest = max(value for _, value in items) or 1

    for label, value in items:
        y = pdf.get_y()
        pdf.set_font("Helvetica", size=8)
        pdf.set_text_color(*INK)
        pdf.cell(label_width, 5, safe(label, 36))

        x = pdf.get_x()
        width = max(0.6, max_bar * value / biggest)
        pdf.set_fill_color(*BLUE)
        pdf.rect(x, y + 0.9, width, 3.2, style="F")

        pdf.set_xy(x + width + 2, y)
        pdf.cell(25, 5, f"{value:,}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    pdf.set_fill_color(255, 255, 255)  # otherwise the bar colour leaks into later table cells


def _table(pdf, headers, rows, widths):
    pdf.set_font("Helvetica", size=8)
    pdf.set_text_color(*INK)
    pdf.set_fill_color(255, 255, 255)

    with pdf.table(col_widths=widths, text_align="LEFT", line_height=4.5) as table:
        header = table.row()

        for title in headers:
            header.cell(safe(title))

        for values in rows:
            row = table.row()

            for value in values:
                row.cell(safe(value))


def build_report(data, generated_at=None):
    generated_at = generated_at or datetime.now(timezone.utc)

    pdf = Report()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ----- title -----
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*INK)
    pdf.cell(0, 12, "CyberLab Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 5, f"Generated {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if data["empty"]:
        _heading(pdf, "No data")
        _note(pdf, "The database has no flows, honeypot events or alerts yet.")
        return bytes(pdf.output())

    pdf.cell(0, 5, f"Period: {fmt_time(data['since'])} to {fmt_time(data['until'])} UTC", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ----- summary -----
    counts = data["overview"]
    medium = counts["alerts"] - counts["high_alerts"]

    _heading(pdf, "Summary")
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(*INK)
    pdf.multi_cell(
        0, 6,
        safe(
            f"{counts['flows']:,} network flows and {counts['honeypot_events']:,} honeypot events were "
            f"analysed. The detector raised {counts['alerts']} alerts: {counts['high_alerts']} high "
            f"and {medium} medium severity."
        ),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )

    if data["hide_docker_desktop"]:
        _note(pdf, "Docker Desktop internal traffic (192.168.65.0/24) is excluded from the network figures.")

    # ----- alerts -----
    _heading(pdf, "Alerts")

    if data["alerts"]:
        shown = data["alerts"][:25]
        _table(
            pdf,
            ("Severity", "Time (UTC)", "Rule", "Source", "Description"),
            [
                (alert["severity"].upper(), fmt_time(alert["ts"]), alert["rule"], alert["src_ip"], alert["description"])
                for alert in shown
            ],
            widths=(18, 33, 27, 27, 85),
        )

        if len(data["alerts"]) > len(shown):
            _note(pdf, f"Showing {len(shown)} of {len(data['alerts'])} alerts (high severity first).")
    else:
        _note(pdf, "No alerts in this period.")

    # ----- network -----
    _heading(pdf, "Network traffic")
    _bar_chart(
        pdf,
        "Top sources by connection attempts",
        [(row["src_ip"], row["attempts"]) for row in data["sources"]],
    )
    pdf.ln(2)
    _bar_chart(
        pdf,
        "Busiest TCP ports (completed connections)",
        [(port_label(row["dst_port"]), row["connections"]) for row in data["ports"]],
    )

    # ----- honeypot -----
    _heading(pdf, "Honeypot")
    _bar_chart(
        pdf,
        "Connections by source",
        [(row["src_ip"], row["connections"]) for row in data["honeypot_sources"]],
    )

    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*INK)
    pdf.cell(0, 7, "What visitors sent", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    summary = data["payload_summary"]

    if data["payloads"]:
        if summary["probes"]:
            _note(
                pdf,
                f"{summary['probes']} of the latest {summary['total']} messages are protocol probes: each one "
                "asks a service 'what are you?' using a different protocol. This is what a scanner's version "
                "detection does (for example Nmap -sV). They are looking around, not trying to break in.",
            )

        if summary["unrecognised"]:
            _note(pdf, f"{summary['unrecognised']} messages are in a format this report does not recognise yet.")

        pdf.ln(1)
        _table(
            pdf,
            ("Time (UTC)", "From", "What it looks like", "Details"),
            [
                (fmt_time(row["ts"]), row["src_ip"], row["label"], safe(row["detail"], 62))
                for row in data["payloads"][:15]
            ],
            widths=(33, 27, 62, 68),
        )

        if len(data["payloads"]) > 15:
            _note(pdf, f"Showing the latest 15 of {len(data['payloads'])} messages.")
    else:
        _note(pdf, "No payloads were sent to the honeypot in this period.")
    return bytes(pdf.output())
