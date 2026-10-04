import io
from datetime import datetime, timezone

from pypdf import PdfReader

from dashboard.data import load_dashboard_data
from dashboard.report import build_report, safe
from common.database import connect


def text_of(pdf_bytes):
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() for page in reader.pages)


def test_safe_removes_what_the_pdf_fonts_cannot_show():
    assert safe(None) == ""
    assert safe("line1\r\nline2\x00\x1b[31m") == "line1  line2  [31m"
    assert safe("caf\u00e9 \u4e2d\u6587 \U0001F600") == "caf\u00e9 ?? ?"
    assert safe("x" * 200, 20) == "x" * 17 + "..."


def test_report_is_a_valid_pdf_with_the_key_facts(seeded_db):
    pdf = build_report(load_dashboard_data(seeded_db), datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc))

    assert pdf.startswith(b"%PDF")

    text = text_of(pdf)
    assert "CyberLab Security Report" in text
    assert "Generated 2026-10-02 12:00:00 UTC" in text
    assert "port_scan" in text
    assert "172.18.0.5" in text
    assert "probed 200 different TCP ports" in text
    assert "SSH-2.0-OpenSSH_9.6" in text           # honeypot payload
    assert "Juice Shop" in text                    # port 3000 label
    assert "192.168.65.1" not in text.replace("192.168.65.0/24", "")  # Docker Desktop noise hidden


def test_hostile_honeypot_text_does_not_break_the_report(seeded_db):
    hostile = "A" * 5000 + "\x00\x1b[2J" + "\u202e\U0001F4A5" * 50 + "<script>alert(1)</script>"
    connection = connect(seeded_db)
    with connection:
        connection.execute(
            "INSERT INTO honeypot_events (ts, event, src_ip, src_port, data) VALUES (9e9, 'data', '6.6.6.6', 1, ?)",
            (hostile,),
        )
    connection.close()

    pdf = build_report(load_dashboard_data(seeded_db))

    assert pdf.startswith(b"%PDF")
    assert "6.6.6.6" in text_of(pdf)


def test_report_for_an_empty_database(tmp_path):
    connect(tmp_path / "empty.db").close()

    pdf = build_report(load_dashboard_data(tmp_path / "empty.db"))

    assert "No data" in text_of(pdf)


def test_report_with_many_alerts_spills_onto_more_pages(seeded_db):
    data = load_dashboard_data(seeded_db)
    data["alerts"] = data["alerts"] * 40  # 25 shown, long table

    reader = PdfReader(io.BytesIO(build_report(data)))

    assert len(reader.pages) >= 2