from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from common.database import connect

APP = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")
PAGES = ("Overview", "Alerts", "Network traffic", "Honeypot activity")


@pytest.fixture(autouse=True)
def clear_cache():
    import streamlit as st

    st.cache_data.clear()


def open_app(db_path, monkeypatch):
    monkeypatch.setenv("CYBERLAB_DB", str(db_path))
    return AppTest.from_file(APP, default_timeout=30).run()


@pytest.mark.parametrize("page", PAGES)
def test_every_page_renders_without_errors(seeded_db, monkeypatch, page):
    at = open_app(seeded_db, monkeypatch)
    at.sidebar.radio[0].set_value(page).run()

    assert not at.exception
    assert not at.error


def test_overview_shows_the_counts(seeded_db, monkeypatch):
    at = open_app(seeded_db, monkeypatch)

    labels = [metric.label for metric in at.metric]
    assert labels == ["Network flows", "Honeypot events", "Alerts", "High severity"]
    assert int(at.metric[3].value) >= 1


def test_time_range_and_docker_filter_can_be_changed(seeded_db, monkeypatch):
    at = open_app(seeded_db, monkeypatch)
    before = at.metric[0].value

    at.sidebar.checkbox[0].set_value(False).run()
    assert not at.exception
    assert at.metric[0].value != before            # Docker Desktop flows are now counted

    at.sidebar.selectbox[0].set_value("Latest 1 hour").run()
    assert not at.exception


def test_alerts_page_filters(seeded_db, monkeypatch):
    at = open_app(seeded_db, monkeypatch)
    at.sidebar.radio[0].set_value("Alerts").run()

    at.multiselect[0].set_value(["high"]).run()

    assert not at.exception
    assert any("alerts" in caption.value for caption in at.caption)


def test_missing_database_shows_help_instead_of_crashing(tmp_path, monkeypatch):
    at = open_app(tmp_path / "nope.db", monkeypatch)

    assert not at.exception
    assert any("No database found" in error.value for error in at.error)


def test_empty_database_shows_a_warning(tmp_path, monkeypatch):
    connect(tmp_path / "empty.db").close()

    at = open_app(tmp_path / "empty.db", monkeypatch)

    assert not at.exception
    assert any("empty" in warning.value for warning in at.warning)


def test_pdf_report_can_be_prepared(seeded_db, monkeypatch):
    at = open_app(seeded_db, monkeypatch)

    [prepare] = [button for button in at.sidebar.button if button.label == "Prepare PDF report"]
    prepare.click().run()

    assert not at.exception
    assert "report" in at.session_state
    assert at.session_state["report"][1].startswith(b"%PDF")