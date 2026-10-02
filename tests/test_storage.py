from scanner.models import Host, Port
from scanner.storage import load_scan_results, save_scan_results

HOSTS = [
    Host(
        ip="10.0.0.5",
        hostname=None,
        ports=[Port(number=22, protocol="tcp", state="open", service="ssh")],
    )
]


def test_save_then_load_returns_same_data(tmp_path):
    path = save_scan_results(HOSTS, tmp_path)

    timestamp, loaded = load_scan_results(path)

    assert loaded == HOSTS
    assert timestamp  # an ISO timestamp string


def test_two_saves_do_not_overwrite_each_other(tmp_path):
    first = save_scan_results(HOSTS, tmp_path)
    second = save_scan_results(HOSTS, tmp_path)

    assert first != second
    assert len(list(tmp_path.glob("scan_*.json"))) == 2


def test_output_directory_is_created(tmp_path):
    folder = tmp_path / "does" / "not" / "exist"

    path = save_scan_results(HOSTS, folder)

    assert path.exists()