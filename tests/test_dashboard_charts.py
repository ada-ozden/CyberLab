from datetime import datetime, timedelta, timezone

import pytest

from dashboard import charts

BUCKET = 3600
NOON = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc).timestamp()


def rows(*values, key="attempts"):
    return [{"bucket": NOON + i * BUCKET, key: value} for i, value in enumerate(values)]


@pytest.mark.parametrize("dark", [False, True])
def test_every_chart_builds_in_light_and_dark(dark):
    assert charts.alerts_over_time(
        [{"bucket": NOON, "severity": "high", "count": 2}, {"bucket": NOON, "severity": "medium", "count": 1}],
        BUCKET, dark,
    ) is not None
    assert charts.time_bars(rows(3, 5, key="connections"), "connections", BUCKET, "connections", dark) is not None
    assert charts.time_line(rows(3, 5, 4), "attempts", "attempts", dark, BUCKET) is not None
    assert charts.bars_horizontal(["a", "b"], [5, 3], "connections", dark) is not None


def test_charts_without_data_return_none_so_the_page_can_say_so():
    assert charts.alerts_over_time([], BUCKET) is None
    assert charts.time_bars([], "connections", BUCKET, "connections") is None
    assert charts.time_line([], "attempts", "attempts") is None
    assert charts.bars_horizontal([], [], "connections") is None


def test_a_line_chart_always_starts_at_zero():
    figure = charts.time_line(rows(1000, 1001), "attempts", "attempts", False, BUCKET)

    assert figure.layout.yaxis.rangemode == "tozero"


def test_a_single_point_gets_a_sensible_time_span_not_milliseconds():
    figure = charts.time_line(rows(1000), "attempts", "attempts", False, BUCKET)

    start, end = figure.layout.xaxis.range
    assert end - start == timedelta(seconds=2 * BUCKET)


def test_several_points_keep_the_automatic_time_axis():
    figure = charts.time_line(rows(1, 2, 3), "attempts", "attempts", False, BUCKET)

    assert figure.layout.xaxis.range is None


def test_severities_use_fixed_colours_and_are_labelled():
    figure = charts.alerts_over_time(
        [{"bucket": NOON, "severity": "high", "count": 2}, {"bucket": NOON, "severity": "medium", "count": 1}],
        BUCKET,
    )

    colours = {trace.name: trace.marker.color for trace in figure.data}
    assert colours == {"HIGH": charts.SEVERITY_COLORS["high"], "MEDIUM": charts.SEVERITY_COLORS["medium"]}
    assert figure.layout.showlegend is True


def test_ranked_bars_show_their_values_and_put_the_biggest_first():
    figure = charts.bars_horizontal(["a", "b"], [1500, 3], "connections")

    assert list(figure.data[0].text) == ["1,500", "3"]
    assert figure.layout.yaxis.autorange == "reversed"


def test_quiet_periods_drop_to_zero_instead_of_being_joined_by_a_slope():
    sparse = [{"bucket": NOON, "attempts": 30}, {"bucket": NOON + 4 * BUCKET, "attempts": 1000}]

    figure = charts.time_line(sparse, "attempts", "attempts", False, BUCKET)

    assert list(figure.data[0].y) == [30, 0, 0, 0, 1000]
    assert len(figure.data[0].x) == 5


def test_fill_gaps_leaves_complete_or_unbucketed_data_alone():
    complete = rows(1, 2, 3)

    assert charts.fill_gaps(complete, "attempts", BUCKET) == complete
    assert charts.fill_gaps(complete[:1], "attempts", BUCKET) == complete[:1]
    assert len(charts.time_line(complete, "attempts", "attempts").data[0].y) == 3   # no bucket given: untouched


def test_fill_gaps_gives_up_on_absurd_ranges():
    far_apart = [{"bucket": 0, "attempts": 1}, {"bucket": 10 ** 9, "attempts": 1}]

    assert charts.fill_gaps(far_apart, "attempts", 1) == far_apart