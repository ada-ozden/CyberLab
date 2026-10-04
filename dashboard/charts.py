from datetime import datetime, timedelta, timezone

import plotly.graph_objects as go

# Chart colours. One series = one colour (slot 1 blue). Severity uses the fixed status
# colours: medium = warning (amber), high = critical (red). Colour is never the only
# cue: every chart has a legend or value labels, hover text and a "Show data" table.
LIGHT = {"surface": "#ffffff", "series": "#2a78d6", "grid": "rgba(128,128,128,0.18)"}
DARK = {"surface": "#0e1117", "series": "#3987e5", "grid": "rgba(128,128,128,0.28)"}
SEVERITY_COLORS = {"high": "#d03b3b", "medium": "#fab219"}


def utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None)


def _style(fig, dark, x_title=None, y_title=None, legend=False, height=300):
    theme = DARK if dark else LIGHT

    fig.update_layout(
        height=height,
        margin=dict(l=8, r=16, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        bargap=0.35,
        hoverlabel=dict(font_size=13),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=theme["grid"], title=x_title)
    fig.update_yaxes(gridcolor=theme["grid"], gridwidth=1, zeroline=False, title=y_title)

    try:
        fig.update_layout(barcornerradius=4)  # rounded data ends (newer Plotly only)
    except ValueError:
        pass

    return fig


def alerts_over_time(rows, bucket, dark=False):
    # Stacked bars: alerts per time bucket, split by severity.
    if not rows:
        return None

    theme = DARK if dark else LIGHT
    fig = go.Figure()

    for severity in ("high", "medium"):
        points = [row for row in rows if row["severity"] == severity]

        if not points:
            continue

        fig.add_bar(
            x=[utc(row["bucket"]) for row in points],
            y=[row["count"] for row in points],
            name=severity.upper(),
            width=[bucket * 700] * len(points),  # milliseconds on a time axis
            marker=dict(color=SEVERITY_COLORS[severity], line=dict(color=theme["surface"], width=2)),
            hovertemplate="%{x|%Y-%m-%d %H:%M:%S} UTC<br>%{y} alerts<extra>" + severity.upper() + "</extra>",
        )

    fig.update_layout(barmode="stack")
    return _style(fig, dark, x_title="Time (UTC)", y_title="Alerts", legend=True)


def time_bars(rows, value_key, bucket, name, dark=False):
    # Single-series bars over time (honeypot connections).
    if not rows:
        return None

    fig = go.Figure(
        go.Bar(
            x=[utc(row["bucket"]) for row in rows],
            y=[row[value_key] for row in rows],
            width=[bucket * 700] * len(rows),
            marker_color=(DARK if dark else LIGHT)["series"],
            hovertemplate="%{x|%Y-%m-%d %H:%M:%S} UTC<br>%{y:,} " + name + "<extra></extra>",
        )
    )

    return _style(fig, dark, x_title="Time (UTC)", y_title=name.capitalize())


def fill_gaps(rows, value_key, bucket, limit=2000):
    # Time buckets with no events are missing from the data. A line drawn straight across such a
    # gap would look like a slow climb, so add the empty buckets back as zeros.
    by_bucket = {row["bucket"]: row[value_key] for row in rows}
    first, last = min(by_bucket), max(by_bucket)

    if (last - first) / bucket > limit:
        return rows  # absurdly many buckets: leave the data as it is

    filled = []
    moment = first

    while moment <= last:
        filled.append({"bucket": moment, value_key: by_bucket.get(moment, 0)})
        moment += bucket

    return filled


def time_line(rows, value_key, name, dark=False, bucket=None):
    # Single-series line over time (connection attempts).
    if not rows:
        return None

    if bucket:
        rows = fill_gaps(rows, value_key, bucket)

    colour = (DARK if dark else LIGHT)["series"]

    fig = go.Figure(
        go.Scatter(
            x=[utc(row["bucket"]) for row in rows],
            y=[row[value_key] for row in rows],
            mode="lines+markers" if len(rows) <= 40 else "lines",
            line=dict(color=colour, width=2),
            marker=dict(size=8, color=colour),
            hovertemplate="%{x|%Y-%m-%d %H:%M:%S} UTC<br>%{y:,} " + name + "<extra></extra>",
        )
    )

    fig.update_layout(hovermode="x unified")
    _style(fig, dark, x_title="Time (UTC)", y_title=name.capitalize())

    # Counts start at zero, so a line never exaggerates a small change.
    fig.update_yaxes(rangemode="tozero")

    # One lonely point would zoom the time axis into milliseconds: show a sensible span instead.
    if len(rows) == 1 and bucket:
        centre = utc(rows[0]["bucket"])
        padding = timedelta(seconds=bucket)
        fig.update_xaxes(range=[centre - padding, centre + padding])

    return fig


def bars_horizontal(labels, values, name, dark=False):
    # Ranked categories, biggest at the top. Nominal categories = ONE colour, with value labels.
    if not labels:
        return None

    fig = go.Figure(
        go.Bar(
            x=values,
            y=labels,
            orientation="h",
            marker_color=(DARK if dark else LIGHT)["series"],
            text=[f"{value:,}" for value in values],
            textposition="outside",
            cliponaxis=False,
            hovertemplate="%{y}<br>%{x:,} " + name + "<extra></extra>",
        )
    )

    fig.update_yaxes(autorange="reversed", type="category", gridcolor="rgba(0,0,0,0)")
    fig.update_xaxes(gridcolor=(DARK if dark else LIGHT)["grid"])

    _style(fig, dark, x_title=name.capitalize(), height=max(180, 36 * len(labels) + 60))
    fig.update_yaxes(showgrid=False)
    fig.update_xaxes(showgrid=True)
    return fig