import json

# Buckets (in seconds) used to group events over time.
BUCKETS = (1, 5, 10, 30, 60, 300, 900, 3600, 21600, 86400)


def pick_bucket(span_seconds, target_bars=120):
    # The smallest bucket that keeps a chart at or under ~120 bars.
    for bucket in BUCKETS:
        if span_seconds / bucket <= target_bars:
            return bucket

    return BUCKETS[-1]


def _ts_where(column, since, until):
    clauses, params = [], []

    if since is not None:
        clauses.append(f"{column} >= ?")
        params.append(since)

    if until is not None:
        clauses.append(f"{column} <= ?")
        params.append(until)

    return clauses, params


def _where(clauses):
    return ("WHERE " + " AND ".join(clauses)) if clauses else ""


def _flow_where(since, until, hide_prefixes, extra=()):
    clauses, params = _ts_where("first_seen", since, until)
    clauses = list(extra) + clauses

    for prefix in hide_prefixes:
        clauses += ["src_ip NOT LIKE ?", "dst_ip NOT LIKE ?"]
        params += [prefix + "%", prefix + "%"]

    return _where(clauses), params


def time_bounds(conn):
    # (earliest, latest) timestamp across all tables, or None if the database is empty.
    lows, highs = [], []

    for query in (
        "SELECT MIN(first_seen), MAX(last_seen) FROM flows",
        "SELECT MIN(ts), MAX(ts) FROM honeypot_events",
        "SELECT MIN(ts), MAX(ts) FROM alerts",
    ):
        low, high = conn.execute(query).fetchone()

        if low is not None:
            lows.append(low)
            highs.append(high)

    return (min(lows), max(highs)) if lows else None


def overview(conn, since, until, hide):
    flow_where, flow_params = _flow_where(since, until, hide)
    hp_clauses, hp_params = _ts_where("ts", since, until)
    alert_clauses, alert_params = _ts_where("ts", since, until)

    return {
        "flows": conn.execute(f"SELECT COUNT(*) FROM flows {flow_where}", flow_params).fetchone()[0],
        "honeypot_events": conn.execute(
            f"SELECT COUNT(*) FROM honeypot_events {_where(hp_clauses)}", hp_params
        ).fetchone()[0],
        "alerts": conn.execute(
            f"SELECT COUNT(*) FROM alerts {_where(alert_clauses)}", alert_params
        ).fetchone()[0],
        "high_alerts": conn.execute(
            f"SELECT COUNT(*) FROM alerts {_where(alert_clauses + ['severity = ?'])}",
            alert_params + ["high"],
        ).fetchone()[0],
    }


def alerts_over_time(conn, since, until, bucket):
    clauses, params = _ts_where("ts", since, until)

    rows = conn.execute(
        f"""
        SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, severity, COUNT(*) AS count
        FROM alerts {_where(clauses)}
        GROUP BY bucket, severity
        ORDER BY bucket
        """,
        [bucket, bucket] + params,
    )

    return [dict(row) for row in rows]


def list_alerts(conn, since, until, limit=500):
    clauses, params = _ts_where("ts", since, until)

    rows = conn.execute(
        f"""
        SELECT ts, rule, severity, src_ip, description, evidence
        FROM alerts {_where(clauses)}
        ORDER BY CASE severity WHEN 'high' THEN 0 ELSE 1 END, ts DESC
        LIMIT ?
        """,
        params + [limit],
    )

    alerts = []

    for row in rows:
        alert = dict(row)

        try:
            alert["evidence"] = json.loads(alert["evidence"])
        except (TypeError, ValueError):
            alert["evidence"] = {}

        alerts.append(alert)

    return alerts


def top_sources(conn, since, until, hide, limit=10):
    # Who STARTED the most connections (syn_count > 0 = connection attempts, not replies).
    where, params = _flow_where(since, until, hide, extra=["syn_count > 0"])

    rows = conn.execute(
        f"""
        SELECT src_ip,
               SUM(syn_count)           AS attempts,
               COUNT(DISTINCT dst_port) AS ports_tried,
               COUNT(DISTINCT dst_ip)   AS targets
        FROM flows {where}
        GROUP BY src_ip
        ORDER BY attempts DESC
        LIMIT ?
        """,
        params + [limit],
    )

    return [dict(row) for row in rows]


def top_ports(conn, since, until, hide, limit=10):
    # Ports with the most COMPLETED connections: the client sent a SYN and later an ACK.
    # A SYN scan never completes the handshake, so scanned ports do not pollute this list.
    where, params = _flow_where(
        since, until, hide, extra=["syn_count > 0", "protocol = 'tcp'", "tcp_flags LIKE '%A%'"]
    )

    rows = conn.execute(
        f"""
        SELECT dst_port,
               COUNT(*)               AS connections,
               COUNT(DISTINCT src_ip) AS sources
        FROM flows {where}
        GROUP BY dst_port
        ORDER BY connections DESC, dst_port
        LIMIT ?
        """,
        params + [limit],
    )

    return [dict(row) for row in rows]


def attempts_over_time(conn, since, until, hide, bucket):
    where, params = _flow_where(since, until, hide, extra=["syn_count > 0"])

    rows = conn.execute(
        f"""
        SELECT CAST(first_seen / ? AS INTEGER) * ? AS bucket, SUM(syn_count) AS attempts
        FROM flows {where}
        GROUP BY bucket
        ORDER BY bucket
        """,
        [bucket, bucket] + params,
    )

    return [dict(row) for row in rows]


def honeypot_over_time(conn, since, until, bucket):
    clauses, params = _ts_where("ts", since, until)

    rows = conn.execute(
        f"""
        SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, COUNT(*) AS connections
        FROM honeypot_events {_where(['event = ' + "'connection'"] + clauses)}
        GROUP BY bucket
        ORDER BY bucket
        """,
        [bucket, bucket] + params,
    )

    return [dict(row) for row in rows]


def honeypot_sources(conn, since, until, limit=10):
    clauses, params = _ts_where("ts", since, until)

    rows = conn.execute(
        f"""
        SELECT src_ip,
               SUM(event = 'connection') AS connections,
               SUM(event = 'data')       AS payloads
        FROM honeypot_events {_where(clauses)}
        GROUP BY src_ip
        ORDER BY connections DESC
        LIMIT ?
        """,
        params + [limit],
    )

    return [dict(row) for row in rows]


def honeypot_payloads(conn, since, until, limit=50):
    clauses, params = _ts_where("ts", since, until)

    rows = conn.execute(
        f"""
        SELECT ts, src_ip, src_port, data
        FROM honeypot_events {_where(['event = ' + "'data'"] + clauses)}
        ORDER BY ts DESC
        LIMIT ?
        """,
        params + [limit],
    )

    return [dict(row) for row in rows]