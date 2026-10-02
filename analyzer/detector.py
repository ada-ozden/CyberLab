import ipaddress
from itertools import groupby

from .models import Alert

# Docker Desktop's own traffic between its Linux VM and Windows. It is not lab traffic.
DEFAULT_IGNORED_NETWORKS = ("192.168.65.0/24",)


def parse_networks(networks):
    return [ipaddress.ip_network(network) for network in networks]


def is_ignored(ip, networks):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(address in network for network in networks)


def strongest_window(points, window_seconds):
    # points: [(time, key), ...] sorted by time.
    # Slides a window of `window_seconds` over the points and finds the position
    # that contains the most DIFFERENT keys. Returns (count, start, end).
    # Each point is added once and removed once, so this is fast even for huge lists.
    best_count, best_start, best_end = 0, 0.0, 0.0
    counts = {}
    left = 0

    for time, key in points:
        counts[key] = counts.get(key, 0) + 1

        while time - points[left][0] > window_seconds:
            old_key = points[left][1]
            counts[old_key] -= 1

            if counts[old_key] == 0:
                del counts[old_key]

            left += 1

        if len(counts) > best_count:
            best_count, best_start, best_end = len(counts), points[left][0], time

    return best_count, best_start, best_end


def detect_port_scans(connection, min_ports=10, window_seconds=60, ignored=()):
    # One source IP starting connections to many DIFFERENT ports of one target, quickly.
    # syn_count > 0 keeps only connection ATTEMPTS, so server replies never count.
    rows = connection.execute(
        """
        SELECT src_ip, dst_ip, first_seen, dst_port
        FROM flows
        WHERE syn_count > 0 AND protocol = 'tcp'
        ORDER BY src_ip, dst_ip, first_seen
        """
    )

    alerts = []

    for (src_ip, dst_ip), group in groupby(rows, key=lambda row: (row["src_ip"], row["dst_ip"])):
        if is_ignored(src_ip, ignored):
            continue

        points = [(row["first_seen"], row["dst_port"]) for row in group]
        count, start, end = strongest_window(points, window_seconds)

        if count < min_ports:
            continue

        ports = sorted({port for time, port in points if start <= time <= end})

        alerts.append(
            Alert(
                ts=start,
                rule="port_scan",
                severity="high" if count >= min_ports * 10 else "medium",
                src_ip=src_ip,
                description=(
                    f"{src_ip} probed {count} different TCP ports on {dst_ip} "
                    f"within {end - start:.1f}s"
                ),
                evidence={
                    "dst_ip": dst_ip,
                    "distinct_ports": count,
                    "window_start": start,
                    "window_end": end,
                    "sample_ports": ports[:20],
                },
            )
        )

    return alerts


def detect_honeypot_bursts(connection, min_connections=10, window_seconds=60, ignored=()):
    # One source IP opening many connections to the honeypot in a short time.
    rows = connection.execute(
        """
        SELECT src_ip, ts, id
        FROM honeypot_events
        WHERE event = 'connection'
        ORDER BY src_ip, ts
        """
    )

    alerts = []

    for src_ip, group in groupby(rows, key=lambda row: row["src_ip"]):
        if is_ignored(src_ip, ignored):
            continue

        # The event id is unique, so "distinct keys" here simply means "number of connections".
        points = [(row["ts"], row["id"]) for row in group]
        count, start, end = strongest_window(points, window_seconds)

        if count < min_connections:
            continue

        alerts.append(
            Alert(
                ts=start,
                rule="honeypot_burst",
                severity="high" if count >= min_connections * 5 else "medium",
                src_ip=src_ip,
                description=(
                    f"{src_ip} opened {count} connections to the honeypot "
                    f"within {end - start:.1f}s"
                ),
                evidence={
                    "connections": count,
                    "window_start": start,
                    "window_end": end,
                },
            )
        )

    return alerts


def run_detectors(
    connection,
    min_ports=10,
    min_connections=10,
    window_seconds=60,
    ignored_networks=DEFAULT_IGNORED_NETWORKS,
):
    ignored = parse_networks(ignored_networks)

    alerts = detect_port_scans(connection, min_ports, window_seconds, ignored)
    alerts += detect_honeypot_bursts(connection, min_connections, window_seconds, ignored)

    return sorted(alerts, key=lambda alert: alert.ts)