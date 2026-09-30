import xml.etree.ElementTree as ET

from .models import Host, Port


def parse_nmap_xml(xml_output: str) -> list[Host]:
    root = ET.fromstring(xml_output)
    hosts = []

    for host_element in root.findall("host"):
        status = host_element.find("status")

        if status is not None and status.get("state") != "up":
            continue

        address = host_element.find("address")

        if address is None:
            continue

        ip = address.get("addr")

        if not ip:
            continue

        hostname_element = host_element.find("./hostnames/hostname")
        hostname = (
            hostname_element.get("name")
            if hostname_element is not None
            else None
        )

        ports = []

        for port_element in host_element.findall("./ports/port"):
            port_number = port_element.get("portid")
            protocol = port_element.get("protocol")

            if not port_number or not protocol:
                continue

            state_element = port_element.find("state")
            state = (
                state_element.get("state", "unknown")
                if state_element is not None
                else "unknown"
            )

            service_element = port_element.find("service")

            service = None
            product = None
            version = None

            if service_element is not None:
                service = service_element.get("name")
                product = service_element.get("product")
                version = service_element.get("version")

            ports.append(
                Port(
                    number=int(port_number),
                    protocol=protocol,
                    state=state,
                    service=service,
                    product=product,
                    version=version,
                )
            )

        hosts.append(
            Host(
                ip=ip,
                hostname=hostname,
                ports=ports,
            )
        )

    return hosts