import re
from dataclasses import dataclass

HTTP_METHODS = "GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE"
HTTP_REQUEST_LINE = re.compile(rf"^(?:{HTTP_METHODS}) .+ HTTP/\d(?:\.\d)?$")


@dataclass(frozen=True)
class Description:
    label: str                     # plain English: "Java debugger handshake (JDWP)"
    detail: str = ""               # a readable extra, e.g. the request line of a web request
    service_probe: bool = False    # "what service are you?" - the kind of message scanners send
    known: bool = True             # False when we could not recognise it


# Binary protocols, recognised by the bytes they start with (or a marker inside).
# Each entry: (label, what it is looking for, test on the decoded text). The honeypot stores
# payloads as text, so bytes that were not valid text arrive as "\ufffd"; every test tolerates that.
BINARY_SIGNATURES = (
    (
        "Java debugger handshake (JDWP)",
        "Checks whether a Java program is open to remote debugging",
        lambda t: t.startswith("JDWP-Handshake"),
    ),
    (
        "Java RMI call",
        "Checks for a Java remote-method service",
        lambda t: t.startswith("JRMI"),
    ),
    (
        "CORBA request (GIOP)",
        "Checks for a CORBA object service (older enterprise software)",
        lambda t: t.startswith("GIOP"),
    ),
    (
        "Microsoft SQL Server pre-login (TDS)",
        "Checks for a Microsoft SQL Server database",
        lambda t: t.startswith("\x12\x01") or "MSSQLServer" in t,
    ),
    (
        "Oracle database listener request (TNS)",
        "Checks for an Oracle database",
        lambda t: "(CONNECT_DATA=" in t
        or (len(t) > 12 and t[0] == "\x00" and t[2:5] == "\x00\x00\x01" and t[8] == "\x01"),
    ),
    (
        "Windows Media streaming request (MMS)",
        "Checks for a Windows Media streaming server",
        lambda t: "MMS" in t[:32] and "\x00\x00\x00MMS" in t,
    ),
    (
        "Remote Desktop (RDP) connection request",
        "Checks for a Windows Remote Desktop service",
        lambda t: t.startswith("\x03\x00\x00") and len(t) < 64,
    ),
    (
        "LDAP directory request",
        "Checks for a directory service such as Active Directory",
        lambda t: t[:1] == "0" and "\x02\x01" in t[1:10],
    ),
    (
        "DNS 'version.bind' query",
        "Asks a DNS server which software it runs",
        lambda t: "version\x04bind" in t,
    ),
    (
        "TLS/HTTPS handshake attempt",
        "Starts an encrypted (HTTPS) connection",
        lambda t: t[:2] == "\x16\x03",
    ),
)


def _first_line(text, limit=80):
    line = text.split("\n", 1)[0].rstrip("\r")
    return line if len(line) <= limit else line[: limit - 3] + "..."


def _mostly_text(text):
    if not text:
        return False

    readable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return readable / len(text) >= 0.9


def describe_payload(text):
    # Turn the raw text a visitor sent into something a person can understand.
    text = "" if text is None else str(text)

    if not text:
        return Description("Empty message")

    # Text protocols first.
    if text.startswith(("OPTIONS sip:", "INVITE sip:", "REGISTER sip:")):
        # "sip:nm" and "tag=root" are the fixed values Nmap's SIP probe uses.
        probe = text.startswith("OPTIONS sip:nm ") or "tag=root" in text
        detail = "Asks a phone service what it supports (typical of Nmap)" if probe else _first_line(text)
        return Description("SIP (internet phone) request", detail, service_probe=probe)

    if text.startswith("SSH-"):
        return Description("SSH client greeting", _first_line(text))

    if HTTP_REQUEST_LINE.match(text.split("\n", 1)[0].rstrip("\r")):
        return Description("Web (HTTP) request", _first_line(text))

    # Binary protocols: these are all "what service are you?" probes.
    for label, purpose, matches in BINARY_SIGNATURES:
        if matches(text):
            return Description(label, purpose, service_probe=True)

    if _mostly_text(text):
        return Description("Plain text message", _first_line(text))

    return Description("Unrecognised data", f"Not a protocol this tool knows ({len(text)} characters)", known=False)