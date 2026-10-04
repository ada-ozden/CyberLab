import pytest

from common.payloads import describe_payload

# The payloads below are the ones the lab's honeypot really received from an Nmap
# service-detection scan (-sV). "\ufffd" is a byte that was not valid text.
NMAP_SCAN_PAYLOADS = [
    ("JDWP-Handshake\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x01", "Java debugger handshake (JDWP)"),
    ("GIOP\x01\x00\x01\x00$\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06", "CORBA request (GIOP)"),
    ("\x12\x01\x004\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00", "Microsoft SQL Server pre-login (TDS)"),
    ("\x00Z\x00\x00\x01\x00\x00\x00\x016\x01,\x00\x00\x08\x00\x7f\ufffd\x7f\x08\x00\x00\x00", "Oracle database listener request (TNS)"),
    ("\x00Z\x00\x00\x01\x00\x00\x00\x016\x01,\x00\x00\x08\x00(CONNECT_DATA=(COMMAND=version))", "Oracle database listener request (TNS)"),
    ("\x01\x00\x00\ufffd\ufffd\ufffd\x0b\ufffd\ufffd\x00\x00\x00MMS\x14\x00\x00\x00\x00\x00", "Windows Media streaming request (MMS)"),
    ("JRMI\x00\x02K", "Java RMI call"),
    ("\x03\x00\x00\x0b\x06\ufffd\x00\x00\x00\x00\x00", "Remote Desktop (RDP) connection request"),
    ("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\nFrom: <sip:nm@nm>;tag=root\r\n", "SIP (internet phone) request"),
    ("0\x0c\x02\x01\x01`\x07\x02\x01\x02\x04\x00\ufffd\x00", "LDAP directory request"),
    ("0\ufffd\x00\x00\x00-\x02\x01\x07c\ufffd\x00\x00\x00$\x04\x00\n\x01\x00\n\x01\x00\x02", "LDAP directory request"),
]

# Probes this recogniser does not know (yet): they must be reported honestly, not guessed.
UNKNOWN_PROBES = [
    "\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x0f\x00",
    ":\x00\x00\x00/\x00\x00\x00\x02\x00\x00@\x02\x0f\x00\x01\x00=\x05",
    "DmdT\x00\x00\x00\x17\x00\x00\x00\x01\x00\x00\x00\x00\x11\x11\x00\ufffd\x01\ufffd\x13",
    "TNMP\x04\x00\x00\x00TNME\x00\x00\x04\x00",
    "\x01default\n",
]


@pytest.mark.parametrize("payload, label", NMAP_SCAN_PAYLOADS)
def test_known_probes_get_a_plain_english_name(payload, label):
    description = describe_payload(payload)

    assert description.label == label
    assert description.service_probe is True
    assert description.known is True
    assert description.detail.startswith(("Checks", "Asks", "Starts"))   # says what it was looking for


@pytest.mark.parametrize("payload", UNKNOWN_PROBES)
def test_unknown_data_is_reported_as_unrecognised(payload):
    description = describe_payload(payload)

    assert description.label == "Unrecognised data"
    assert description.known is False
    assert description.service_probe is False
    assert "characters" in description.detail


def test_web_request_shows_its_request_line():
    description = describe_payload("GET /index.php?id=1' OR '1'='1 HTTP/1.1\r\nHost: lab\r\n\r\n")

    assert description.label == "Web (HTTP) request"
    assert description.detail == "GET /index.php?id=1' OR '1'='1 HTTP/1.1"
    assert description.service_probe is False


def test_web_request_with_unusual_characters_is_still_recognised():
    assert describe_payload("GET /\u00e9\u4e2d\u6587 \U0001F600 HTTP/1.1").label == "Web (HTTP) request"


def test_ssh_greeting_is_not_a_probe():
    description = describe_payload("SSH-2.0-OpenSSH_9.6\r\n")

    assert description.label == "SSH client greeting"
    assert description.detail == "SSH-2.0-OpenSSH_9.6"
    assert description.service_probe is False


def test_sip_request_from_a_normal_client_is_not_flagged_as_nmap():
    description = describe_payload("OPTIONS sip:alice@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33\r\n")

    assert description.label == "SIP (internet phone) request"
    assert description.service_probe is False


def test_other_recognised_protocols():
    assert describe_payload("\x16\x03\x01\x00\xa5\x01").label == "TLS/HTTPS handshake attempt"
    assert describe_payload("\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03").label == "DNS 'version.bind' query"


def test_plain_text_and_empty_messages():
    plain = describe_payload("hello there\n")
    assert (plain.label, plain.detail) == ("Plain text message", "hello there")

    assert describe_payload("").label == "Empty message"
    assert describe_payload(None).label == "Empty message"


def test_long_text_is_cut_to_one_short_line():
    description = describe_payload("A" * 500 + "\nsecond line")

    assert len(description.detail) <= 80
    assert "second line" not in description.detail


def test_text_that_merely_starts_like_a_binary_protocol_is_not_misread():
    assert describe_payload("JRMI is a Java thing").label == "Java RMI call"  # known limit: prefix match
    assert describe_payload("0 apples").label == "Plain text message"          # '0' alone is not LDAP
    assert describe_payload("hello MMS world").label == "Plain text message"