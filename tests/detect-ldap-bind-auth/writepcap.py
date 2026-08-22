import sys
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
LDAP_PORT = 389


def ber_length(length: int) -> bytes:
    """Encode a BER length field for a TLV element."""
    if length < 0x80:
        return bytes([length])

    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag: int, value: bytes) -> bytes:
    """Build a BER TLV value from a tag and byte string payload."""
    return bytes([tag]) + ber_length(len(value)) + value


def ber_integer(value: int) -> bytes:
    """Encode a non-negative ASN.1 INTEGER as a BER TLV value."""
    if value < 0:
        raise ValueError("only non-negative INTEGER values allowed")

    if value == 0:
        encoded = b"\x00"
    else:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded

    return tlv(0x02, encoded)


def ber_octet_string(value: bytes) -> bytes:
    """Encode an ASN.1 OCTET STRING as a BER TLV value."""
    return tlv(0x04, value)


def ldap_bind_request_simple(message_id: int, dn: bytes, password: bytes) -> bytes:
    """Create an LDAP simple bind request with a DN and password."""
    # AuthenticationChoice.simple is context-specific primitive tag [0].
    authentication = tlv(0x80, password)

    bind_request = ber_integer(3) + ber_octet_string(dn) + authentication

    # BindRequest is [APPLICATION 0].
    protocol_op = tlv(0x60, bind_request)

    # LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp ... }
    return tlv(0x30, ber_integer(message_id) + protocol_op)


def ldap_bind_request_sasl(
    message_id: int,
    dn: bytes,
    mechanism: bytes,
    credentials: bytes | None,
) -> bytes:
    """Create an LDAP SASL bind request, optionally including credentials."""
    # AuthenticationChoice.sasl is context-specific constructed tag [3].
    #
    # LDAP uses IMPLICIT tagging here, so the [3] tag directly contains
    # the SaslCredentials fields rather than an additional SEQUENCE tag.
    sasl = ber_octet_string(mechanism)
    if credentials is not None:
        sasl += ber_octet_string(credentials)

    authentication = tlv(0xA3, sasl)

    bind_request = ber_integer(3) + ber_octet_string(dn) + authentication

    protocol_op = tlv(0x60, bind_request)
    return tlv(0x30, ber_integer(message_id) + protocol_op)


def ldap_bind_response_success(message_id: int) -> bytes:
    """Return a successful LDAP bind response for the given message ID."""
    # LDAPResult:
    #   resultCode        ENUMERATED success(0)
    #   matchedDN         OCTET STRING ""
    #   diagnosticMessage OCTET STRING ""
    ldap_result = tlv(0x0A, b"\x00") + ber_octet_string(b"") + ber_octet_string(b"")

    # BindResponse is [APPLICATION 1].
    protocol_op = tlv(0x61, ldap_result)
    return tlv(0x30, ber_integer(message_id) + protocol_op)


def add_tcp_flow(
    packets: list,
    sport: int,
    request: bytes,
    response: bytes,
    start_time: float,
) -> float:
    """Append a full LDAP TCP flow, including handshake and teardown, to `packets`."""
    cseq = 1000
    sseq = 5000
    now = start_time

    def add(pkt):
        nonlocal now
        pkt.time = now
        packets.append(pkt)
        now += 0.001

    c2s = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT_IP, dst=SERVER_IP)
    s2c = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER_IP, dst=CLIENT_IP)

    # Three-way handshake.
    add(c2s / TCP(sport=sport, dport=LDAP_PORT, flags="S", seq=cseq))
    add(
        s2c
        / TCP(
            sport=LDAP_PORT,
            dport=sport,
            flags="SA",
            seq=sseq,
            ack=cseq + 1,
        )
    )
    add(
        c2s
        / TCP(
            sport=sport,
            dport=LDAP_PORT,
            flags="A",
            seq=cseq + 1,
            ack=sseq + 1,
        )
    )

    cseq += 1
    sseq += 1

    # LDAP BindRequest.
    add(
        c2s
        / TCP(
            sport=sport,
            dport=LDAP_PORT,
            flags="PA",
            seq=cseq,
            ack=sseq,
        )
        / Raw(request)
    )
    cseq += len(request)

    # Successful BindResponse.
    add(
        s2c
        / TCP(
            sport=LDAP_PORT,
            dport=sport,
            flags="PA",
            seq=sseq,
            ack=cseq,
        )
        / Raw(response)
    )
    sseq += len(response)

    add(
        c2s
        / TCP(
            sport=sport,
            dport=LDAP_PORT,
            flags="A",
            seq=cseq,
            ack=sseq,
        )
    )

    # Graceful close.
    add(
        c2s
        / TCP(
            sport=sport,
            dport=LDAP_PORT,
            flags="FA",
            seq=cseq,
            ack=sseq,
        )
    )
    cseq += 1

    add(
        s2c
        / TCP(
            sport=LDAP_PORT,
            dport=sport,
            flags="FA",
            seq=sseq,
            ack=cseq,
        )
    )
    sseq += 1

    add(
        c2s
        / TCP(
            sport=sport,
            dport=LDAP_PORT,
            flags="A",
            seq=cseq,
            ack=sseq,
        )
    )

    return now + 0.100


def main() -> None:
    """Generate the LDAP bind-auth PCAP covering simple and SASL bind requests."""
    output = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).with_name("ldap-bind-auth.pcap")
    )

    packets = []
    now = 1_700_000_000.0

    # Flow 1: simple authentication.
    #
    # The DN and password intentionally contain strings used by the negative
    # SASL sticky-buffer rules. If either SASL sticky buffer accidentally
    # inspects the whole BindRequest or the simple-auth data, those rules
    # will incorrectly alert.
    simple_request = ldap_bind_request_simple(
        message_id=1,
        dn=b"cn=SIMPLE-ONLY-MECH,dc=example,dc=com",
        password=b"SIMPLE-ONLY-CRED",
    )
    now = add_tcp_flow(
        packets,
        sport=40000,
        request=simple_request,
        response=ldap_bind_response_success(1),
        start_time=now,
    )

    # Flow 2: SASL authentication with both mechanism and credentials.
    sasl_with_credentials = ldap_bind_request_sasl(
        message_id=2,
        dn=b"cn=sasl-user,dc=example,dc=com",
        mechanism=b"GSS-SPNEGO",
        credentials=b"SASL-CREDS-MARKER",
    )
    now = add_tcp_flow(
        packets,
        sport=40001,
        request=sasl_with_credentials,
        response=ldap_bind_response_success(2),
        start_time=now,
    )

    # Flow 3: SASL authentication with no credentials.
    #
    # This exercises the optional-credentials path: the authentication selector
    # and mechanism buffer should still match, while the credentials getter has
    # no buffer to expose.
    sasl_without_credentials = ldap_bind_request_sasl(
        message_id=3,
        dn=b"cn=plain-user,dc=example,dc=com",
        mechanism=b"PLAIN",
        credentials=None,
    )
    add_tcp_flow(
        packets,
        sport=40002,
        request=sasl_without_credentials,
        response=ldap_bind_response_success(3),
        start_time=now,
    )

    wrpcap(str(output), packets)
    print(f"Wrote {len(packets)} packets to {output}")


if __name__ == "__main__":
    main()
