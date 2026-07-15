"""DNS / email-authentication checks (SPF, DMARC, CAA).

Uses a tiny hand-rolled DNS-over-UDP query so the tool stays dependency-free.
If DNS cannot be reached (blocked network, no resolver), the checks simply
return nothing rather than penalising the target.
"""

from __future__ import annotations

import socket
import struct
from typing import List, Optional

from security_analyser.model import Finding, Severity

# Public resolvers to try, in order.
_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
_TYPE_TXT = 16
_TYPE_CAA = 257
_TYPE_DNSKEY = 48


def _build_query(qname: str, qtype: int) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(
        bytes([len(label)]) + label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
        for label in qname.rstrip(".").split(".") if label
    ) + b"\x00"
    return header + q + struct.pack(">HH", qtype, 1)


def _skip_name(data: bytes, offset: int) -> int:
    """Advance past a (possibly compressed) DNS name; return new offset."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer (2 bytes)
            return offset + 2
        offset += 1 + length
    return offset


def _parse_answers(data: bytes, want_type: int) -> List[bytes]:
    """Return the rdata blobs of answers matching ``want_type``."""
    try:
        _id, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return []
    offset = 12
    for _ in range(qd):  # skip question section
        offset = _skip_name(data, offset)
        offset += 4
    out: List[bytes] = []
    for _ in range(an):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == want_type:
            out.append(rdata)
    return out


def _query(qname: str, qtype: int, timeout: float = 5.0) -> Optional[List[bytes]]:
    packet = _build_query(qname, qtype)
    for resolver in _RESOLVERS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout, 5.0))
        try:
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(4096)
            return _parse_answers(data, qtype)
        except (OSError, socket.timeout):
            continue
        finally:
            sock.close()
    return None


def txt_records(name: str, timeout: float = 5.0) -> Optional[List[str]]:
    raw = _query(name, _TYPE_TXT, timeout)
    if raw is None:
        return None
    records = []
    for rdata in raw:
        # TXT rdata is one or more <length><bytes> character-strings.
        i, parts = 0, []
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        records.append("".join(parts))
    return records


def caa_records(name: str, timeout: float = 5.0) -> Optional[List[str]]:
    raw = _query(name, _TYPE_CAA, timeout)
    if raw is None:
        return None
    out = []
    for rdata in raw:
        if len(rdata) < 2:
            continue
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii", "replace")
        value = rdata[2 + tag_len:].decode("ascii", "replace")
        out.append(f"{tag} {value}")
    return out


def dnskey_present(name: str, timeout: float = 5.0):
    raw = _query(name, _TYPE_DNSKEY, timeout)
    if raw is None:
        return None
    return len(raw) > 0


def _registrable_domain(host: str) -> str:
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def check_dns(host: str, timeout: float = 5.0) -> List[Finding]:
    """Check SPF, DMARC and CAA records for ``host``'s domain."""
    domain = _registrable_domain(host)
    findings: List[Finding] = []

    txt = txt_records(domain, timeout)
    if txt is None:
        # DNS unreachable — skip silently rather than reporting false gaps.
        return []

    if not any(r.lower().startswith("v=spf1") for r in txt):
        findings.append(
            Finding(
                id="DNS-SPF",
                title="No SPF record",
                severity=Severity.MEDIUM,
                category="DNS & email",
                description=(
                    f"The domain {domain} has no SPF (v=spf1) TXT record. Without SPF, "
                    "attackers can more easily spoof email from your domain."
                ),
                recommendation="Publish an SPF record listing your legitimate mail senders.",
            )
        )

    dmarc = txt_records(f"_dmarc.{domain}", timeout) or []
    if not any(r.lower().startswith("v=dmarc1") for r in dmarc):
        findings.append(
            Finding(
                id="DNS-DMARC",
                title="No DMARC record",
                severity=Severity.MEDIUM,
                category="DNS & email",
                description=(
                    f"The domain {domain} has no DMARC policy (_dmarc.{domain}). DMARC "
                    "lets you detect and reject spoofed email using your domain."
                ),
                recommendation="Publish a DMARC record, starting at 'v=DMARC1; p=none' and tightening to 'reject'.",
            )
        )

    has_dnssec = dnskey_present(domain, timeout)
    if has_dnssec is False:
        findings.append(
            Finding(
                id="DNS-DNSSEC",
                title="DNSSEC not enabled",
                severity=Severity.LOW,
                category="DNS & email",
                description=(
                    f"The domain {domain} publishes no DNSKEY records, so DNSSEC is "
                    "not enabled. Without it, DNS responses can be forged (cache "
                    "poisoning), redirecting users to attacker infrastructure."
                ),
                recommendation="Enable DNSSEC at your DNS provider / registrar.",
            )
        )

    caa = caa_records(domain, timeout)
    if caa is not None and not caa:
        findings.append(
            Finding(
                id="DNS-CAA",
                title="No CAA record",
                severity=Severity.LOW,
                category="DNS & email",
                description=(
                    f"The domain {domain} has no CAA record. CAA restricts which "
                    "certificate authorities may issue certificates for your domain, "
                    "reducing the risk of mis-issuance."
                ),
                recommendation="Add a CAA record naming your CA(s), e.g. '0 issue \"letsencrypt.org\"'.",
            )
        )
    return findings
