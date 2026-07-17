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


def _read_name(data: bytes, off: int):
    """Decode a (possibly compressed) DNS name; return (name, next_offset)."""
    labels = []
    jumped = False
    resume = off
    guard = 0
    while off < len(data) and guard < 128:
        guard += 1
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                resume = off + 2
            off = ptr
            jumped = True
            continue
        labels.append(data[off + 1:off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), (resume if jumped else off)


def _query_message(qname: str, qtype: int, timeout: float) -> Optional[bytes]:
    packet = _build_query(qname, qtype)
    for resolver in _RESOLVERS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout, 5.0))
        try:
            sock.sendto(packet, (resolver, 53))
            return sock.recvfrom(4096)[0]
        except (OSError, socket.timeout):
            continue
        finally:
            sock.close()
    return None


def ns_records(domain: str, timeout: float = 5.0) -> Optional[List[str]]:
    data = _query_message(domain, 2, timeout)  # type 2 = NS
    if data is None:
        return None
    try:
        _id, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return []
    off = 12
    for _ in range(qd):
        _n, off = _read_name(data, off)
        off += 4
    names = []
    for _ in range(an):
        _n, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _c, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 2:
            nsname, _ = _read_name(data, off)
            if nsname:
                names.append(nsname.rstrip("."))
        off += rdlen
    return names


def zone_transfer_open(domain: str, timeout: float = 5.0) -> Optional[bool]:
    """Attempt an AXFR against the domain's nameservers. True if any allows it."""
    nameservers = ns_records(domain, timeout)
    if not nameservers:
        return None
    query = _build_query(domain, 252)  # type 252 = AXFR
    for ns in nameservers[:3]:
        try:
            ip = socket.gethostbyname(ns)
        except OSError:
            continue
        try:
            with socket.create_connection((ip, 53), timeout=min(timeout, 5.0)) as sock:
                sock.sendall(struct.pack(">H", len(query)) + query)
                header = sock.recv(2)
                if len(header) < 2:
                    continue
                length = struct.unpack(">H", header)[0]
                resp = b""
                while len(resp) < min(length, 4096):
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                if len(resp) >= 12:
                    ancount = struct.unpack(">HHHHHH", resp[:12])[3]
                    if ancount >= 2:  # SOA + at least one real record = transfer worked
                        return True
        except (OSError, socket.timeout, struct.error):
            continue
    return False


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

    spf = next((r for r in txt if r.lower().startswith("v=spf1")), None)
    if not spf:
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
    else:
        low = spf.lower()
        if "+all" in low or low.rstrip().endswith(" all"):
            findings.append(Finding(
                id="DNS-SPF-ALL",
                title="SPF record ends with a permissive '+all'",
                severity=Severity.MEDIUM,
                category="DNS & email",
                description=(
                    f"The SPF record for {domain} uses '+all' (or bare 'all'), which "
                    "authorises any server to send mail as your domain — defeating SPF."
                ),
                recommendation="End the SPF record with '-all' (hard fail) or '~all' (soft fail).",
                evidence=spf,
            ))
        lookups = sum(low.count(m) for m in ("include:", "a:", "mx:", "ptr", "exists:", "redirect="))
        if lookups > 10:
            findings.append(Finding(
                id="DNS-SPF-LOOKUPS",
                title="SPF record exceeds the 10 DNS-lookup limit",
                severity=Severity.LOW,
                category="DNS & email",
                description=(
                    f"The SPF record for {domain} appears to require more than 10 DNS "
                    "lookups, which causes a permerror and makes SPF fail open."
                ),
                recommendation="Flatten includes to stay within the 10-lookup limit.",
                evidence=f"~{lookups} lookup mechanisms",
            ))

    dmarc = txt_records(f"_dmarc.{domain}", timeout) or []
    dmarc_rec = next((r for r in dmarc if r.lower().startswith("v=dmarc1")), None)
    if not dmarc_rec:
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
    else:
        policy = ""
        for part in dmarc_rec.lower().split(";"):
            part = part.strip()
            if part.startswith("p="):
                policy = part[2:].strip()
        if policy == "none":
            findings.append(Finding(
                id="DNS-DMARC-WEAK",
                title="DMARC policy is 'p=none' (monitoring only)",
                severity=Severity.LOW,
                category="DNS & email",
                description=(
                    f"The DMARC policy for {domain} is 'p=none', so spoofed mail is "
                    "reported but not rejected — it provides no active protection."
                ),
                recommendation="Move DMARC to 'p=quarantine' and then 'p=reject' once monitoring looks clean.",
                evidence=dmarc_rec,
            ))

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

    if zone_transfer_open(domain, timeout) is True:
        findings.append(Finding(
            id="DNS-AXFR",
            title="DNS zone transfer (AXFR) allowed",
            severity=Severity.HIGH,
            category="DNS & email",
            description=(
                f"A nameserver for {domain} answered an AXFR request, handing over the "
                "full DNS zone. This exposes every host and subdomain — a complete map "
                "of your infrastructure for an attacker."
            ),
            recommendation="Restrict zone transfers to authorised secondary nameservers only.",
        ))
    return findings
