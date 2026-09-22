"""Minimal TSIG-capable DNS client.

Used by the acceptance service (``SERVICE_ROLE=verify``) and the automated
tests. It constructs RFC 1035 queries, signs them with the same RFC 2845-style
HMAC-SHA256 scheme the server uses, and parses/verifies signed responses.
"""
from __future__ import annotations

import hmac
import hashlib
import socket
import struct

from . import dnswire as w

ALG = w._ALGORITHM_WIRE


# ---------------------------------------------------------------------------
# Query construction
# ---------------------------------------------------------------------------

def question_wire(qname: str, qtype: int) -> bytes:
    return w.encode_name(qname) + struct.pack(">HH", qtype, w.CLASS_IN)


def soa_authority(zone: str, serial: int) -> bytes:
    rdata = (w.encode_name(zone) + w.encode_name(zone)
             + struct.pack(">IIIII", serial, 7200, 3600, 1209600, 3600))
    return (w.encode_name(zone) + struct.pack(">HHIH", w.TYPE_SOA, w.CLASS_IN,
                                              3600, len(rdata)) + rdata)


def build_tsig_query(qid: int, qname: str, qtype: int, key_name: str,
                     secret: bytes, when: int | None = None, fudge: int = 300,
                     authority: bytes = b"") -> bytes:
    when = w.utcnow() if when is None else when
    flags = 0x0100  # standard query, RD
    # The MAC is taken over the message before the TSIG is appended, with
    # ARCOUNT not yet incremented for it (RFC 2845 §3.4.1); here that is 0.
    base = struct.pack(">HHHHHH", qid, flags, 1, 0, 1 if authority else 0, 0)
    base += question_wire(qname, qtype) + authority
    block = (w.patch_arcount(base, 0)
             + w.tsig_variables(key_name, ALG, when, fudge, 0, b""))
    mac = hmac.new(secret, block, hashlib.sha256).digest()
    rdata = (ALG
             + struct.pack(">HIH", (when >> 32) & 0xFFFF, when & 0xFFFFFFFF,
                           fudge)
             + struct.pack(">H", len(mac)) + mac
             + struct.pack(">HHH", qid, 0, 0))
    rr = w.encode_name(key_name) + struct.pack(">HHIH", w.TYPE_TSIG,
                                               w.CLASS_ANY, 0, len(rdata)) + rdata
    return w.patch_arcount(base, 1) + rr


def build_plain_query(qid: int, qname: str, qtype: int, rd: bool = True) -> bytes:
    flags = 0x0100 if rd else 0
    return (struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
            + question_wire(qname, qtype))


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_rrs(buf: bytes, off: int, count: int):
    out = []
    for _ in range(count):
        name, off2 = w.decode_name(buf, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off2:off2 + 10])
        rstart = off2 + 10
        out.append({"name": name, "type": rtype, "class": rclass, "ttl": ttl,
                    "rdata": buf[rstart:rstart + rdlen]})
        off = rstart + rdlen
    return out, off


def parse_message(buf: bytes) -> dict:
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    qname, off = w.decode_name(buf, off)
    qtype, qclass = struct.unpack(">HH", buf[off:off + 4])
    off += 4
    question_end = off
    answers, off = _parse_rrs(buf, off, an)
    authority, off = _parse_rrs(buf, off, ns)
    tsig = None
    tsig_off = None
    additionals = []
    walk = off
    for _ in range(ar):
        rr_start = walk
        tname, p = w.decode_name(buf, walk)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[p:p + 10])
        rstart = p + 10
        rr = {"name": tname, "type": rtype, "class": rclass, "ttl": ttl,
              "rdata": buf[rstart:rstart + rdlen]}
        if rtype == w.TYPE_TSIG:
            tsig = {"name": tname, **w.parse_tsig_rdata(buf, rstart, rdlen)}
            tsig_off = rr_start
        additionals.append(rr)
        walk = rstart + rdlen
    return {"id": qid, "flags": flags, "rcode": flags & 0xF,
            "tc": bool(flags & w.FLAG_TC), "aa": bool(flags & w.FLAG_AA),
            "qname": qname, "qtype": qtype, "answers": answers,
            "authority": authority, "additionals": additionals,
            "tsig": tsig, "tsig_offset": tsig_off, "raw": buf,
            "arcount": ar, "question_end": question_end}


def _skip_section(buf, off, qd_questions):
    for _ in range(qd_questions):
        _, off = w.decode_name(buf, off)
        off += 4
    return off


def _skip_to_section_end(buf, start, qd, an, ns):
    off = _skip_section(buf, start, qd)
    for _ in range(an + ns):
        _, off = w.decode_name(buf, off)
        rdlen = struct.unpack(">H", buf[off + 8:off + 10])[0]
        off += 10 + rdlen
    return off


def _signed_base(msg: dict) -> bytes:
    """RFC 2845 §3.2/§3.4.1: wire bytes before the TSIG RR with the TSIG
    removed, i.e. ARCOUNT decremented by one."""
    base = msg["raw"][:msg["tsig_offset"]]
    return w.patch_arcount(base, msg["arcount"] - 1)


def _tsig_timers(t: dict) -> bytes:
    return struct.pack(">HIH", (t["time"] >> 32) & 0xFFFF,
                       t["time"] & 0xFFFFFFFF, t["fudge"])


class TransferVerifier:
    """Verify a (possibly multi-message) TSIG transfer by reproducing the
    server's continuous HMAC state (RFC 2845 §4.4).

    Feed every envelope in order with :meth:`observe`: unsigned envelopes are
    folded into the running HMAC verbatim; a signed envelope is checked
    against the current state and resets that state with its own MAC. The
    first signed envelope uses the full TSIG variables (§4.2); every later
    signed envelope uses timers only (§4.4)."""

    def __init__(self, secret: bytes, key_name: str, request_mac: bytes):
        self.secret = secret
        self.key_name = key_name
        self._reset(request_mac)
        self.signed_seen = 0

    def _reset(self, prior_mac: bytes) -> None:
        self.ctx = hmac.new(self.secret, b"", hashlib.sha256)
        self.ctx.update(struct.pack(">H", len(prior_mac)) + prior_mac)

    def observe(self, msg: dict) -> bytes:
        t = msg["tsig"]
        if t is None:
            # Unsigned intermediary: feed the raw wire message exactly as sent.
            self.ctx.update(msg["raw"])
            return b""
        self.ctx.update(_signed_base(msg))
        if self.signed_seen == 0:
            self.ctx.update(w.tsig_variables(
                self.key_name, ALG, t["time"], t["fudge"], t["error"],
                t["other"]))
        else:
            self.ctx.update(_tsig_timers(t))
        expect = self.ctx.digest()
        if not hmac.compare_digest(expect, t["mac"]):
            raise AssertionError("response TSIG MAC mismatch")
        self.signed_seen += 1
        self._reset(t["mac"])
        return t["mac"]


def verify_response_mac(msg: dict, secret: bytes, prior_mac: bytes,
                        key_name: str, when: int | None = None) -> bytes:
    """Verify a single standard answer's TSIG (RFC 2845 §4.2) independently;
    returns its MAC for chaining. The prior/request MAC carries the two-octet
    MAC-size prefix (§3.4.3). For multi-message transfers use
    :class:`TransferVerifier`."""
    t = msg["tsig"]
    block = (struct.pack(">H", len(prior_mac)) + prior_mac
             + _signed_base(msg) + w.tsig_variables(
                 key_name, ALG, t["time"], t["fudge"], t["error"], t["other"]))
    expect = hmac.new(secret, block, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, t["mac"]):
        raise AssertionError("response TSIG MAC mismatch")
    return t["mac"]


def reference_request_mac(qname: str, qtype: int, qclass: int, flags: int,
                          authority: bytes, key_name: str, secret: bytes,
                          when: int, fudge: int, qid: int) -> bytes:
    """Independently compute the standard request MAC (RFC 2845 §3.4) from
    scratch, without sharing the server/client message builders: the message
    before the TSIG is added with ARCOUNT not yet incremented (0 here)."""
    question = w.encode_name(qname) + struct.pack(">HH", qtype, qclass)
    nscount = 1 if authority else 0
    base = struct.pack(">HHHHHH", qid, flags, 1, 0, nscount, 0)
    base += question + authority
    block = (w.patch_arcount(base, 0)
             + w.tsig_variables(key_name, ALG, when, fudge, 0, b""))
    return hmac.new(secret, block, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

def tcp_query(host: str, port: int, message: bytes, timeout: float = 10.0
              ) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(message)) + message)
        head = _recv(s, 2)
        (length,) = struct.unpack(">H", head)
        return _recv(s, length)


def tcp_transfer(host: str, port: int, message: bytes, timeout: float = 30.0
                 ) -> list[bytes]:
    """Read every framed response message until EOF (transfers close after the
    final message)."""
    out = []
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(message)) + message)
        try:
            while True:
                head = _recv(s, 2)
                if head is None:
                    break
                (length,) = struct.unpack(">H", head)
                out.append(_recv(s, length))
        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            pass
    return out


def _recv(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None if not buf else buf
        buf += chunk
    return buf


def udp_query(host: str, port: int, message: bytes, timeout: float = 5.0
              ) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(message, (host, port))
        data, _ = s.recvfrom(4096)
        return data


def udp_send_raw(host: str, port: int, message: bytes, timeout: float = 2.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(message, (host, port))
        try:
            data, _ = s.recvfrom(4096)
            return data
        except socket.timeout:
            return None


# ---------------------------------------------------------------------------
# RR helpers
# ---------------------------------------------------------------------------

def soa_serial(rdata: bytes) -> int:
    _, p = w.decode_name(rdata, 0)
    _, p = w.decode_name(rdata, p)
    return struct.unpack(">I", rdata[p:p + 4])[0]
