import hashlib
import hmac
import struct
import time
import unittest

from app import dnsclient as dc
from app import dnswire as w


def _xfer_message(tag: str, qid: int = 1) -> bytes:
    """A small valid transfer-style DNS message (no TSIG) whose content
    depends on *tag*."""
    rr = w.pack_rr("example.", w.TYPE_TXT, w.CLASS_IN, 60,
                   w.encode_rdata("TXT", {"text": tag}))
    return (w.build_header(qid, w.FLAG_QR | w.FLAG_AA, 1, 1, 0, 0)
            + w.encode_name("example.")
            + struct.pack(">HH", w.TYPE_AXFR, w.CLASS_IN) + rr)


def _walk_chain(wires, secret, key_name, prior):
    """Client-side walk of the continuous chain: verify signed messages,
    fold unsigned ones. Returns the final running MAC."""
    for wire in wires:
        p = dc.parse_message(wire)
        if p["tsig"] is not None:
            prior = dc.verify_response_mac(p, secret, prior, key_name)
        else:
            prior = dc.continue_running_mac(secret, prior, p["raw"])
    return prior


class TestTsigWire(unittest.TestCase):
    def test_time_48bit_roundtrip(self):
        for when in (0, 1, 1700000000, 0xFFFFFFFF, 0x1_FFFFFFFF):
            q = dc.build_tsig_query(0x1234, "example.", w.TYPE_AXFR,
                                    "key.", b"k" * 32, when=when, fudge=300)
            parsed = w.parse_query(q)
            self.assertEqual(parsed["tsig"]["time"], when, when)
            self.assertEqual(parsed["tsig"]["fudge"], 300)

    def test_current_time_roundtrip(self):
        now = int(time.time())
        q = dc.build_tsig_query(1, "example.", w.TYPE_SOA, "key.",
                                b"k" * 32)
        parsed = w.parse_query(q)
        self.assertLessEqual(abs(parsed["tsig"]["time"] - now), 2)

    def test_time_verification(self):
        now = 1000000
        self.assertTrue(w.verify_tsig_time(now, 300, now))
        self.assertTrue(w.verify_tsig_time(now + 300, 300, now))
        self.assertFalse(w.verify_tsig_time(now + 301, 300, now))
        self.assertFalse(w.verify_tsig_time(now - 100000, 300, now))
        self.assertFalse(w.verify_tsig_time(now, 99999, now))  # fudge cap

    def test_request_mac_deterministic(self):
        q1 = dc.build_tsig_query(1, "example.", w.TYPE_AXFR, "k.",
                                 b"k" * 32, when=1000)
        q2 = dc.build_tsig_query(1, "example.", w.TYPE_AXFR, "k.",
                                 b"k" * 32, when=1000)
        self.assertEqual(q1, q2)
        p1, p2 = w.parse_query(q1), w.parse_query(q2)
        self.assertEqual(p1["tsig"]["mac"], p2["tsig"]["mac"])

    def test_request_mac_standard_arcount(self):
        # RFC 2845 §4.2: the request MAC input is the message *before* the
        # TSIG RR is appended, with ARCOUNT=0 (not the on-the-wire value 1).
        secret = b"s" * 32
        q = dc.build_tsig_query(0x2222, "example.", w.TYPE_AXFR, "key.",
                                secret, when=1700000000, fudge=300)
        parsed = w.parse_query(q)
        self.assertEqual(parsed["arcount"], 1)  # TSIG present on the wire
        base = w.patch_arcount(parsed["raw"][:parsed["tsig_offset"]], 0)
        ref = hmac.new(secret,
                       base + w.tsig_variables("key.", w._ALGORITHM_WIRE,
                                               1700000000, 300, 0, b""),
                       hashlib.sha256).digest()
        self.assertEqual(parsed["tsig"]["mac"], ref)
        # the server's verifier computes the same value
        self.assertEqual(w.expected_request_mac(secret, parsed), ref)
        # and the independent from-scratch reference agrees
        self.assertEqual(
            dc.reference_request_mac("example.", w.TYPE_AXFR, w.CLASS_IN,
                                     0x0100, b"", "key.", secret, 1700000000,
                                     300, 0x2222), ref)

    def test_response_mac_standard_reference(self):
        # RFC 2845 §4.3/§4.4: response MAC = HMAC(len16(prior) || prior ||
        # response-without-TSIG (ARCOUNT=0) || TSIG variables).
        secret, prior = b"k" * 32, b"p" * 32
        soa = w.encode_rdata("SOA", {"mname": "ns1.example.",
                                     "rname": "admin.example.", "serial": 7,
                                     "refresh": 7200, "retry": 3600,
                                     "expire": 1209600, "minimum": 3600})
        msg = (w.build_header(0x1234, w.FLAG_QR | w.FLAG_AA, 1, 1, 0, 0)
               + w.encode_name("example.")
               + struct.pack(">HH", w.TYPE_AXFR, w.CLASS_IN)
               + w.pack_rr("example.", w.TYPE_SOA, w.CLASS_IN, 3600, soa))
        wire, mac = w.sign_response(secret, msg, "key.", prior, 1700000000,
                                    300, 0x1234, arcount_before=0)
        ref = hmac.new(secret,
                       struct.pack(">H", len(prior)) + prior + msg
                       + w.tsig_variables("key.", w._ALGORITHM_WIRE,
                                          1700000000, 300, 0, b""),
                       hashlib.sha256).digest()
        self.assertEqual(mac, ref)
        parsed = dc.parse_message(wire)
        self.assertEqual(parsed["arcount"], 1)  # TSIG appended on the wire
        self.assertEqual(dc.verify_response_mac(parsed, secret, prior,
                                                "key."), mac)

    def test_transfer_chain_covers_middle_messages(self):
        # Two 3-message streams differing only in the unsigned middle
        # message must end with different TSIG MACs: the middle content is
        # covered by the continuous authentication chain.
        secret, req = b"c" * 32, b"r" * 32

        def run(middle_tag):
            wires = [wire for wire, _ in w.sign_transfer_stream(
                secret, "key.", req, 1700000000, 300, 1,
                [_xfer_message("first"), _xfer_message(middle_tag),
                 _xfer_message("last")])]
            parsed = [dc.parse_message(x) for x in wires]
            self.assertIsNotNone(parsed[0]["tsig"])
            self.assertIsNone(parsed[1]["tsig"])     # middle stays unsigned
            self.assertIsNotNone(parsed[2]["tsig"])
            _walk_chain(wires, secret, "key.", req)  # and it verifies
            return parsed[-1]["tsig"]["mac"]

        self.assertNotEqual(run("middle-a"), run("middle-b"))

    def test_transfer_chain_periodic_signing(self):
        # RFC 2845 §4.4: first, last and at least every 100th message signed.
        secret, req = b"c" * 32, b"r" * 32
        wires = [wire for wire, _ in w.sign_transfer_stream(
            secret, "key.", req, 1700000000, 300, 1,
            [_xfer_message(f"m{i}") for i in range(102)])]
        self.assertEqual(len(wires), 102)
        signed = [i for i, x in enumerate(wires)
                  if dc.parse_message(x)["tsig"] is not None]
        self.assertEqual(signed, [0, 100, 101])
        # never more than 99 consecutive unsigned messages
        for a, b in zip(signed, signed[1:]):
            self.assertLessEqual(b - a, w.TSIG_SIGN_INTERVAL)
        _walk_chain(wires, secret, "key.", req)

    def test_transfer_chain_single_message(self):
        # A one-message transfer is both first and last: exactly one signed
        # message chaining directly from the request MAC.
        secret, req = b"c" * 32, b"r" * 32
        wires = [wire for wire, _ in w.sign_transfer_stream(
            secret, "key.", req, 1700000000, 300, 1, [_xfer_message("only")])]
        self.assertEqual(len(wires), 1)
        p = dc.parse_message(wires[0])
        self.assertIsNotNone(p["tsig"])
        self.assertEqual(dc.verify_response_mac(p, secret, req, "key."),
                         p["tsig"]["mac"])


if __name__ == "__main__":
    unittest.main()
