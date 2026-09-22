import hashlib
import hmac
import struct
import time
import unittest

from app import dnsclient as dc
from app import dnswire as w


KN = "key."
SECRET = b"k" * 32
WHEN = 1700000000
FUDGE = 300


def _question(qtype=w.TYPE_AXFR):
    return w.encode_name("example.") + struct.pack(">HH", qtype, w.CLASS_IN)


def _soa_rr(serial=1):
    return w.pack_rr(
        "example.", w.TYPE_SOA, w.CLASS_IN, 3600,
        w.encode_rdata("SOA", {"mname": "ns1.example.", "rname": "a.example.",
                               "serial": serial, "refresh": 7200, "retry": 3600,
                               "expire": 1209600, "minimum": 3600}))


def _a_rr(last_octet):
    return w.pack_rr("h.example.", w.TYPE_A, w.CLASS_IN, 300,
                     bytes([192, 0, 2, last_octet & 255]))


def _plain_response(qid=0x1234, answers=()):
    body = b"".join(answers)
    return (w.build_header(qid, w.FLAG_QR | w.FLAG_AA, 1, len(answers), 0, 0)
            + _question() + body)


def _indep_first_mac(secret, prior, response_no_tsig, key_name, t):
    """Fully independent RFC 2845 section 4.2 first-answer MAC:
    size||prior, then the response with TSIG removed (ARCOUNT decremented),
    then the full TSIG variables."""
    block = (struct.pack(">H", len(prior)) + prior
             + w.patch_arcount(response_no_tsig, 0)
             + w.tsig_variables(key_name, w._ALGORITHM_WIRE, t["time"],
                                t["fudge"], t["error"], t["other"]))
    return hmac.new(secret, block, hashlib.sha256).digest()


def _indep_later_mac(secret, prior, unsigned_msgs, signed_no_tsig, when,
                     fudge):
    """Independent RFC 2845 section 4.4 subsequent-envelope MAC: one
    continuous HMAC seeded with size||prior, fed every raw unsigned
    intermediary, then the signed message without TSIG and the timers
    (time||fudge) only."""
    ctx = hmac.new(secret, b"", hashlib.sha256)
    ctx.update(struct.pack(">H", len(prior)) + prior)
    for m in unsigned_msgs:
        ctx.update(m)
    ctx.update(signed_no_tsig)
    ctx.update(struct.pack(">HIH", (when >> 32) & 0xFFFF,
                           when & 0xFFFFFFFF, fudge))
    return ctx.digest()


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


class TestRequestMac(unittest.TestCase):
    def test_request_signed_with_arcount_zero(self):
        # The wire carries ARCOUNT=1 (the TSIG), but the MAC input must be the
        # message before the TSIG is appended with ARCOUNT not incremented (0).
        q = dc.build_tsig_query(0x1234, "example.", w.TYPE_AXFR, KN, SECRET,
                                when=WHEN)
        self.assertEqual(struct.unpack(">H", q[10:12])[0], 1)
        parsed = w.parse_query(q)
        ref = dc.reference_request_mac("example.", w.TYPE_AXFR, w.CLASS_IN,
                                       0x0100, b"", KN, SECRET, WHEN, FUDGE,
                                       0x1234)
        self.assertEqual(parsed["tsig"]["mac"], ref)
        # The server must authenticate exactly that standard MAC.
        self.assertEqual(w.expected_request_mac(SECRET, parsed), ref)

    def test_request_with_authority_section(self):
        auth = dc.soa_authority("example.", 7)
        q = dc.build_tsig_query(0x9999, "example.", w.TYPE_IXFR, KN, SECRET,
                                when=WHEN, authority=auth)
        parsed = w.parse_query(q)
        ref = dc.reference_request_mac("example.", w.TYPE_IXFR, w.CLASS_IN,
                                       0x0100, auth, KN, SECRET, WHEN, FUDGE,
                                       0x9999)
        self.assertEqual(parsed["tsig"]["mac"], ref)
        self.assertEqual(w.expected_request_mac(SECRET, parsed), ref)

    def test_tsig_variables_exclude_type_and_rdlen(self):
        # RFC 2845 section 3.4.2: NAME, CLASS ANY, TTL 0 then RDATA-without-MAC;
        # the RR TYPE and RDLEN fields must NOT be present.
        name_wire = w.encode_name(KN)
        block = w.tsig_variables(KN, w._ALGORITHM_WIRE, WHEN, FUDGE, 0, b"")
        self.assertTrue(block.startswith(name_wire))
        self.assertEqual(block[len(name_wire):len(name_wire) + 6],
                         struct.pack(">HI", w.CLASS_ANY, 0))
        rdata = block[len(name_wire) + 6:]
        self.assertTrue(rdata.startswith(w._ALGORITHM_WIRE))


class TestResponseMac(unittest.TestCase):
    def test_first_response_mac_matches_independent_formula(self):
        req = dc.build_tsig_query(0x1234, "example.", w.TYPE_AXFR, KN, SECRET,
                                  when=WHEN)
        req_mac = w.parse_query(req)["tsig"]["mac"]
        plain = _plain_response()
        signed, mac = w.sign_response(SECRET, plain, KN, req_mac, WHEN, FUDGE,
                                      0x1234)
        parsed = dc.parse_message(signed)
        self.assertEqual(mac, _indep_first_mac(SECRET, req_mac, plain, KN,
                                               parsed["tsig"]))
        # The client's single-answer verifier agrees.
        self.assertEqual(dc.verify_response_mac(parsed, SECRET, req_mac, KN),
                         mac)

    def test_single_message_is_first_and_last_with_request_prior(self):
        # A one-message transfer signs exactly once, chaining from request MAC.
        req = dc.build_tsig_query(1, "example.", w.TYPE_AXFR, KN, SECRET,
                                  when=WHEN)
        req_mac = w.parse_query(req)["tsig"]["mac"]
        running = w.RunningMac(SECRET, req_mac)
        plain = _plain_response(answers=[_soa_rr()])
        wire, mac = running.sign(plain, KN, WHEN, FUDGE, 1, first=True)
        parsed = dc.parse_message(wire)
        self.assertIsNotNone(parsed["tsig"])
        self.assertEqual(mac, _indep_first_mac(SECRET, req_mac, plain, KN,
                                               parsed["tsig"]))


class TestRunningChain(unittest.TestCase):
    def _stream(self, middle_answers):
        req = dc.build_tsig_query(0x4321, "example.", w.TYPE_AXFR, KN, SECRET,
                                  when=WHEN)
        req_mac = w.parse_query(req)["tsig"]["mac"]
        running = w.RunningMac(SECRET, req_mac)
        first = _plain_response(answers=[_soa_rr()])
        first_wire, first_mac = running.sign(first, KN, WHEN, FUDGE, 0x4321,
                                             first=True)
        out = [first_wire]
        unsigned = []
        for answers in middle_answers:
            m = _plain_response(answers=answers)
            running.feed_unsigned(m)
            unsigned.append(m)
            out.append(m)
        last = _plain_response(answers=[_soa_rr()])
        wire, mac = running.sign(last, KN, WHEN, FUDGE, 0x4321, first=False)
        out.append(wire)
        return req_mac, first_mac, out, unsigned, last, mac

    def test_last_mac_covers_unsigned_middle(self):
        req_mac, first_mac, _out, unsigned, last, mac = self._stream(
            [[_a_rr(10)]])
        self.assertEqual(mac, _indep_later_mac(SECRET, first_mac, unsigned,
                                               last, WHEN, FUDGE))

    def test_changing_unsigned_middle_changes_final_mac(self):
        _r, _f, _o, _u, _l, mac_a = self._stream([[_a_rr(10)]])
        _r, _f, _o, _u, _l, mac_b = self._stream([[_a_rr(11)]])
        self.assertNotEqual(mac_a, mac_b)

    def test_multiple_unsigned_messages_all_covered(self):
        req_mac, first_mac, _out, unsigned, last, mac = self._stream(
            [[_a_rr(1)], [_a_rr(2)], [_a_rr(3)]])
        self.assertEqual(mac, _indep_later_mac(SECRET, first_mac, unsigned,
                                               last, WHEN, FUDGE))
        # Reordering intermediaries changes the final MAC.
        reordered = _indep_later_mac(SECRET, first_mac,
                                     [unsigned[0], unsigned[2], unsigned[1]],
                                     last, WHEN, FUDGE)
        self.assertNotEqual(mac, reordered)

    def test_client_transfer_verifier_continuous_chain(self):
        req_mac, _first_mac, out, _u, _l, mac = self._stream(
            [[_a_rr(10)], [_a_rr(11)]])
        verifier = dc.TransferVerifier(SECRET, KN, req_mac)
        last_mac = b""
        for wire in out:
            last_mac = verifier.observe(dc.parse_message(wire))
        self.assertEqual(last_mac, mac)
        self.assertEqual(verifier.signed_seen, 2)

    def test_client_verifier_rejects_tampered_middle(self):
        req_mac, _f, out, _u, _l, _mac = self._stream([[_a_rr(10)]])
        # Flip a byte in the unsigned intermediary only.
        tampered = bytearray(out[1])
        tampered[-1] ^= 0xFF
        out[1] = bytes(tampered)
        verifier = dc.TransferVerifier(SECRET, KN, req_mac)
        with self.assertRaises(AssertionError):
            for wire in out:
                verifier.observe(dc.parse_message(wire))

    def test_periodic_signing_positions(self):
        # Mirror the server rule: first, last, every 100th envelope.
        for n, expected in [(1, [0]), (2, [0, 1]), (100, [0, 99]),
                            (101, [0, 100]), (102, [0, 100, 101]),
                            (201, [0, 100, 200]), (250, [0, 100, 200, 249])]:
            idx = [i for i in range(n)
                   if i == 0 or i == n - 1
                   or i % w.TSIG_SIGN_INTERVAL == 0]
            self.assertEqual(idx, expected, n)
            gaps = [b - a for a, b in zip(idx, idx[1:])]
            self.assertTrue(all(g <= w.TSIG_SIGN_INTERVAL for g in gaps), n)


if __name__ == "__main__":
    unittest.main()
