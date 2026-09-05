#!/usr/bin/env python3
"""Tests for tools/runtime/scope.py bypass-surface hardening (v1.24.1+)."""
import sys
import unittest
from pathlib import Path

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.runtime.scope import _canonical, _host_of, _decode_alt_ip, _is_loopback


class DecimalIPBypass(unittest.TestCase):
    """http://2130706433/ must normalize to 127.0.0.1."""

    def test_decimal_ip_loopback(self):
        # 127.0.0.1 == 2130706433 (32-bit encoding)
        self.assertEqual(_decode_alt_ip("2130706433"), "127.0.0.1")
        self.assertTrue(_is_loopback(_canonical("2130706433")))

    def test_octal_ip_loopback(self):
        # 0177.0.0.1 (legacy octal) == 127.0.0.1
        self.assertEqual(_decode_alt_ip("0177.0.0.1"), "127.0.0.1")
        self.assertTrue(_is_loopback(_canonical("0177.0.0.1")))

    def test_hex_ip_loopback(self):
        # 0x7f000001 == 127.0.0.1
        self.assertEqual(_decode_alt_ip("0x7f000001"), "127.0.0.1")
        self.assertTrue(_is_loopback(_canonical("0x7f000001")))

    def test_octal_per_part(self):
        # 0177.00.00.01 — octal per part
        self.assertEqual(_decode_alt_ip("0177.00.00.01"), "127.0.0.1")

    def test_hex_per_part(self):
        # 0x7f.0x0.0x0.0x1 — hex per part
        self.assertEqual(_decode_alt_ip("0x7f.0x0.0x0.0x1"), "127.0.0.1")

    def test_full_quad_decimal(self):
        # 127.0.0.1 as full decimal
        self.assertEqual(_decode_alt_ip("127.0.0.1"), "127.0.0.1")

    def test_external_decimal_ip(self):
        # 0xC0A80101 == 192.168.1.1
        self.assertEqual(_decode_alt_ip("0xC0A80101"), "192.168.1.1")
        # Not loopback
        self.assertFalse(_is_loopback(_canonical("0xC0A80101")))

    def test_invalid_returns_none(self):
        # Random text is not a numeric IP
        self.assertIsNone(_decode_alt_ip("evil.com"))
        self.assertIsNone(_decode_alt_ip("not-an-ip"))

    def test_overflow_returns_none(self):
        # > 0xFFFFFFFF — invalid
        self.assertIsNone(_decode_alt_ip("4294967296"))  # 2^32
        self.assertIsNone(_decode_alt_ip("0x100000000"))


class HostOfNormalization(unittest.TestCase):
    """The URL parser must catch all bypass encodings."""

    def test_decimal_in_url(self):
        self.assertEqual(_host_of("http://2130706433/"), "127.0.0.1")
        self.assertEqual(_host_of("http://2130706433:8080/admin"), "127.0.0.1")

    def test_userinfo_stripped(self):
        # userinfo must NOT affect the host
        self.assertEqual(_host_of("http://attacker@target/"), "target")
        # And if the host is decimal, userinfo is irrelevant
        self.assertEqual(_host_of("http://attacker@2130706433/"), "127.0.0.1")

    def test_https_decimal(self):
        self.assertEqual(_host_of("https://0x7f000001/api"), "127.0.0.1")

    def test_bare_host(self):
        self.assertEqual(_host_of("2130706433"), "127.0.0.1")

    def test_normal_host_unchanged(self):
        self.assertEqual(_host_of("example.com"), "example.com")
        self.assertEqual(_host_of("api.example.com"), "api.example.com")
        self.assertEqual(_host_of("EXAMPLE.COM"), "example.com")

    def test_idn_passes_through(self):
        # ASCII hostname, no IDN
        self.assertEqual(_host_of("example.com"), "example.com")
        # Punycode label passes through
        self.assertEqual(_host_of("xn--bcher-kva.example.com"),
                         "xn--bcher-kva.example.com")


class LoopbackDetection(unittest.TestCase):

    def test_localhost(self):
        self.assertTrue(_is_loopback("localhost"))

    def test_ipv6_loopback(self):
        self.assertTrue(_is_loopback("::1"))

    def test_ipv4_loopback(self):
        self.assertTrue(_is_loopback("127.0.0.1"))
        self.assertTrue(_is_loopback("127.0.0.5"))

    def test_ipv4_mapped_loopback(self):
        # IPv4-mapped IPv6
        self.assertTrue(_is_loopback("::ffff:127.0.0.1"))

    def test_non_loopback(self):
        self.assertFalse(_is_loopback("8.8.8.8"))
        self.assertFalse(_is_loopback("example.com"))


if __name__ == "__main__":
    unittest.main()
