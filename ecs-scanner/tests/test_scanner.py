#!/usr/bin/env python3
"""Offline unit tests for the ECS scanner's parsing and input validation."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ecs_ingress_scanner as scanner  # noqa: E402


class ParseDigOutputTests(unittest.TestCase):
    def test_extracts_status_valid_scope_and_ipv4_answers(self):
        output = """\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; CLIENT-SUBNET: 8.8.8.0/24/20
mask.apple-dns.net. 60 IN A 203.0.113.7
mask.apple-dns.net. 60 IN A 198.51.100.11
mask.apple-dns.net. 60 IN AAAA 2001:db8::1
"""

        status, scope, addresses = scanner.parse_dig_output(output)

        self.assertEqual(status, "NOERROR")
        self.assertEqual(scope, 20)
        self.assertEqual(addresses, ["203.0.113.7", "198.51.100.11"])

    def test_rejects_unusable_ecs_scope_without_discarding_answers(self):
        output = """\
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; CLIENT-SUBNET: 8.8.8.0/25/25
mask.apple-dns.net. 60 IN A 203.0.113.7
not an answer record
"""

        status, scope, addresses = scanner.parse_dig_output(output)

        self.assertEqual(status, "NOERROR")
        self.assertIsNone(scope)
        self.assertEqual(addresses, ["203.0.113.7"])


class InputPrefixValidationTests(unittest.TestCase):
    def write_input(self, directory, contents):
        path = Path(directory) / "prefixes.txt"
        path.write_text(contents)
        return path

    def test_accepts_sorted_unique_global_ipv4_24_prefixes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_input(directory, "1.1.1.0/24\n8.8.8.0/24\n")

            prefixes = list(scanner.iter_prefixes(path))

        self.assertEqual([str(prefix) for prefix in prefixes], ["1.1.1.0/24", "8.8.8.0/24"])

    def test_rejects_duplicate_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_input(directory, "1.1.1.0/24\n1.1.1.0/24\n")

            with self.assertRaisesRegex(ValueError, "sorted and unique"):
                list(scanner.iter_prefixes(path))

    def test_rejects_unsorted_prefixes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_input(directory, "8.8.8.0/24\n1.1.1.0/24\n")

            with self.assertRaisesRegex(ValueError, "sorted and unique"):
                list(scanner.iter_prefixes(path))

    def test_rejects_private_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_input(directory, "10.0.0.0/24\n")

            with self.assertRaisesRegex(ValueError, "not public IPv4 space"):
                list(scanner.iter_prefixes(path))


if __name__ == "__main__":
    unittest.main()
