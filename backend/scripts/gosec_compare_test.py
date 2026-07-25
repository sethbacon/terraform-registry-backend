#!/usr/bin/env python3
"""
Regression test for gosec-compare.py's fingerprinting (#655).

Run with:
    python3 backend/scripts/gosec_compare_test.py

Standard library only (unittest) — no extra dependencies required.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parent / "gosec-compare.py"
_spec = importlib.util.spec_from_file_location("gosec_compare", _MODULE_PATH)
gosec_compare = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gosec_compare)


class FingerprintCollisionTest(unittest.TestCase):
    """
    Reproduces the proven collision from the current gosec-baseline.json:
    three distinct G104 findings in internal/mirror/upstream.go (lines 445,
    480, 539) share the same rule, file, and details, and their code snippets
    all start with the same two lines (`body, _ := io.ReadAll(resp.Body)` /
    `resp.Body.Close()`) but differ on the third line (a different error
    message per call site).
    """

    BASE_DIR = Path("/repo").resolve()

    def _issue(self, line: str, third_line: str) -> dict:
        return {
            "rule_id": "G104",
            "details": "Errors unhandled",
            "file": "/repo/internal/mirror/upstream.go",
            "line": line,
            "code": (
                f"{int(line) - 1}: \t\t\tbody, _ := io.ReadAll(resp.Body)\n"
                f"{line}: \t\t\tresp.Body.Close()\n"
                f"{int(line) + 1}: \t\t\t{third_line}\n"
            ),
        }

    def test_distinct_call_sites_get_distinct_fingerprints(self):
        finding_a = self._issue(
            "445",
            'return "", fmt.Errorf("v2 provider lookup failed with status %d: %s", resp.StatusCode, string(body))',
        )
        finding_b = self._issue(
            "480",
            'return "", fmt.Errorf("v2 provider-versions request failed with status %d: %s", resp.StatusCode, string(body))',
        )
        finding_c = self._issue(
            "539",
            'return nil, fmt.Errorf("v2 provider doc index request failed with status %d: %s", resp.StatusCode, string(body))',
        )

        fp_a = gosec_compare.fingerprint(finding_a, self.BASE_DIR)
        fp_b = gosec_compare.fingerprint(finding_b, self.BASE_DIR)
        fp_c = gosec_compare.fingerprint(finding_c, self.BASE_DIR)

        fingerprints = {fp_a, fp_b, fp_c}
        self.assertEqual(
            len(fingerprints),
            3,
            f"expected 3 distinct fingerprints for 3 distinct call sites, got {fingerprints}",
        )

    def test_same_call_site_still_matches_after_unrelated_line_drift(self):
        # The anchor must still ignore raw line numbers, so a finding at the
        # same call site keeps matching its baseline entry after unrelated
        # code earlier in the file shifts every line number down.
        original = self._issue(
            "539",
            'return nil, fmt.Errorf("v2 provider doc index request failed with status %d: %s", resp.StatusCode, string(body))',
        )
        shifted = self._issue(
            "545",
            'return nil, fmt.Errorf("v2 provider doc index request failed with status %d: %s", resp.StatusCode, string(body))',
        )

        self.assertEqual(
            gosec_compare.fingerprint(original, self.BASE_DIR),
            gosec_compare.fingerprint(shifted, self.BASE_DIR),
        )


if __name__ == "__main__":
    unittest.main()
