#!/usr/bin/env python3
"""
Regression tests for gosec-compare.py: fingerprinting (#655) and the
vacuous-scan guard.

Run with:
    python3 backend/scripts/gosec_compare_test.py

Standard library only (unittest) — no extra dependencies required.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
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


class VacuousScanTest(unittest.TestCase):
    """A scan that analysed nothing must not read as a scan that found nothing.

    `gosec ... || true` discards gosec's exit code, so a run that failed to
    analyse anything reaches the comparator looking exactly like a clean repo:
    `"Issues": []`. Every step after that behaves correctly on an empty universe
    and the required check goes green having verified nothing.
    """

    def _write(self, payload: dict) -> str:
        path = Path(tempfile.mkdtemp()) / "gosec-results.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    def test_zero_files_scanned_is_not_clean(self):
        path = self._write({"Issues": [], "Stats": {"files": 0, "lines": 0}})
        problems = gosec_compare.scan_integrity_problems(path)
        self.assertTrue(problems, "a scan of 0 files must be reported as unusable")
        self.assertIn("files scanned", problems[0])

    def test_missing_stats_is_not_clean(self):
        path = self._write({"Issues": []})
        self.assertTrue(
            gosec_compare.scan_integrity_problems(path),
            "results with no Stats at all must be reported as unusable",
        )

    def test_go_compile_errors_make_the_finding_set_incomplete(self):
        path = self._write(
            {
                "Issues": [],
                "Stats": {"files": 248, "lines": 65750},
                "Golang errors": {
                    "internal/mirror": [{"error": "undefined: Foo"}],
                },
            }
        )
        problems = gosec_compare.scan_integrity_problems(path)
        self.assertTrue(problems, "packages that did not compile were not analysed")
        self.assertIn("internal/mirror", problems[0])

    def test_a_real_scan_is_not_flagged(self):
        path = self._write(
            {
                "Issues": [],
                "Stats": {"files": 248, "lines": 65750, "nosec": 173},
                "Golang errors": {},
            }
        )
        self.assertEqual(
            gosec_compare.scan_integrity_problems(path),
            [],
            "a genuine clean scan must still pass",
        )


class VacuousScanIsRejectedEndToEndTest(unittest.TestCase):
    """Run the script the way CI runs it.

    The unit tests above cover scan_integrity_problems() but not its CALL SITE:
    deleting the call from main() leaves every one of them green while the guard
    protects nothing. A tested function that nothing invokes is the same defect
    as an untested one, so this drives the actual entry point and asserts on the
    exit code CI branches on.
    """

    def _run(self, results: dict) -> subprocess.CompletedProcess:
        tmp = Path(tempfile.mkdtemp())
        (tmp / "results.json").write_text(json.dumps(results), encoding="utf-8")
        (tmp / "baseline.json").write_text(
            json.dumps({"Issues": [], "Stats": {"files": 248, "lines": 65750}}),
            encoding="utf-8",
        )
        return subprocess.run(
            [
                sys.executable, str(_MODULE_PATH),
                "--results", str(tmp / "results.json"),
                "--baseline", str(tmp / "baseline.json"),
                "--base-dir", str(tmp),
            ],
            capture_output=True, text=True,
        )

    def test_a_scan_of_nothing_exits_nonzero(self):
        proc = self._run({"Issues": [], "Stats": {"files": 0, "lines": 0}})
        self.assertNotEqual(
            proc.returncode, 0,
            "a gosec run that analysed 0 files must not exit 0:\n" + proc.stdout,
        )
        self.assertIn("did not produce a usable scan", proc.stdout)

    def test_a_real_clean_scan_still_exits_zero(self):
        proc = self._run(
            {"Issues": [], "Stats": {"files": 248, "lines": 65750}, "Golang errors": {}}
        )
        self.assertEqual(
            proc.returncode, 0,
            "a genuine clean scan must still pass:\n" + proc.stdout + proc.stderr,
        )


if __name__ == "__main__":
    unittest.main()
