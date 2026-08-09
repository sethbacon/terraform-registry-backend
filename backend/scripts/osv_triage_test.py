#!/usr/bin/env python3
"""Unit tests for osv_triage.py. Run: python3 scripts/osv_triage_test.py"""

import importlib.util
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location(
    "osv_triage", pathlib.Path(__file__).with_name("osv_triage.py")
)
osv_triage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(osv_triage)


def _result(pkg, version, ecosystem, vulns, source="backend/go.mod"):
    return {
        "results": [
            {
                "source": {"path": source},
                "packages": [
                    {
                        "package": {
                            "name": pkg,
                            "version": version,
                            "ecosystem": ecosystem,
                        },
                        "vulnerabilities": vulns,
                    }
                ],
            }
        ]
    }


class TriageTest(unittest.TestCase):
    def test_no_fixed_version_is_unfixable(self):
        """The real GO-2026-5932 / x/crypto shape: affected, but no fix yet."""
        data = _result(
            "golang.org/x/crypto",
            "0.54.0",
            "Go",
            [
                {
                    "id": "GO-2026-5932",
                    "affected": [
                        {
                            "package": {"name": "golang.org/x/crypto", "ecosystem": "Go"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                        }
                    ],
                }
            ],
        )
        fixable, unfixable = osv_triage.triage(data)
        self.assertEqual(fixable, [])
        self.assertEqual(len(unfixable), 1)
        self.assertEqual(unfixable[0]["id"], "GO-2026-5932")

    def test_fixed_version_is_fixable(self):
        data = _result(
            "example.com/lib",
            "1.0.0",
            "Go",
            [
                {
                    "id": "GO-0000-1",
                    "affected": [
                        {
                            "package": {"name": "example.com/lib", "ecosystem": "Go"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                                }
                            ],
                        }
                    ],
                }
            ],
        )
        fixable, unfixable = osv_triage.triage(data)
        self.assertEqual(unfixable, [])
        self.assertEqual(fixable[0]["fixed"], ["1.0.1"])

    def test_fix_for_a_different_package_does_not_count(self):
        """A multi-package advisory must not mark our package upgradable."""
        data = _result(
            "example.com/ours",
            "1.0.0",
            "Go",
            [
                {
                    "id": "GO-0000-2",
                    "affected": [
                        {
                            "package": {"name": "example.com/ours", "ecosystem": "Go"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                        },
                        {
                            "package": {"name": "example.com/other", "ecosystem": "Go"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        },
                    ],
                }
            ],
        )
        fixable, unfixable = osv_triage.triage(data)
        self.assertEqual(fixable, [])
        self.assertEqual(len(unfixable), 1)

    def test_mixed_findings_report_both(self):
        data = _result(
            "example.com/lib",
            "1.0.0",
            "Go",
            [
                {
                    "id": "GO-0000-3",
                    "affected": [
                        {
                            "package": {"name": "example.com/lib", "ecosystem": "Go"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "1.1.0"}],
                                }
                            ],
                        }
                    ],
                },
                {
                    "id": "GO-0000-4",
                    "affected": [
                        {
                            "package": {"name": "example.com/lib", "ecosystem": "Go"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                        }
                    ],
                },
            ],
        )
        fixable, unfixable = osv_triage.triage(data)
        self.assertEqual([e["id"] for e in fixable], ["GO-0000-3"])
        self.assertEqual([e["id"] for e in unfixable], ["GO-0000-4"])

    def test_clean_scan(self):
        fixable, unfixable = osv_triage.triage({"results": []})
        self.assertEqual((fixable, unfixable), ([], []))
        self.assertIn("No vulnerabilities reported", osv_triage.render([], []))


class IssueBodyTest(unittest.TestCase):
    """--issue-body and the exit status the weekly workflow gates on (#776).

    The weekly run used to file an issue for ANY finding, with a body that
    named none of them ("Please review the workflow logs") and pointed at logs
    that expire. An advisory with no published fix therefore reopened a fresh,
    contentless issue every week. Issue creation is now gated on this exit
    status and uses this file as the body, so both are asserted here.
    """

    def _run(self, argv):
        import contextlib
        import io as _io
        import sys

        old_argv = sys.argv
        sys.argv = ["osv_triage.py"] + argv
        buf = _io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                return osv_triage.main()
        finally:
            sys.argv = old_argv

    def _write(self, tmp, data):
        import json

        path = pathlib.Path(tmp) / "osv.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def test_unfixable_only_exits_zero_and_files_no_issue(self):
        """The exact shape of #776 — x/crypto with no published fix.

        Exit 0 is what stops the weekly issue from being filed at all. If this
        ever returns 1, the contentless-weekly-issue treadmill is back.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            results = self._write(
                tmp,
                _result(
                    "golang.org/x/crypto",
                    "0.54.0",
                    "Go",
                    [
                        {
                            "id": "GO-2026-5932",
                            "affected": [
                                {
                                    "package": {
                                        "name": "golang.org/x/crypto",
                                        "ecosystem": "Go",
                                    },
                                    "ranges": [{"events": [{"introduced": "0"}]}],
                                }
                            ],
                        }
                    ],
                ),
            )
            body = str(pathlib.Path(tmp) / "report.md")
            self.assertEqual(self._run([results, "--issue-body", body]), 0)
            # Still reported, just not as an issue.
            text = pathlib.Path(body).read_text(encoding="utf-8")
            self.assertIn("GO-2026-5932", text)
            self.assertIn("No fix available", text)

    def test_fixable_exits_one_and_body_names_the_upgrade(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            results = self._write(
                tmp,
                _result(
                    "golang.org/x/net",
                    "0.20.0",
                    "Go",
                    [
                        {
                            "id": "GO-0000-9",
                            "affected": [
                                {
                                    "package": {
                                        "name": "golang.org/x/net",
                                        "ecosystem": "Go",
                                    },
                                    "ranges": [
                                        {
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "0.23.0"},
                                            ]
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                ),
            )
            body = str(pathlib.Path(tmp) / "report.md")
            self.assertEqual(self._run([results, "--issue-body", body]), 1)
            text = pathlib.Path(body).read_text(encoding="utf-8")
            # The whole point of the change: the issue must stand on its own
            # once the workflow logs expire.
            for expected in ("GO-0000-9", "golang.org/x/net", "0.20.0", "0.23.0"):
                self.assertIn(expected, text)

    def test_missing_results_file_fails_closed_and_still_writes_a_body(self):
        """A scanner that produced no output is a failed scan, not a clean one.

        The body matters as much as the exit code here: the workflow reads it
        unconditionally when the exit status is non-zero, so not writing one
        would turn a scanner failure into a file-not-found crash in a later
        step instead of a report saying what went wrong.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            body = str(pathlib.Path(tmp) / "report.md")
            missing = str(pathlib.Path(tmp) / "nope.json")
            self.assertEqual(self._run([missing, "--issue-body", body]), 1)
            text = pathlib.Path(body).read_text(encoding="utf-8")
            self.assertIn("Could not triage", text)
            self.assertIn("not a clean one", text)

    def test_malformed_results_fail_closed_and_still_write_a_body(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            bad = pathlib.Path(tmp) / "osv.json"
            bad.write_text("{not json", encoding="utf-8")
            body = str(pathlib.Path(tmp) / "report.md")
            self.assertEqual(self._run([str(bad), "--issue-body", body]), 1)
            self.assertIn(
                "Could not triage", pathlib.Path(body).read_text(encoding="utf-8")
            )

    def test_issue_body_flag_is_optional(self):
        """The PR-gate invocation passes no --issue-body and must keep working."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            results = self._write(tmp, {"results": []})
            self.assertEqual(self._run([results]), 0)

    def test_issue_body_without_a_path_is_a_usage_error(self):
        self.assertEqual(self._run(["osv.json", "--issue-body"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
