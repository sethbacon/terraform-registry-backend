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


if __name__ == "__main__":
    unittest.main(verbosity=2)
