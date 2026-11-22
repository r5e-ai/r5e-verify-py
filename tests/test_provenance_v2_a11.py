"""Conformance and unit tests for Amendment A11 (V1–V11 offline verifier rules)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from r5e_verify.a11 import (
    CATEGORY_CRYPTOGRAPHIC_PROOF,
    CATEGORY_INSTITUTIONAL_ASSERTION,
    CATEGORY_MECHANICAL_CHECK,
    CATEGORY_UNAVAILABLE_EVIDENCE,
    VALID_CATEGORIES,
    classify_finding,
    verify_provenance_bundle_a11,
)
from r5e_verify.provenance import verify_provenance_bundle

A11_CASES_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "r5e-spec"
    / "amendments"
    / "a11"
    / "cases"
)

FINDING_KEYS = ("layer", "subject", "check", "result", "code", "category", "about")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class AmendmentA11ConformanceTests(unittest.TestCase):
    def test_all_33_a11_conformance_cases(self) -> None:
        self.assertTrue(
            A11_CASES_DIR.is_dir(),
            f"A11 conformance cases directory not found: {A11_CASES_DIR}",
        )
        case_dirs = sorted(p for p in A11_CASES_DIR.iterdir() if p.is_dir())
        self.assertEqual(len(case_dirs), 33, f"Expected 33 A11 cases, found {len(case_dirs)}")

        for case_dir in case_dirs:
            with self.subTest(case=case_dir.name):
                bundle = _load_json(case_dir / "bundle.json")
                case_meta = _load_json(case_dir / "case.json")
                expected = _load_json(case_dir / "expected-report.json")

                report = verify_provenance_bundle_a11(
                    bundle,
                    trusted_profiles=case_meta.get("trustedProfiles") or (),
                    trusted_publishers=case_meta.get("trustedPublishers") or (),
                    trusted_roots=case_meta.get("trustedRoots"),
                    trusted_chain=case_meta.get("trustedChain"),
                    min_start_seq=case_meta.get("minStartSeq"),
                )

                self.assertEqual(report["format"], expected["format"])
                self.assertEqual(report["amendment"], expected["amendment"])

                if expected.get("baselineClean"):
                    self.assertTrue(
                        report["baselineClean"],
                        f"Baseline not clean for {case_dir.name}: "
                        f"{[f for f in report['findings'] if f['result'] != 'ok']}",
                    )
                    non_ok_baseline = [
                        f for f in report["findings"] if f["result"] != "ok"
                    ]
                    self.assertEqual(
                        non_ok_baseline,
                        [],
                        f"Unexpected non-ok baseline findings for {case_dir.name}: {non_ok_baseline}",
                    )

                self.assertEqual(
                    report["verdict"],
                    expected["verdict"],
                    f"Verdict mismatch for {case_dir.name}: "
                    f"got {report['verdict']!r}, expected {expected['verdict']!r}; "
                    f"a11Findings={report['a11Findings']}",
                )

                actual_findings = report["a11Findings"]
                for finding in actual_findings:
                    self.assertEqual(tuple(sorted(finding.keys())), tuple(sorted(FINDING_KEYS)))
                    self.assertIn(finding["category"], VALID_CATEGORIES)
                    self.assertEqual(classify_finding(finding), finding["category"])

                expected_findings = expected["expectedA11Findings"]
                for exp in expected_findings:
                    self.assertIn(
                        exp,
                        actual_findings,
                        f"Expected A11 finding missing for {case_dir.name}:\n"
                        f"  expected: {exp}\n"
                        f"  actual:   {actual_findings}",
                    )

                # No unexpected failed or incomplete A11 findings
                actual_non_ok = [f for f in actual_findings if f["result"] != "ok"]
                expected_non_ok = [f for f in expected_findings if f["result"] != "ok"]
                self.assertEqual(
                    actual_non_ok,
                    expected_non_ok,
                    f"Non-ok A11 findings mismatch for {case_dir.name}:\n"
                    f"  actual:   {actual_non_ok}\n"
                    f"  expected: {expected_non_ok}",
                )

    def test_classify_finding_categories(self) -> None:
        self.assertEqual(
            classify_finding(
                {
                    "layer": 2,
                    "subject": "evidence:sha256:" + "0" * 64,
                    "check": "basis_signatures",
                    "result": "failed",
                    "code": "basis_missing_counter_signature",
                    "about": None,
                }
            ),
            CATEGORY_MECHANICAL_CHECK,
        )
        self.assertEqual(
            classify_finding(
                {
                    "layer": 3,
                    "subject": "evidence:sha256:" + "0" * 64,
                    "check": "witness_receipt_binding",
                    "result": "failed",
                    "code": "witness_unpinned",
                    "about": None,
                }
            ),
            CATEGORY_CRYPTOGRAPHIC_PROOF,
        )
        self.assertEqual(
            classify_finding(
                {
                    "layer": 1,
                    "subject": "evidence:sha256:" + "0" * 64,
                    "check": "salted_content_ref",
                    "result": "incomplete",
                    "code": "unavailable_evidence",
                    "about": None,
                }
            ),
            CATEGORY_UNAVAILABLE_EVIDENCE,
        )
        self.assertEqual(
            classify_finding(
                {
                    "layer": 3,
                    "subject": "evidence:sha256:" + "0" * 64,
                    "check": "erasure_l2_proof",
                    "result": "ok",
                    "code": "ok",
                    "category": CATEGORY_INSTITUTIONAL_ASSERTION,
                    "about": None,
                }
            ),
            CATEGORY_INSTITUTIONAL_ASSERTION,
        )

    def test_baseline_report_shape_unchanged(self) -> None:
        case_dir = A11_CASES_DIR / "basis-person-two-signatures-valid"
        bundle = _load_json(case_dir / "bundle.json")
        case_meta = _load_json(case_dir / "case.json")
        baseline = verify_provenance_bundle(
            bundle,
            trusted_profiles=case_meta.get("trustedProfiles") or (),
            trusted_publishers=case_meta.get("trustedPublishers") or (),
            trusted_roots=case_meta.get("trustedRoots"),
            trusted_chain=case_meta.get("trustedChain"),
            min_start_seq=case_meta.get("minStartSeq"),
        )
        self.assertNotIn("amendment", baseline)
        self.assertNotIn("a11Findings", baseline)
        self.assertIn("format", baseline)
        self.assertIn("summary", baseline)
        self.assertIn("findings", baseline)


if __name__ == "__main__":
    unittest.main()
