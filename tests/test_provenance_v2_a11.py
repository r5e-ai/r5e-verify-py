"""Conformance, CLI, and unit tests for Amendment A11 (V1–V11 offline verifier rules)."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
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
from r5e_verify.cli import main as cli_main
from r5e_verify.provenance import verify_provenance_bundle

A11_CASES_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "r5e-spec"
    / "amendments"
    / "a11"
    / "cases"
)

BASELINE_CASES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "r5e-spec" / "cases"
)

FINDING_KEYS = ("about", "category", "check", "code", "layer", "result", "subject")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_cli(argv: list[str]) -> tuple[int, bytes, str]:
    stdout_buf = io.BytesIO()
    stderr_buf = io.StringIO()
    wrapper = io.TextIOWrapper(stdout_buf, encoding="utf-8")
    with redirect_stdout(wrapper), redirect_stderr(stderr_buf):
        code = cli_main(argv)
    wrapper.flush()
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


class AmendmentA11ConformanceTests(unittest.TestCase):
    def test_all_90_a11_conformance_cases(self) -> None:
        self.assertTrue(
            A11_CASES_DIR.is_dir(),
            f"A11 conformance cases directory not found: {A11_CASES_DIR}",
        )
        case_dirs = sorted(p for p in A11_CASES_DIR.iterdir() if p.is_dir())
        self.assertEqual(len(case_dirs), 90, f"Expected 90 A11 cases, found {len(case_dirs)}")

        for case_dir in case_dirs:
            with self.subTest(case=case_dir.name):
                bundle = _load_json(case_dir / "bundle.json")
                case_meta = _load_json(case_dir / "case.json")
                expected = _load_json(case_dir / "expected-report.json")
                mode = case_meta.get("mode", "a11")

                if mode == "baseline":
                    report = verify_provenance_bundle(
                        bundle,
                        trusted_profiles=case_meta.get("trustedProfiles") or (),
                        trusted_publishers=case_meta.get("trustedPublishers") or (),
                        trusted_roots=case_meta.get("trustedRoots"),
                        trusted_chain=case_meta.get("trustedChain"),
                        min_start_seq=case_meta.get("minStartSeq"),
                        mode="baseline",
                    )
                    self.assertEqual(report["format"], expected["format"])
                    self.assertNotIn("amendment", report)
                    self.assertNotIn("a11Findings", report)
                    baseline_summary = report["summary"]
                    baseline_clean = (
                        baseline_summary["failed"] == 0
                        and baseline_summary["incomplete"] == 0
                    )
                    self.assertEqual(
                        baseline_clean,
                        expected["baselineClean"],
                        f"Baseline clean mismatch for {case_dir.name}: "
                        f"{[f for f in report['findings'] if f['result'] != 'ok']}",
                    )
                    actual_verdict = (
                        "failed"
                        if baseline_summary["failed"] > 0
                        else ("incomplete" if baseline_summary["incomplete"] > 0 else "ok")
                    )
                    self.assertEqual(actual_verdict, expected["verdict"])
                    continue

                report = verify_provenance_bundle_a11(
                    bundle,
                    trusted_profiles=case_meta.get("trustedProfiles") or (),
                    trusted_publishers=case_meta.get("trustedPublishers") or (),
                    trusted_roots=case_meta.get("trustedRoots"),
                    trusted_chain=case_meta.get("trustedChain"),
                    min_start_seq=case_meta.get("minStartSeq"),
                    trusted_checkpoints=case_meta.get("trustedCheckpoints") or (),
                )

                self.assertEqual(report["format"], expected["format"])
                self.assertEqual(report["amendment"], expected["amendment"])

                baseline_summary = report["baseline"]["summary"]
                baseline_clean = (
                    baseline_summary["failed"] == 0
                    and baseline_summary["incomplete"] == 0
                )
                self.assertEqual(
                    baseline_clean,
                    expected["baselineClean"],
                    f"baselineClean mismatch for {case_dir.name}: "
                    f"got {baseline_clean}, expected {expected['baselineClean']}; "
                    f"non-ok baseline={[f for f in report['baseline']['findings'] if f['result'] != 'ok']}",
                )

                for bf in report["baseline"]["findings"]:
                    self.assertIn(bf["category"], VALID_CATEGORIES)

                self.assertEqual(
                    report["verdict"],
                    expected["verdict"],
                    f"Verdict mismatch for {case_dir.name}: "
                    f"got {report['verdict']!r}, expected {expected['verdict']!r}; "
                    f"a11Findings={report['a11Findings']}",
                )

                actual_findings = report["a11Findings"]
                for finding in actual_findings:
                    self.assertEqual(tuple(sorted(finding.keys())), FINDING_KEYS)
                    self.assertIn(finding["category"], VALID_CATEGORIES)
                    self.assertEqual(classify_finding(finding), finding["category"])

                self.assertEqual(
                    actual_findings,
                    expected["expectedA11Findings"],
                    f"Exact a11Findings mismatch for {case_dir.name}:\n"
                    f"  actual:   {actual_findings}\n"
                    f"  expected: {expected['expectedA11Findings']}",
                )

    def test_cli_enforces_a11_failures_and_checkpoint_pins(self) -> None:
        case_dir = A11_CASES_DIR / "basis-person-one-signature-rejected"
        meta = _load_json(case_dir / "case.json")
        argv = [str(case_dir / "bundle.json")]
        for p in meta.get("trustedProfiles") or ():
            argv.extend(["--trusted-profile", p])
        for pub in meta.get("trustedPublishers") or ():
            argv.extend(["--trusted-publisher", pub])
        if meta.get("trustedChain"):
            argv.extend(["--trusted-chain", meta["trustedChain"]])

        code, out_bytes, err_text = _run_cli(argv)
        self.assertEqual(code, 1, f"CLI must fail on A11 violation; stderr={err_text!r}")
        report = json.loads(out_bytes.decode("utf-8"))
        self.assertEqual(report["amendment"], "A11")
        self.assertEqual(report["verdict"], "failed")

        # Test repeatable --checkpoint SEQ=REF and SEQ:REF
        ckpt_dir = A11_CASES_DIR / "checkpoint-trusted-pin-catches-stripped-fork-rejected"
        ckpt_meta = _load_json(ckpt_dir / "case.json")
        pin = ckpt_meta["trustedCheckpoints"][0]
        for sep in ("=", ":"):
            ckpt_argv = [str(ckpt_dir / "bundle.json")]
            for p in ckpt_meta.get("trustedProfiles") or ():
                ckpt_argv.extend(["--trusted-profile", p])
            for pub in ckpt_meta.get("trustedPublishers") or ():
                ckpt_argv.extend(["--trusted-publisher", pub])
            if ckpt_meta.get("trustedChain"):
                ckpt_argv.extend(["--trusted-chain", ckpt_meta["trustedChain"]])
            ckpt_argv.extend(["--checkpoint", f"{pin['seq']}{sep}{pin['ref']}"])
            ckpt_code, ckpt_out, ckpt_err = _run_cli(ckpt_argv)
            self.assertEqual(ckpt_code, 1, f"CLI --checkpoint with {sep!r} failed: {ckpt_err!r}")
            ckpt_report = json.loads(ckpt_out.decode("utf-8"))
            self.assertEqual(ckpt_report["verdict"], "failed")
            self.assertTrue(
                any(
                    f["code"] == "checkpoint_fork_or_stale"
                    for f in ckpt_report["a11Findings"]
                )
            )

    def test_cli_preserves_baseline_report_shape_unchanged(self) -> None:
        base_case = BASELINE_CASES_DIR / "valid-single-record-ed25519"
        if not base_case.is_dir():
            self.skipTest("Baseline vectors directory not found")
        meta = _load_json(base_case / "case.json")
        argv = [str(base_case / "bundle.json")]
        for p in meta.get("trustedProfiles") or ():
            argv.extend(["--trusted-profile", p])
        for pub in meta.get("trustedPublishers") or ():
            argv.extend(["--trusted-publisher", pub])
        if meta.get("trustedChain"):
            argv.extend(["--trusted-chain", meta["trustedChain"]])
        for root in meta.get("trustedRoots") or ():
            argv.extend(["--trusted-root", root])
        code, out_bytes, err_text = _run_cli(argv)
        self.assertEqual(code, 0, f"Baseline CLI failed: {err_text!r}")
        report = json.loads(out_bytes.decode("utf-8"))
        self.assertNotIn("amendment", report)
        self.assertNotIn("a11Findings", report)
        self.assertEqual(report["format"], "r5e.provenance-verify-report/v2")
        self.assertEqual(report["summary"]["failed"], 0)

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
                    "code": "salted_content_omitted",
                    "about": None,
                }
            ),
            CATEGORY_UNAVAILABLE_EVIDENCE,
        )
        self.assertEqual(
            classify_finding(
                {
                    "layer": 2,
                    "subject": "evidence:sha256:" + "0" * 64,
                    "check": "profile",
                    "result": "incomplete",
                    "code": "profile_not_trusted",
                    "about": None,
                }
            ),
            CATEGORY_INSTITUTIONAL_ASSERTION,
        )
        self.assertEqual(
            classify_finding(
                {
                    "layer": 3,
                    "subject": "evidence:sha256:" + "0" * 64,
                    "check": "membership",
                    "result": "ok",
                    "code": "ok",
                    "about": None,
                }
            ),
            CATEGORY_CRYPTOGRAPHIC_PROOF,
        )

    def test_malformed_a11_inputs_do_not_crash(self) -> None:
        malformed_bundles: list[dict[str, Any]] = [
            {
                "format": "r5e.provenance-export/v2",
                "blobs": [],
                "keys": [],
                "records": [],
                "checkpoints": [],
                "manifests": [],
                "proofs": [],
                "pinnedCheckpoints": [{}],
            },
            {
                "format": "r5e.provenance-export/v2",
                "blobs": [],
                "keys": [],
                "records": [],
                "checkpoints": [],
                "manifests": [],
                "proofs": [],
                "unlockLog": [42],
            },
            {
                "format": "r5e.provenance-export/v2",
                "blobs": [],
                "keys": [],
                "records": [],
                "checkpoints": [],
                "manifests": [],
                "proofs": [],
                "witnessReceipts": {"bytes:sha256:" + "0" * 64: {"logIndex": 1.5}},
            },
        ]
        for mb in malformed_bundles:
            rep = verify_provenance_bundle_a11(mb)
            self.assertEqual(rep["verdict"], "failed")
            self.assertTrue(
                any(f["code"] == "malformed_bundle" for f in rep["baseline"]["findings"])
            )


if __name__ == "__main__":
    unittest.main()
