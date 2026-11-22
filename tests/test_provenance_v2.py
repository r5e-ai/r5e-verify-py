from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from r5e_verify.cli import main as cli_main
from r5e_verify.provenance import (
    BADGE_KIND,
    CHAIN_STARTED_KIND,
    CHECKPOINT_KIND,
    DEFINITION_PUBLISHED_KIND,
    DEPLOYMENT_KIND,
    DSSE_PAYLOAD_TYPE,
    ED25519_L,
    ED25519_SMALL_ORDER,
    ENDORSEMENT_KIND,
    EPOCH_SEAL_KIND,
    KIND_DEFINITION_FORMAT,
    MAX_SAFE_INT,
    P256_N,
    P384_N,
    PAYLOAD_DISPOSITION_KIND,
    PRINCIPAL_KIND,
    PROVENANCE_EPOCH_FORMAT,
    PROVENANCE_EXPORT_FORMAT,
    RETENTION_HOLD_KIND,
    RETENTION_HOLD_RELEASE_KIND,
    REVOCATION_KIND,
    ROOT_CHANGE_APPROVAL_KIND,
    ROOTS_CHANGED_KIND,
    SUCCESSION_KIND,
    TIMESTAMP_PATTERN,
    ProvenanceInputError,
    _load_base_definitions,
    _load_bundled_schemas,
    bytes_ref,
    canonical_json_bytes,
    compute_key_id,
    decode_base64,
    decode_strict_base64,
    dsse_pae,
    evidence_ref,
    is_admissible_public_key,
    json_eq,
    load_bundle_json,
    load_strict_json,
    merkle_root_for_events,
    parse_canonical_json,
    parse_definition_document,
    report_exit_code,
    verify_merkle_inclusion,
    verify_provenance_bundle,
    verify_record_envelope,
    verify_signature,
)

VECTORS_ROOT = Path(
    os.environ.get(
        "R5E_PROVENANCE_VECTORS_DIR",
        str(Path(__file__).resolve().parent.parent.parent / "r5e-spec"),
    )
)
BUNDLED_ROOT = Path(__file__).resolve().parent.parent / "r5e_verify" / "provenance_data"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class Ed25519Signer:
    def __init__(self, seed_byte: int = 1) -> None:
        self.priv = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
        self.pub = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        kid = compute_key_id("ed25519", self.pub)
        assert kid is not None
        self.keyid = kid
        self.alg = "ed25519"

    def key_entry(self) -> dict[str, Any]:
        return {"keyid": self.keyid, "algorithm": "ed25519", "bytes": b64(self.pub)}

    def sign(self, message: bytes) -> bytes:
        return self.priv.sign(message)


class EcSigner:
    def __init__(self, alg: str, private_value: int = 7) -> None:
        self.alg = alg
        if alg == "es256":
            curve = ec.SECP256R1()
            self.n = P256_N
            self.coord_len = 32
            self.hash_alg: hashes.HashAlgorithm = hashes.SHA256()
        elif alg == "es384":
            curve = ec.SECP384R1()
            self.n = P384_N
            self.coord_len = 48
            self.hash_alg = hashes.SHA384()
        else:
            raise ValueError(alg)
        self.priv = ec.derive_private_key(private_value, curve)
        self.pub = self.priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        kid = compute_key_id(alg, self.pub)
        assert kid is not None
        self.keyid = kid

    def key_entry(self) -> dict[str, Any]:
        return {"keyid": self.keyid, "algorithm": self.alg, "bytes": b64(self.pub)}

    def sign(self, message: bytes, *, high_s: bool = False) -> bytes:
        der = self.priv.sign(message, ec.ECDSA(self.hash_alg))
        r, s = decode_dss_signature(der)
        if high_s:
            if s <= self.n // 2:
                s = self.n - s
        else:
            if s > self.n // 2:
                s = self.n - s
        return r.to_bytes(self.coord_len, "big") + s.to_bytes(self.coord_len, "big")


class ProvenanceFixtureBuilder:
    """Helper to construct clean, self-contained Provenance v2 bundles for unit tests."""

    def __init__(self) -> None:
        _, _ = _load_base_definitions()
        defs_index = json.loads((BUNDLED_ROOT / "definitions" / "index.json").read_text())
        self.defs_index: dict[str, str] = defs_index
        self.issuer = Ed25519Signer(1)
        self.publisher = Ed25519Signer(2)
        self.sealer = Ed25519Signer(3)
        self.blobs: list[dict[str, Any]] = []
        self.keys: list[dict[str, Any]] = [
            self.issuer.key_entry(),
            self.publisher.key_entry(),
            self.sealer.key_entry(),
        ]
        self.records: list[dict[str, Any]] = []
        self.seals: list[str] = []
        self.proofs: list[dict[str, Any]] = []
        self.omissions: list[dict[str, Any]] = []

        self.policy_bytes = b"deployment-policy-v1"
        self.policy_ref = self.add_blob(self.policy_bytes)

    def add_blob(self, raw: bytes) -> str:
        r = bytes_ref(raw)
        if not any(b["ref"] == r for b in self.blobs):
            self.blobs.append({"ref": r, "base64": b64(raw)})
        return r

    def add_json_blob(self, obj: dict[str, Any]) -> str:
        return self.add_blob(canonical_json_bytes(obj))

    def make_profile(
        self,
        extra_schemas: dict[str, str] | None = None,
        policy_required: list[str] | None = None,
        issuer_keys: list[str] | None = None,
        sealer_keys: list[str] | None = None,
    ) -> str:
        schemas = dict(self.defs_index)
        if extra_schemas:
            schemas.update(extra_schemas)
        profile = {
            "format": "r5e.capture-profile/v2",
            "schemas": schemas,
            "authority": {
                "bindings": [
                    {
                        "streamPrefix": "urn:stream:",
                        "actorPrefixes": ["urn:actor:"],
                        "issuerKeys": issuer_keys or [self.issuer.keyid, self.publisher.keyid, self.sealer.keyid],
                        "sealerKeys": sealer_keys if sealer_keys is not None else [self.sealer.keyid],
                    }
                ],
                "checkpointKeys": [],
            },
            "durability": {
                "failureDomain": "local",
                "requiredPayloads": "submitted",
                "onFailure": "refuse",
            },
            "policyRequiredKinds": policy_required or [],
            "deploymentPolicyRef": self.policy_ref,
        }
        return self.add_json_blob(profile)

    def sign_record(
        self,
        payload: dict[str, Any],
        signers: list[Ed25519Signer | EcSigner] | None = None,
        *,
        raw_payload_override: bytes | None = None,
    ) -> str:
        actual_signers = signers or [self.issuer]
        raw_payload = (
            raw_payload_override
            if raw_payload_override is not None
            else canonical_json_bytes(payload)
        )
        msg = dsse_pae(DSSE_PAYLOAD_TYPE, raw_payload)
        sigs = [{"keyid": s.keyid, "sig": b64(s.sign(msg))} for s in actual_signers]
        r = evidence_ref(raw_payload)
        self.records.append(
            {
                "ref": r,
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE,
                    "payload": b64(raw_payload),
                    "signatures": sigs,
                },
            }
        )
        return r

    def add_publication(
        self,
        profile_ref: str,
        definitions: list[dict[str, str]],
        *,
        signer: Ed25519Signer | None = None,
        seq: int = 1,
        previous: str | None = None,
        stream: str = "urn:stream:pub",
    ) -> str:
        pub_signer = signer or self.publisher
        all_defs = list(definitions)
        pub_def_ref = self.defs_index[DEFINITION_PUBLISHED_KIND]
        if not any(d["kind"] == DEFINITION_PUBLISHED_KIND for d in all_defs):
            all_defs.append({"kind": DEFINITION_PUBLISHED_KIND, "definition": pub_def_ref})
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": pub_def_ref,
            "profileRef": profile_ref,
            "issuer": pub_signer.keyid,
            "actor": "urn:actor:pub",
            "stream": stream,
            "seq": seq,
            "previous": previous,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {"definitions": all_defs},
        }
        return self.sign_record(payload, [pub_signer])

    def bundle(self) -> dict[str, Any]:
        return {
            "format": PROVENANCE_EXPORT_FORMAT,
            "scope": {"query": {}, "at": []},
            "records": self.records,
            "blobs": self.blobs,
            "keys": self.keys,
            "seals": self.seals,
            "checkpoints": [],
            "proofs": self.proofs,
            "publicationProofs": [],
            "omissions": self.omissions,
        }


class ConformanceVectorTests(unittest.TestCase):
    def test_bundled_data_matches_vectors_byte_for_byte(self) -> None:
        if not VECTORS_ROOT.exists():
            self.skipTest("external provenance-vectors directory not present")
        for sub in ("schemas", "definitions"):
            ext_dir = VECTORS_ROOT / sub
            bun_dir = BUNDLED_ROOT / sub
            ext_files = sorted(p.relative_to(ext_dir) for p in ext_dir.rglob("*") if p.is_file())
            bun_files = sorted(p.relative_to(bun_dir) for p in bun_dir.rglob("*") if p.is_file())
            self.assertEqual(bun_files, ext_files)
            for rel in ext_files:
                self.assertEqual((bun_dir / rel).read_bytes(), (ext_dir / rel).read_bytes(), str(rel))

    def test_all_provenance_v2_conformance_cases(self) -> None:
        cases_dir = VECTORS_ROOT / "cases"
        self.assertTrue(cases_dir.is_dir(), f"missing {cases_dir}")
        case_dirs = sorted(p for p in cases_dir.iterdir() if p.is_dir())
        self.assertEqual(len(case_dirs), 162)

        with (
            patch("socket.socket", side_effect=AssertionError("network call forbidden")),
            patch("time.time", side_effect=AssertionError("clock call forbidden")),
        ):
            for cdir in case_dirs:
                with self.subTest(case=cdir.name):
                    meta = json.loads((cdir / "case.json").read_text("utf-8"))
                    bundle = load_bundle_json((cdir / "bundle.json").read_bytes())
                    expected = json.loads((cdir / "expected-report.json").read_text("utf-8"))
                    actual = verify_provenance_bundle(
                        bundle,
                        trusted_profiles=meta.get("trustedProfiles", []),
                        trusted_publishers=meta.get("trustedPublishers", []),
                        trusted_roots=meta.get("trustedRoots"),
                        trusted_chain=meta.get("trustedChain"),
                        min_start_seq=meta.get("minStartSeq"),
                    )
                    self.assertTrue(
                        json_eq(actual, expected),
                        f"{cdir.name} mismatch:\nexpected={json.dumps(expected, indent=2)}\n"
                        f"actual={json.dumps(actual, indent=2)}",
                    )
                    encoded = canonical_json_bytes(actual)
                    expected_encoded = canonical_json_bytes(expected)
                    self.assertEqual(
                        hashlib.sha256(encoded).hexdigest(),
                        hashlib.sha256(expected_encoded).hexdigest(),
                    )
                    self.assertTrue(json_eq(parse_canonical_json(encoded), actual))


class CanonicalJsonAndPrimitivesTests(unittest.TestCase):
    def test_canonical_json_escapes_unicode_and_limits(self) -> None:
        val = {
            "é": "café 😀 \x7f /",
            "a": "\b\t\n\f\r\"\\\x00\x1f",
            "max": MAX_SAFE_INT,
            "min": -MAX_SAFE_INT,
        }
        raw = canonical_json_bytes(val)
        expected = (
            b'{"a":"\\b\\t\\n\\f\\r\\"\\\\\\u0000\\u001f",'
            b'"max":9007199254740991,"min":-9007199254740991,'
            + '"é":"café 😀 \x7f /"}'.encode()
        )
        self.assertEqual(raw, expected)
        self.assertTrue(json_eq(parse_canonical_json(raw), val))

        for bad in (
            b'{"a":1,"a":2}',
            b'{"x":-0}',
            b'{"x":1.0}',
            b'{"x":1e2}',
            b'{"x":9007199254740992}',
            b'{"x":-9007199254740992}',
            '{"😀":1}'.encode(),
            b'{"a":"\\u000a"}',
            b'{"a":"\\u001F"}',
            b'{"b":1,"a":2}',
            b'{"a":1}\n',
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_canonical_json(bad)

        with self.assertRaises(ValueError):
            load_strict_json(b'{"dup":1,"dup":2}')
        with self.assertRaises(ValueError):
            load_strict_json(b"-0")

    def test_crypto_admissibility_and_low_s(self) -> None:
        for pt in ED25519_SMALL_ORDER:
            self.assertFalse(is_admissible_public_key("ed25519", pt))
            hi = pt[:31] + bytes([pt[31] | 0x80])
            self.assertFalse(is_admissible_public_key("ed25519", hi))
            self.assertIsNone(compute_key_id("ed25519", pt))

        # Off-curve Ed25519 y (find first y >= 2 not on curve)
        off_curve_found = False
        for candidate_y in range(2, 100):
            raw_y = candidate_y.to_bytes(32, "little")
            if not is_admissible_public_key("ed25519", raw_y):
                off_curve_found = True
                self.assertIsNone(compute_key_id("ed25519", raw_y))
                break
        self.assertTrue(off_curve_found)

        ed = Ed25519Signer(9)
        msg = b"test message"
        sig = ed.sign(msg)
        self.assertTrue(verify_signature("ed25519", ed.pub, sig, msg))
        malleable_s = (int.from_bytes(sig[32:], "little") + ED25519_L).to_bytes(32, "little")
        self.assertFalse(verify_signature("ed25519", ed.pub, sig[:32] + malleable_s, msg))

        for alg, order_n, clen in (("es256", P256_N, 32), ("es384", P384_N, 48)):
            ec_signer = EcSigner(alg, 11)
            low_sig = ec_signer.sign(msg, high_s=False)
            high_sig = ec_signer.sign(msg, high_s=True)
            self.assertTrue(verify_signature(alg, ec_signer.pub, low_sig, msg))
            self.assertFalse(verify_signature(alg, ec_signer.pub, high_sig, msg))
            self.assertFalse(verify_signature(alg, b"\x04" + b"\x00" * (2 * clen), low_sig, msg))
            zero_r = (0).to_bytes(clen, "big") + (1).to_bytes(clen, "big")
            n_r = order_n.to_bytes(clen, "big") + (1).to_bytes(clen, "big")
            self.assertFalse(verify_signature(alg, ec_signer.pub, zero_r, msg))
            self.assertFalse(verify_signature(alg, ec_signer.pub, n_r, msg))

    def test_base64_and_merkle_inclusion_exhaustive(self) -> None:
        self.assertEqual(decode_base64(""), b"")
        with self.assertRaises(ValueError):
            decode_strict_base64("")
        with self.assertRaises(ValueError):
            decode_base64("AB==")
        with self.assertRaises(ValueError):
            decode_strict_base64("AB==")

        for size in range(1, 18):
            refs = [
                "evidence:sha256:" + hashlib.sha256(f"rec-{i}".encode()).hexdigest()
                for i in range(size)
            ]
            root = merkle_root_for_events(refs)

            def build_proof(sub_refs: list[str], idx: int) -> list[str]:
                n = len(sub_refs)
                if n == 1:
                    return []
                k = 1 << ((n - 1).bit_length() - 1)
                if idx < k:
                    return build_proof(sub_refs[:k], idx) + [merkle_root_for_events(sub_refs[k:])]
                return build_proof(sub_refs[k:], idx - k) + [merkle_root_for_events(sub_refs[:k])]

            for idx in range(size):
                proof = build_proof(refs, idx)
                self.assertTrue(verify_merkle_inclusion(refs[idx], idx, size, proof, root))
                extra = proof + ["sha256:" + "0" * 64]
                self.assertFalse(verify_merkle_inclusion(refs[idx], idx, size, extra, root))
                if proof:
                    self.assertFalse(verify_merkle_inclusion(refs[idx], idx, size, proof[:-1], root))


class DefinitionSchemaAndSignersTests(unittest.TestCase):
    def _custom_bundle_with_def(
        self,
        def_doc: dict[str, Any],
        body: dict[str, Any],
        *,
        kind_path: str = "example.com/v1/Custom",
        signers: list[Ed25519Signer | EcSigner] | None = None,
    ) -> dict[str, Any]:
        fx = ProvenanceFixtureBuilder()
        def_ref = fx.add_json_blob(def_doc)
        extra_keys: list[str] = []
        if signers:
            for s in signers:
                if not any(k["keyid"] == s.keyid for k in fx.keys):
                    fx.keys.append(s.key_entry())
                extra_keys.append(s.keyid)
        prof_ref = fx.make_profile(
            extra_schemas={kind_path: def_ref},
            issuer_keys=[fx.issuer.keyid, fx.publisher.keyid] + extra_keys,
        )
        fx.add_publication(prof_ref, [{"kind": kind_path, "definition": def_ref}])
        api_version, kind = kind_path.rsplit("/", 1)
        rec_signers = signers or [fx.issuer]
        payload = {
            "apiVersion": api_version,
            "kind": kind,
            "schemaRef": def_ref,
            "profileRef": prof_ref,
            "issuer": rec_signers[0].keyid,
            "actor": "urn:actor:1",
            "stream": "urn:stream:1",
            "seq": 1,
            "previous": None,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": body,
        }
        fx.sign_record(payload, rec_signers)
        return verify_provenance_bundle(
            fx.bundle(),
            trusted_profiles=[prof_ref],
            trusted_publishers=[fx.publisher.keyid],
        )

    def test_key_bytes_and_derives_key_id_of(self) -> None:
        ec256 = EcSigner("es256", 21)
        valid_def = {
            "format": KIND_DEFINITION_FORMAT,
            "kind": "example.com/v1/Custom",
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["pubKey", "derivedId"],
                "properties": {
                    "pubKey": {
                        "type": "object",
                        "keyBytes": True,
                        "additionalProperties": False,
                        "required": ["algorithm", "bytes"],
                        "properties": {
                            "algorithm": {"type": "string"},
                            "bytes": {"type": "string"},
                        },
                    },
                    "derivedId": {
                        "type": "string",
                        "derives": {"keyIdOf": "pubKey"},
                    },
                },
            },
        }
        ok_report = self._custom_bundle_with_def(
            valid_def,
            {
                "pubKey": {"algorithm": "es256", "bytes": b64(ec256.pub)},
                "derivedId": ec256.keyid,
            },
        )
        self.assertEqual(ok_report["summary"]["failed"], 0)
        self.assertEqual(ok_report["summary"]["incomplete"], 0)

        # Wrong derived key id -> body_does_not_match_definition
        bad_id_report = self._custom_bundle_with_def(
            valid_def,
            {
                "pubKey": {"algorithm": "es256", "bytes": b64(ec256.pub)},
                "derivedId": "key:es256:sha256:" + "0" * 64,
            },
        )
        body_findings = [f for f in bad_id_report["findings"] if f["check"] == "body" and f["result"] == "failed"]
        self.assertEqual(len(body_findings), 1)
        self.assertEqual(body_findings[0]["code"], "body_does_not_match_definition")

        # Inadmissible key in keyBytes -> body_does_not_match_definition
        bad_key_report = self._custom_bundle_with_def(
            valid_def,
            {
                "pubKey": {"algorithm": "ed25519", "bytes": b64(b"\x00" * 32)},
                "derivedId": ec256.keyid,
            },
        )
        self.assertTrue(
            any(f["code"] == "body_does_not_match_definition" for f in bad_key_report["findings"])
        )

        # Non-canonical base64 in keyBytes -> body_does_not_match_definition
        noncanon_b64_report = self._custom_bundle_with_def(
            valid_def,
            {
                "pubKey": {"algorithm": "ed25519", "bytes": "AB=="},
                "derivedId": ec256.keyid,
            },
        )
        self.assertTrue(
            any(f["code"] == "body_does_not_match_definition" for f in noncanon_b64_report["findings"])
        )

        # Document faults for keyBytes and derives -> definition_not_available (None from parser)
        faulty_defs = [
            # keyBytes: false
            {
                "format": KIND_DEFINITION_FORMAT,
                "kind": "example.com/v1/Custom",
                "schema": {
                    "keyBytes": False,
                    "required": ["algorithm", "bytes"],
                    "properties": {"algorithm": {"type": "string"}, "bytes": {"type": "string"}},
                },
            },
            # keyBytes missing required bytes
            {
                "format": KIND_DEFINITION_FORMAT,
                "kind": "example.com/v1/Custom",
                "schema": {
                    "keyBytes": True,
                    "required": ["algorithm"],
                    "properties": {"algorithm": {"type": "string"}, "bytes": {"type": "string"}},
                },
            },
            # derives referencing optional (non-required) keyBytes sibling
            {
                "format": KIND_DEFINITION_FORMAT,
                "kind": "example.com/v1/Custom",
                "schema": {
                    "required": ["derivedId"],
                    "properties": {
                        "pubKey": {
                            "keyBytes": True,
                            "required": ["algorithm", "bytes"],
                            "properties": {
                                "algorithm": {"type": "string"},
                                "bytes": {"type": "string"},
                            },
                        },
                        "derivedId": {"type": "string", "derives": {"keyIdOf": "pubKey"}},
                    },
                },
            },
        ]
        for fd in faulty_defs:
            self.assertIsNone(parse_definition_document(canonical_json_bytes(fd)))

    def test_three_signers_matches_signer_1_nested_and_unfit_definitions(self) -> None:
        s1, s2, s3 = Ed25519Signer(10), Ed25519Signer(11), EcSigner("es256", 12)
        three_sig_def = {
            "format": KIND_DEFINITION_FORMAT,
            "kind": "example.com/v1/Custom",
            "signatures": 3,
            "schema": {
                "type": "object",
                "required": ["second", "third"],
                "properties": {
                    "firstEcho": {"type": "string", "matchesSigner": 1},
                    "second": {"type": "string", "matchesSigner": 2},
                    "third": {"type": "string", "matchesSigner": 3},
                    "nested": {
                        "type": "object",
                        "properties": {
                            "confirmSecond": {"type": "string", "matchesSigner": 2}
                        },
                    },
                },
            },
        }
        ok_rep = self._custom_bundle_with_def(
            three_sig_def,
            {
                "firstEcho": s1.keyid,
                "second": s2.keyid,
                "third": s3.keyid,
                "nested": {"confirmSecond": s2.keyid},
            },
            signers=[s1, s2, s3],
        )
        self.assertEqual(ok_rep["summary"]["failed"], 0)
        self.assertEqual(ok_rep["summary"]["incomplete"], 0)

        # Nested matchesSigner mismatch -> body_does_not_match_definition
        bad_nested = self._custom_bundle_with_def(
            three_sig_def,
            {
                "firstEcho": s1.keyid,
                "second": s2.keyid,
                "third": s3.keyid,
                "nested": {"confirmSecond": s3.keyid},
            },
            signers=[s1, s2, s3],
        )
        self.assertTrue(
            any(f["code"] == "body_does_not_match_definition" for f in bad_nested["findings"])
        )

        # matchesSigner: 1 mismatch -> body_does_not_match_definition
        bad_first = self._custom_bundle_with_def(
            three_sig_def,
            {
                "firstEcho": s2.keyid,
                "second": s2.keyid,
                "third": s3.keyid,
            },
            signers=[s1, s2, s3],
        )
        self.assertTrue(
            any(f["code"] == "body_does_not_match_definition" for f in bad_first["findings"])
        )

        # Unfit: matchesSigner: 2 when signatures == 1 -> definition_not_available
        unfit_above_count = {
            "format": KIND_DEFINITION_FORMAT,
            "kind": "example.com/v1/Custom",
            "signatures": 1,
            "schema": {
                "required": ["s2"],
                "properties": {"s2": {"type": "string", "matchesSigner": 2}},
            },
        }
        self.assertIsNone(parse_definition_document(canonical_json_bytes(unfit_above_count)))

    def test_body_schema_keywords_ordered_timestamps_and_calendar_validation(self) -> None:
        rich_def = {
            "format": KIND_DEFINITION_FORMAT,
            "kind": "example.com/v1/Custom",
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["mode", "count", "tsStart", "tsEnd", "targetRef"],
                "nonEmpty": ["tags", "meta", "label"],
                "ordered": [["minVal", "maxVal"], ["tsStart", "tsEnd"]],
                "exactlyOne": [["optA", "optB"]],
                "atMostOne": [["flag1", "flag2"]],
                "requires": [{"when": {"field": "mode", "equals": "strict"}, "then": ["reason"]}],
                "properties": {
                    "mode": {"type": "string", "enum": ["strict", "lenient"]},
                    "reason": {"type": "string", "pattern": "^because-.+$"},
                    "label": {"type": "string"},
                    "count": {"type": "integer", "minimum": 1, "maximum": 10},
                    "minVal": {"type": "integer"},
                    "maxVal": {"type": "integer"},
                    "tsStart": {"type": "string", "pattern": TIMESTAMP_PATTERN},
                    "tsEnd": {"type": "string", "pattern": TIMESTAMP_PATTERN},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "meta": {"type": "object", "values": {"type": ["string", "boolean"]}},
                    "optA": {"type": "boolean"},
                    "optB": {"type": "boolean"},
                    "flag1": {"type": "integer"},
                    "flag2": {"type": "integer"},
                    "targetRef": {
                        "type": "ref",
                        "ref": {"anyOf": [{"bytes": True}, {"event": True}]},
                    },
                },
            },
        }
        base_body = {
            "mode": "strict",
            "reason": "because-test",
            "label": "ok",
            "count": 5,
            "minVal": -10,
            "maxVal": 0,
            # 10:00:00+02:00 is 08:00:00Z, which is <= 09:00:00Z!
            "tsStart": "2026-05-01T10:00:00+02:00",
            "tsEnd": "2026-05-01T09:00:00Z",
            "tags": ["x"],
            "meta": {"k1": "v1", "k2": True},
            "optA": True,
            "flag1": 0,
            "targetRef": "event:sha256:" + "a" * 64,
        }
        ok_rep = self._custom_bundle_with_def(rich_def, base_body)
        self.assertEqual(ok_rep["summary"]["failed"], 0)

        mutations = [
            # ordered timestamp out of order across offsets (11:00+02:00 = 09:00Z > 08:59Z)
            {**base_body, "tsStart": "2026-05-01T11:00:00+02:00", "tsEnd": "2026-05-01T08:59:59Z"},
            # calendar invalid date Feb 29 on non-leap year 2026
            {**base_body, "tsStart": "2026-02-29T00:00:00Z"},
            # pattern with trailing newline rejected by $ -> \Z
            {**base_body, "reason": "because-test\n"},
            # enum mismatch
            {**base_body, "mode": "other"},
            # maximum violated
            {**base_body, "count": 11},
            # nonEmpty violated by []
            {**base_body, "tags": []},
            # nonEmpty violated by {}
            {**base_body, "meta": {}},
            # nonEmpty violated by ""
            {**base_body, "label": ""},
            # ordered integers violated
            {**base_body, "minVal": 5, "maxVal": 4},
            # exactlyOne violated (both present)
            {**base_body, "optB": False},
            # atMostOne violated
            {**base_body, "flag2": 1},
            # requires violated (mode == strict without reason)
            {k: v for k, v in base_body.items() if k != "reason"},
            # wrong type (bool for integer)
            {**base_body, "count": True},
        ]
        for idx, bad_body in enumerate(mutations):
            with self.subTest(mutation=idx):
                rep = self._custom_bundle_with_def(rich_def, bad_body)
                self.assertTrue(
                    any(f["code"] == "body_does_not_match_definition" for f in rep["findings"]),
                    f"mutation {idx} did not fail with body_does_not_match_definition: {rep}",
                )


class UnpinnedCodesAndEdgeCasesTests(unittest.TestCase):
    def test_invalid_base64_and_conflicting_or_unreadable_key(self) -> None:
        fx = ProvenanceFixtureBuilder()
        prof_ref = fx.make_profile()
        obs_def = fx.defs_index["provenance.r5e.io/v2/Observation"]
        fx.add_publication(prof_ref, [{"kind": "provenance.r5e.io/v2/Observation", "definition": obs_def}])

        # 1. Blob with unused non-zero pad bits AB== -> content_hash: invalid_base64
        bad_blob_ref = "bytes:sha256:" + "1" * 64
        fx.blobs.append({"ref": bad_blob_ref, "base64": "AB=="})

        # 2. Key with AB== -> conflicting_or_unreadable_key, plus conflicting duplicate keyid
        other_signer = Ed25519Signer(44)
        fx.keys.append({"keyid": other_signer.keyid, "algorithm": "ed25519", "bytes": "AB=="})
        fx.keys.append({"keyid": fx.issuer.keyid, "algorithm": "ed25519", "bytes": b64(other_signer.pub)})

        # 3. Record with AB== in payload -> identity: invalid_base64
        bad_rec_ref = "evidence:sha256:" + "2" * 64
        fx.records.append(
            {
                "ref": bad_rec_ref,
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE,
                    "payload": "AB==",
                    "signatures": [{"keyid": fx.issuer.keyid, "sig": "AA=="}],
                },
            }
        )

        rep = verify_provenance_bundle(
            fx.bundle(),
            trusted_profiles=[prof_ref],
            trusted_publishers=[fx.publisher.keyid],
        )
        codes = {(f["layer"], f["check"], f["code"]) for f in rep["findings"]}
        self.assertIn((2, "content_hash", "invalid_base64"), codes)
        self.assertIn((1, "key", "conflicting_or_unreadable_key"), codes)
        self.assertIn((1, "identity", "invalid_base64"), codes)

    def test_layer1_malformed_envelope_non_object_and_issuer_mismatch(self) -> None:
        schemas = _load_bundled_schemas()
        rec_ref = "evidence:sha256:" + "3" * 64
        opened, finding = verify_record_envelope(rec_ref, {"payloadType": "wrong"}, schemas["signed-evidence.schema.json"])
        self.assertIsNone(opened)
        self.assertEqual(finding["code"], "malformed_envelope")

        # payload_not_an_object (canonical JSON array `[]`)
        fx = ProvenanceFixtureBuilder()
        arr_bytes = b"[]"
        arr_ref = evidence_ref(arr_bytes)
        fx.records.append(
            {
                "ref": arr_ref,
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE,
                    "payload": b64(arr_bytes),
                    "signatures": [{"keyid": fx.issuer.keyid, "sig": b64(fx.issuer.sign(dsse_pae(DSSE_PAYLOAD_TYPE, arr_bytes)))}],
                },
            }
        )
        # issuer_is_not_signer
        obj_bytes = canonical_json_bytes({"issuer": fx.publisher.keyid})
        obj_ref = evidence_ref(obj_bytes)
        fx.records.append(
            {
                "ref": obj_ref,
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE,
                    "payload": b64(obj_bytes),
                    "signatures": [{"keyid": fx.issuer.keyid, "sig": b64(fx.issuer.sign(dsse_pae(DSSE_PAYLOAD_TYPE, obj_bytes)))}],
                },
            }
        )
        rep = verify_provenance_bundle(fx.bundle())
        codes = {f["code"] for f in rep["findings"]}
        self.assertIn("payload_not_an_object", codes)
        self.assertIn("issuer_is_not_signer", codes)

    def test_causes_session_and_profile_edge_codes(self) -> None:
        fx = ProvenanceFixtureBuilder()
        prof_ref = fx.make_profile()
        obs_def = fx.defs_index["provenance.r5e.io/v2/Observation"]

        # 1. causes_not_sorted_and_unique (unique items out of byte order)
        c_b = "evidence:sha256:" + "b" * 64
        c_a = "evidence:sha256:" + "a" * 64
        fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_def,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:1",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "causes": [c_b, c_a],
                "body": {"event": "ping"},
            }
        )

        # 2. session_differs_from_body on SessionOpened and SessionClosed (using self-contained test definitions)
        custom_sess_open_def = fx.add_json_blob(
            {
                "format": KIND_DEFINITION_FORMAT,
                "kind": "provenance.r5e.io/v2/SessionOpened",
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["session"],
                    "properties": {"session": {"type": "string"}},
                },
            }
        )
        custom_sess_close_def = fx.add_json_blob(
            {
                "format": KIND_DEFINITION_FORMAT,
                "kind": "provenance.r5e.io/v2/SessionClosed",
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["session"],
                    "properties": {"session": {"type": "string"}},
                },
            }
        )
        fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "SessionOpened",
                "schemaRef": custom_sess_open_def,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:2",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "session": "urn:session:outer",
                "body": {"session": "urn:session:inner"},
            }
        )
        fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "SessionClosed",
                "schemaRef": custom_sess_close_def,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:2b",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "session": "urn:session:outer",
                "body": {"session": "urn:session:inner"},
            }
        )

        # 3. profile_not_available & unreadable_profile
        missing_prof = "bytes:sha256:" + "9" * 64
        bad_prof_bytes = b'{"not":"a valid capture profile"}'
        bad_prof_ref = fx.add_blob(bad_prof_bytes)

        fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_def,
                "profileRef": missing_prof,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:3",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {"event": "x"},
            }
        )
        fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_def,
                "profileRef": bad_prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:4",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {"event": "y"},
            }
        )

        rep = verify_provenance_bundle(fx.bundle(), trusted_profiles=[prof_ref])
        codes = {f["code"] for f in rep["findings"]}
        self.assertIn("causes_not_sorted_and_unique", codes)
        self.assertIn("session_differs_from_body", codes)
        self.assertIn("profile_not_available", codes)
        self.assertIn("unreadable_profile", codes)

    def test_layer3_seal_epoch_and_membership_edge_codes(self) -> None:
        fx = ProvenanceFixtureBuilder()
        prof_ref = fx.make_profile()
        obs_def = fx.defs_index["provenance.r5e.io/v2/Observation"]
        seal_def = fx.defs_index[EPOCH_SEAL_KIND]

        r1 = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_def,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:s1",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {"event": "e1"},
            }
        )
        # Second stream starting at seq 2 (with previousSeal on seal, unconstrained first previous in §7)
        r_s2 = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_def,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:s2",
                "seq": 2,
                "previous": "evidence:sha256:" + "f" * 64,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {"event": "e2"},
            }
        )
        m_s2_ref = fx.add_json_blob({"format": PROVENANCE_EPOCH_FORMAT, "events": [r_s2]})
        seal_s2 = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": seal_def,
                "profileRef": prof_ref,
                "issuer": fx.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:seals",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "stream": "urn:stream:s2",
                    "firstSeq": 2,
                    "lastSeq": 2,
                    "root": merkle_root_for_events([r_s2]),
                    "manifestRef": m_s2_ref,
                    "previousSeal": "evidence:sha256:" + "e" * 64,
                },
            },
            [fx.sealer],
        )

        # Unreadable manifest seal
        bad_m_ref = fx.add_blob(b'{"bad":true}')
        seal_bad_m = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": seal_def,
                "profileRef": prof_ref,
                "issuer": fx.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:seals",
                "seq": 2,
                "previous": seal_s2,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "stream": "urn:stream:s1",
                    "firstSeq": 1,
                    "lastSeq": 1,
                    "root": merkle_root_for_events([r1]),
                    "manifestRef": bad_m_ref,
                },
            },
            [fx.sealer],
        )

        # Uncarried covered record seal
        m_missing_ev = fx.add_json_blob(
            {"format": PROVENANCE_EPOCH_FORMAT, "events": ["evidence:sha256:" + "d" * 64]}
        )
        seal_missing_ev = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": seal_def,
                "profileRef": prof_ref,
                "issuer": fx.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:seals",
                "seq": 3,
                "previous": seal_bad_m,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "stream": "urn:stream:s1",
                    "firstSeq": 1,
                    "lastSeq": 1,
                    "root": "sha256:" + "0" * 64,
                    "manifestRef": m_missing_ev,
                },
            },
            [fx.sealer],
        )

        # Epoch range length mismatch, stream mismatch, sequence mismatch, previous mismatch
        m_r1 = fx.add_json_blob({"format": PROVENANCE_EPOCH_FORMAT, "events": [r1]})
        seal_range_err = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": seal_def,
                "profileRef": prof_ref,
                "issuer": fx.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:seals",
                "seq": 4,
                "previous": seal_missing_ev,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "stream": "urn:stream:s1",
                    "firstSeq": 1,
                    "lastSeq": 2,
                    "root": merkle_root_for_events([r1]),
                    "manifestRef": m_r1,
                },
            },
            [fx.sealer],
        )
        seal_stream_err = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": seal_def,
                "profileRef": prof_ref,
                "issuer": fx.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:seals",
                "seq": 5,
                "previous": seal_range_err,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "stream": "urn:stream:wrong",
                    "firstSeq": 1,
                    "lastSeq": 1,
                    "root": merkle_root_for_events([r1]),
                    "manifestRef": m_r1,
                },
            },
            [fx.sealer],
        )
        seal_seq_err = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": seal_def,
                "profileRef": prof_ref,
                "issuer": fx.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:seals",
                "seq": 6,
                "previous": seal_stream_err,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "stream": "urn:stream:s1",
                    "firstSeq": 2,
                    "lastSeq": 2,
                    "root": merkle_root_for_events([r1]),
                    "manifestRef": m_r1,
                },
            },
            [fx.sealer],
        )

        # epoch_previous: second event in manifest has wrong previous
        r1_b = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_def,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:s1",
                "seq": 2,
                "previous": "evidence:sha256:" + "c" * 64,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {"event": "e1b"},
            }
        )
        m_prev_err = fx.add_json_blob({"format": PROVENANCE_EPOCH_FORMAT, "events": [r1, r1_b]})
        seal_prev_err = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": seal_def,
                "profileRef": prof_ref,
                "issuer": fx.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:seals",
                "seq": 7,
                "previous": seal_seq_err,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "stream": "urn:stream:s1",
                    "firstSeq": 1,
                    "lastSeq": 2,
                    "root": merkle_root_for_events([r1, r1_b]),
                    "manifestRef": m_prev_err,
                },
            },
            [fx.sealer],
        )

        uncarried_seal = "evidence:sha256:" + "7" * 64
        fx.seals.extend(
            [
                uncarried_seal,
                r1,  # not an EpochSeal
                seal_s2,  # valid second seal
                seal_bad_m,
                seal_missing_ev,
                seal_range_err,
                seal_stream_err,
                seal_seq_err,
                seal_prev_err,
            ]
        )

        # Proofs: uncarried seal/record & proof_does_not_reach_root (extra sibling on 1-leaf seal_s2)
        fx.proofs.append({"record": r_s2, "seal": uncarried_seal, "index": 0, "siblings": []})
        fx.proofs.append(
            {"record": r_s2, "seal": seal_s2, "index": 0, "siblings": ["sha256:" + "0" * 64]}
        )

        rep = verify_provenance_bundle(fx.bundle(), trusted_profiles=[prof_ref])
        layer3 = [(f["subject"], f["check"], f["result"], f["code"], f["about"]) for f in rep["findings"] if f["layer"] == 3]
        codes = {x[3] for x in layer3}
        for expected_code in (
            "seal_record_not_carried",
            "not_an_epoch_seal",
            "unreadable_manifest",
            "not_every_covered_record_is_carried",
            "epoch_range_length",
            "epoch_stream",
            "epoch_sequence",
            "epoch_previous",
            "seal_or_record_not_carried",
            "proof_does_not_reach_root",
        ):
            self.assertIn(expected_code, codes)
        # Second seal of stream (seq:2-2) succeeded:
        self.assertIn((seal_s2, "epoch", "ok", "ok", "seq:2-2"), layer3)

    def test_publications_multiple_documents_and_bad_publication_signature(self) -> None:
        fx = ProvenanceFixtureBuilder()
        prof_ref = fx.make_profile()
        obs_def = fx.defs_index["provenance.r5e.io/v2/Observation"]
        alt_def = "bytes:sha256:" + "5" * 64

        # Two valid publications from same trusted publisher for Observation
        pub1 = fx.add_publication(
            prof_ref,
            [{"kind": "provenance.r5e.io/v2/Observation", "definition": alt_def}],
            seq=1,
            stream="urn:stream:pubs",
        )
        pub2 = fx.add_publication(
            prof_ref,
            [{"kind": "provenance.r5e.io/v2/Observation", "definition": obs_def}],
            seq=2,
            previous=pub1,
            stream="urn:stream:pubs",
        )

        # Forged publication with bad signature (must state nothing)
        forged_def = fx.defs_index[DEFINITION_PUBLISHED_KIND]
        forged_payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": forged_def,
            "profileRef": prof_ref,
            "issuer": fx.publisher.keyid,
            "actor": "urn:actor:pub",
            "stream": "urn:stream:forged",
            "seq": 1,
            "previous": None,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {
                "definitions": [
                    {"kind": "provenance.r5e.io/v2/ToolCall", "definition": fx.defs_index["provenance.r5e.io/v2/ToolCall"]}
                ]
            },
        }
        forged_bytes = canonical_json_bytes(forged_payload)
        fx.records.append(
            {
                "ref": evidence_ref(forged_bytes),
                "envelope": {
                    "payloadType": DSSE_PAYLOAD_TYPE,
                    "payload": b64(forged_bytes),
                    "signatures": [{"keyid": fx.publisher.keyid, "sig": b64(b"\x00" * 64)}],
                },
            }
        )

        obs_rec = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": obs_def,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:obs",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {"event": "hello"},
            }
        )
        tc_rec = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "ToolCall",
                "schemaRef": fx.defs_index["provenance.r5e.io/v2/ToolCall"],
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:tc",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {"tool": "echo"},
            }
        )

        rep = verify_provenance_bundle(
            fx.bundle(),
            trusted_profiles=[prof_ref],
            trusted_publishers=[fx.publisher.keyid],
        )
        obs_pub = next(
            f for f in rep["findings"] if f["subject"] == obs_rec and f["check"] == "publication"
        )
        self.assertEqual(obs_pub["result"], "ok")
        self.assertEqual(obs_pub["about"], pub2)

        tc_pub = next(
            f for f in rep["findings"] if f["subject"] == tc_rec and f["check"] == "publication"
        )
        self.assertEqual(tc_pub["result"], "incomplete")
        self.assertEqual(tc_pub["code"], "publication_not_carried")

        # Stranger DefinitionPublished beside a trusted publication gets incomplete /
        # publisher_not_trusted with about = its own ref, without consulting the table (§6.2a),
        # even when its body omits DefinitionPublished itself.
        stranger_pub_signer = Ed25519Signer(99)
        fx.keys.append(stranger_pub_signer.key_entry())
        stranger_pub_ref = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "DefinitionPublished",
                "schemaRef": forged_def,
                "profileRef": prof_ref,
                "issuer": stranger_pub_signer.keyid,
                "actor": "urn:actor:stranger-pub",
                "stream": "urn:stream:stranger-pub",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T00:00:00Z",
                "body": {
                    "definitions": [
                        {"kind": "provenance.r5e.io/v2/Observation", "definition": obs_def}
                    ]
                },
            },
            [stranger_pub_signer],
        )
        rep_with_stranger = verify_provenance_bundle(
            fx.bundle(),
            trusted_profiles=[prof_ref],
            trusted_publishers=[fx.publisher.keyid],
        )
        stranger_pub_finding = next(
            f
            for f in rep_with_stranger["findings"]
            if f["subject"] == stranger_pub_ref and f["check"] == "publication"
        )
        self.assertEqual(stranger_pub_finding["result"], "incomplete")
        self.assertEqual(stranger_pub_finding["code"], "publisher_not_trusted")
        self.assertEqual(stranger_pub_finding["about"], stranger_pub_ref)


class CliProvenanceTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> tuple[int, bytes, str]:
        out_buf = io.BytesIO()
        err_buf = io.StringIO()

        class _FakeStdout:
            buffer = out_buf

        with patch("sys.stdout", _FakeStdout()), patch("sys.stderr", err_buf):
            code = cli_main(argv)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_cli_exit_codes_0_1_2_3_allow_incomplete_and_definitions_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ext_def = {
                "format": KIND_DEFINITION_FORMAT,
                "kind": "ext.example.io/v1/Note",
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["text"],
                    "properties": {"text": {"type": "string"}},
                },
            }
            ext_def_bytes = canonical_json_bytes(ext_def)
            ext_def_ref = bytes_ref(ext_def_bytes)

            defs_dir = tmp_path / "defs"
            defs_dir.mkdir()
            (defs_dir / "Note.json").write_bytes(ext_def_bytes)

            fx = ProvenanceFixtureBuilder()
            obs_def_ref = fx.defs_index["provenance.r5e.io/v2/Observation"]
            prof_ref = fx.make_profile(extra_schemas={"ext.example.io/v1/Note": ext_def_ref})
            fx.add_publication(
                prof_ref,
                [{"kind": "provenance.r5e.io/v2/Observation", "definition": obs_def_ref}],
            )
            note_rec = fx.sign_record(
                {
                    "apiVersion": "ext.example.io/v1",
                    "kind": "Note",
                    "schemaRef": ext_def_ref,
                    "profileRef": prof_ref,
                    "issuer": fx.issuer.keyid,
                    "actor": "urn:actor:1",
                    "stream": "urn:stream:1",
                    "seq": 1,
                    "previous": None,
                    "capturedAt": "2026-11-10T00:00:00Z",
                    "body": {"text": "via definitions-dir"},
                }
            )
            bundle_file = tmp_path / "bundle.json"
            bundle_file.write_text(json.dumps(fx.bundle(), indent=2))

            # Without --definitions-dir -> Note body is definition_not_available, exit 3
            code, out, err = self._run_cli([str(bundle_file)])
            self.assertEqual(code, 3)
            self.assertEqual(err, "")
            parsed = parse_canonical_json(out)
            self.assertEqual(parsed["summary"]["failed"], 0)
            self.assertGreater(parsed["summary"]["incomplete"], 0)
            note_body_before = next(
                f for f in parsed["findings"] if f["subject"] == note_rec and f["check"] == "body"
            )
            self.assertEqual(note_body_before["code"], "definition_not_available")

            # With --definitions-dir -> Note body becomes ok (and --allow-incomplete exits 0)
            code, out_defs, _ = self._run_cli(
                [str(bundle_file), "--definitions-dir", str(defs_dir), "--allow-incomplete"]
            )
            self.assertEqual(code, 0)
            parsed_defs = parse_canonical_json(out_defs)
            note_body_after = next(
                f for f in parsed_defs["findings"] if f["subject"] == note_rec and f["check"] == "body"
            )
            self.assertEqual(note_body_after["result"], "ok")
            self.assertEqual(note_body_after["about"], "ext.example.io/v1/Note")

            # Fully established bundle (carried definition + trusted profile + trusted publisher) -> exit 0 without --allow-incomplete
            fx_est = ProvenanceFixtureBuilder()
            carried_def_ref = fx_est.add_blob(ext_def_bytes)
            est_prof = fx_est.make_profile(extra_schemas={"ext.example.io/v1/Note": carried_def_ref})
            fx_est.add_publication(
                est_prof,
                [{"kind": "ext.example.io/v1/Note", "definition": carried_def_ref}],
            )
            fx_est.sign_record(
                {
                    "apiVersion": "ext.example.io/v1",
                    "kind": "Note",
                    "schemaRef": carried_def_ref,
                    "profileRef": est_prof,
                    "issuer": fx_est.issuer.keyid,
                    "actor": "urn:actor:1",
                    "stream": "urn:stream:1",
                    "seq": 1,
                    "previous": None,
                    "capturedAt": "2026-11-10T00:00:00Z",
                    "body": {"text": "ready"},
                }
            )
            est_file = tmp_path / "established.json"
            est_file.write_text(json.dumps(fx_est.bundle(), indent=2))
            code, out_est, _ = self._run_cli(
                [
                    str(est_file),
                    "--trusted-profile",
                    est_prof,
                    "--trusted-publisher",
                    fx_est.publisher.keyid,
                ]
            )
            self.assertEqual(code, 0)
            rep_est = parse_canonical_json(out_est)
            self.assertEqual(rep_est["summary"]["failed"], 0)
            self.assertEqual(rep_est["summary"]["incomplete"], 0)

            # Failed bundle -> exit 1 even with --allow-incomplete
            bad_bundle = tmp_path / "bad.json"
            bad_bundle.write_text('{"format":"wrong"}')
            code, out_bad, _ = self._run_cli([str(bad_bundle), "--allow-incomplete"])
            self.assertEqual(code, 1)
            rep_bad = parse_canonical_json(out_bad)
            self.assertEqual(rep_bad["findings"][0]["code"], "malformed_bundle")
            self.assertEqual(report_exit_code(rep_bad, allow_incomplete=True), 1)

            # Unreadable / invalid JSON / missing file / bad flags -> exit 2
            not_json = tmp_path / "broken.json"
            not_json.write_text("{not valid json")
            code, _, err = self._run_cli([str(not_json)])
            self.assertEqual(code, 2)
            self.assertIn("recurse_verify:", err)

            code, _, err = self._run_cli(["provenance", str(tmp_path / "missing.json")])
            self.assertEqual(code, 2)

            code, _, err = self._run_cli([str(bundle_file), "--definitions-dir", str(tmp_path / "nope")])
            self.assertEqual(code, 2)

            code, _, err = self._run_cli(["provenance", str(bundle_file), "--unknown"])
            self.assertEqual(code, 2)
            self.assertIn("usage:", err)

    def test_cli_over_all_conformance_cases(self) -> None:
        cases_dir = VECTORS_ROOT / "cases"
        self.assertTrue(cases_dir.is_dir())
        case_dirs = sorted(p for p in cases_dir.iterdir() if p.is_dir())
        self.assertEqual(len(case_dirs), 162)
        for cdir in case_dirs:
            with self.subTest(case=cdir.name):
                meta = json.loads((cdir / "case.json").read_text("utf-8"))
                expected = json.loads((cdir / "expected-report.json").read_text("utf-8"))
                argv = [str(cdir / "bundle.json")]
                for prof in meta.get("trustedProfiles", []):
                    argv.extend(["--trusted-profile", prof])
                for pub in meta.get("trustedPublishers", []):
                    argv.extend(["--trusted-publisher", pub])
                roots = meta.get("trustedRoots")
                if isinstance(roots, list):
                    if roots:
                        for rt in roots:
                            argv.extend(["--trusted-root", rt])
                    else:
                        argv.append("--establish-authority")
                chain = meta.get("trustedChain")
                if chain is not None:
                    argv.extend(["--trusted-chain", chain])
                min_seq = meta.get("minStartSeq")
                if min_seq is not None:
                    argv.extend(["--min-start-seq", str(min_seq)])
                code, out, err = self._run_cli(argv)
                self.assertEqual(err, "")
                actual = parse_canonical_json(out)
                self.assertTrue(json_eq(actual, expected))
                self.assertEqual(code, report_exit_code(expected))
                if code == 3:
                    code_inc, _, _ = self._run_cli(argv + ["--allow-incomplete"])
                    self.assertEqual(code_inc, 0)

    def test_cli_trusted_root_and_establish_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = Ed25519Signer(40)
            worker = Ed25519Signer(41)
            fx = ProvenanceFixtureBuilder()
            for s in (root, worker):
                fx.keys.append(s.key_entry())
            obs_kind = "provenance.r5e.io/v2/Observation"
            end_kind = ENDORSEMENT_KIND
            prof_ref = fx.make_profile(
                issuer_keys=[root.keyid, worker.keyid, fx.publisher.keyid],
            )
            pub_ref = fx.add_publication(
                prof_ref,
                [
                    {"kind": obs_kind, "definition": fx.defs_index[obs_kind]},
                    {"kind": end_kind, "definition": fx.defs_index[end_kind]},
                ],
            )
            fx.sign_record(
                {
                    "apiVersion": "provenance.r5e.io/v2",
                    "kind": "Endorsement",
                    "schemaRef": fx.defs_index[end_kind],
                    "profileRef": prof_ref,
                    "issuer": root.keyid,
                    "actor": "urn:actor:root",
                    "stream": "urn:stream:auth",
                    "seq": 1,
                    "previous": None,
                    "capturedAt": "2026-11-10T01:00:00Z",
                    "body": {
                        "subject": worker.keyid,
                        "kinds": [obs_kind],
                        "mayEndorse": True,
                        "notBefore": "2026-11-10T00:00:00Z",
                        "notAfter": "2026-11-10T10:00:00Z",
                    },
                },
                [root],
            )
            obs_ref = fx.sign_record(
                {
                    "apiVersion": "provenance.r5e.io/v2",
                    "kind": "Observation",
                    "schemaRef": fx.defs_index[obs_kind],
                    "profileRef": prof_ref,
                    "issuer": worker.keyid,
                    "actor": "urn:actor:worker",
                    "stream": "urn:stream:work",
                    "seq": 1,
                    "previous": None,
                    "capturedAt": "2026-11-10T02:00:00Z",
                    "body": {"topic": "ping", "contentRefs": []},
                },
                [worker],
            )
            bundle_file = tmp_path / "a5_bundle.json"
            bundle_file.write_text(json.dumps(fx.bundle()))

            # Without --trusted-root / --establish-authority -> §6.3 profile_not_trusted (exit 3),
            # including on DefinitionPublished itself.
            code, out_prof, _ = self._run_cli([str(bundle_file)])
            self.assertEqual(code, 3)
            rep_prof = parse_canonical_json(out_prof)
            obs_auth_prof = next(
                f for f in rep_prof["findings"] if f["subject"] == obs_ref and f["check"] == "authority"
            )
            pub_auth_prof = next(
                f for f in rep_prof["findings"] if f["subject"] == pub_ref and f["check"] == "authority"
            )
            self.assertEqual(obs_auth_prof["code"], "profile_not_trusted")
            self.assertEqual(pub_auth_prof["code"], "profile_not_trusted")

            # With --establish-authority (empty trustedRoots=[]) -> no_standing on Endorsement,
            # not_covered on Observation, and NO authority finding on DefinitionPublished (§6.3a / A5 §1).
            code_empty, out_empty, _ = self._run_cli([str(bundle_file), "--establish-authority"])
            self.assertEqual(code_empty, 1)
            rep_empty = parse_canonical_json(out_empty)
            obs_auth_empty = next(
                f for f in rep_empty["findings"] if f["subject"] == obs_ref and f["check"] == "authority"
            )
            self.assertEqual(obs_auth_empty["code"], "not_covered")
            self.assertFalse(
                any(
                    f["subject"] == pub_ref and f["check"] == "authority"
                    for f in rep_empty["findings"]
                )
            )

            # With --trusted-root + --trusted-publisher -> fully established (exit 0) with no
            # authority finding on DefinitionPublished even though publisher is outside root's chain.
            code_ok, out_ok, _ = self._run_cli(
                [
                    str(bundle_file),
                    f"--trusted-root={root.keyid}",
                    "--trusted-publisher",
                    fx.publisher.keyid,
                ]
            )
            self.assertEqual(code_ok, 0)
            rep_ok = parse_canonical_json(out_ok)
            self.assertEqual(rep_ok["summary"]["failed"], 0)
            self.assertEqual(rep_ok["summary"]["incomplete"], 0)
            self.assertFalse(
                any(
                    f["subject"] == pub_ref and f["check"] == "authority"
                    for f in rep_ok["findings"]
                )
            )


class _A5Harness:
    """Self-contained helper for constructing Amendment A5 authority-walk bundles."""

    def __init__(self) -> None:
        self.fx = ProvenanceFixtureBuilder()
        self._stream_seq: dict[str, tuple[int, str | None]] = {}
        self.signers_by_id: dict[str, Ed25519Signer] = {}
        self._next_seed = 50
        self.prof_ref = ""

    def new_signer(self) -> Ed25519Signer:
        s = Ed25519Signer(self._next_seed)
        self._next_seed += 1
        self.signers_by_id[s.keyid] = s
        if not any(k["keyid"] == s.keyid for k in self.fx.keys):
            self.fx.keys.append(s.key_entry())
        return s

    def finalize_profile(self) -> str:
        all_kids = [k["keyid"] for k in self.fx.keys]
        self.prof_ref = self.fx.make_profile(issuer_keys=all_kids, sealer_keys=all_kids)
        return self.prof_ref

    def _next_pos(self, stream: str) -> tuple[int, str | None]:
        return self._stream_seq.get(stream, (1, None))

    def _record_pos(self, stream: str, seq: int, ref: str) -> None:
        self._stream_seq[stream] = (seq + 1, ref)

    def add_endorsement(
        self,
        issuer: Ed25519Signer,
        subject: Ed25519Signer,
        *,
        captured_at: str = "2026-11-10T01:00:00Z",
        kinds: list[str] | None = None,
        may_endorse: bool = True,
        not_before: str = "2026-11-10T00:00:00Z",
        not_after: str = "2026-11-10T23:00:00Z",
        parent: str | None = None,
        stream_prefixes: list[str] | None = None,
        actor_prefixes: list[str] | None = None,
        acts_for: str | None = None,
        stream: str = "urn:stream:auth",
    ) -> str:
        seq, prev = self._next_pos(stream)
        body: dict[str, Any] = {
            "subject": subject.keyid,
            "kinds": kinds or ["provenance.r5e.io/v2/Observation", EPOCH_SEAL_KIND],
            "mayEndorse": may_endorse,
            "notBefore": not_before,
            "notAfter": not_after,
        }
        if parent is not None:
            body["parent"] = parent
        if stream_prefixes is not None:
            body["streamPrefixes"] = stream_prefixes
        if actor_prefixes is not None:
            body["actorPrefixes"] = actor_prefixes
        if acts_for is not None:
            body["actsFor"] = acts_for
        ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Endorsement",
                "schemaRef": self.fx.defs_index[ENDORSEMENT_KIND],
                "profileRef": self.prof_ref,
                "issuer": issuer.keyid,
                "actor": "urn:actor:admin",
                "stream": stream,
                "seq": seq,
                "previous": prev,
                "capturedAt": captured_at,
                "body": body,
            },
            [issuer],
        )
        self._record_pos(stream, seq, ref)
        return ref

    def add_badge(
        self,
        issuer: Ed25519Signer,
        subject: Ed25519Signer,
        parent: str,
        *,
        captured_at: str = "2026-11-10T02:00:00Z",
        kinds: list[str] | None = None,
        not_before: str = "2026-11-10T01:00:00Z",
        not_after: str = "2026-11-10T20:00:00Z",
        stream_prefixes: list[str] | None = None,
        actor_prefixes: list[str] | None = None,
        acts_for: str | None = None,
        stream: str = "urn:stream:auth",
        corrupt_second_sig: bool = False,
    ) -> str:
        seq, prev = self._next_pos(stream)
        body: dict[str, Any] = {
            "subject": subject.keyid,
            "subjectKey": {"algorithm": "ed25519", "bytes": b64(subject.pub)},
            "holder": "worker",
            "kinds": kinds or ["provenance.r5e.io/v2/Observation"],
            "notBefore": not_before,
            "notAfter": not_after,
            "parent": parent,
        }
        if stream_prefixes is not None:
            body["streamPrefixes"] = stream_prefixes
        if actor_prefixes is not None:
            body["actorPrefixes"] = actor_prefixes
        if acts_for is not None:
            body["actsFor"] = acts_for
        ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Badge",
                "schemaRef": self.fx.defs_index[BADGE_KIND],
                "profileRef": self.prof_ref,
                "issuer": issuer.keyid,
                "actor": "urn:actor:gateway",
                "stream": stream,
                "seq": seq,
                "previous": prev,
                "capturedAt": captured_at,
                "body": body,
            },
            [issuer, subject],
        )
        if corrupt_second_sig:
            self.fx.records[-1]["envelope"]["signatures"][1]["sig"] = b64(b"\x00" * 64)
        self._record_pos(stream, seq, ref)
        return ref

    def add_succession(
        self,
        pred: Ed25519Signer,
        succ: Ed25519Signer,
        *,
        captured_at: str = "2026-11-10T05:00:00Z",
        stream: str = "urn:stream:succ",
    ) -> str:
        seq, prev = self._next_pos(stream)
        ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Succession",
                "schemaRef": self.fx.defs_index[SUCCESSION_KIND],
                "profileRef": self.prof_ref,
                "issuer": pred.keyid,
                "actor": "urn:actor:keyholder",
                "stream": stream,
                "seq": seq,
                "previous": prev,
                "capturedAt": captured_at,
                "body": {
                    "predecessor": pred.keyid,
                    "successor": succ.keyid,
                    "successorKey": {"algorithm": "ed25519", "bytes": b64(succ.pub)},
                },
            },
            [pred, succ],
        )
        self._record_pos(stream, seq, ref)
        return ref

    def add_revocation(
        self,
        issuer: Ed25519Signer,
        target: str,
        *,
        captured_at: str = "2026-11-10T06:00:00Z",
        stream: str = "urn:stream:rev",
    ) -> str:
        seq, prev = self._next_pos(stream)
        ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Revocation",
                "schemaRef": self.fx.defs_index[REVOCATION_KIND],
                "profileRef": self.prof_ref,
                "issuer": issuer.keyid,
                "actor": "urn:actor:revoker",
                "stream": stream,
                "seq": seq,
                "previous": prev,
                "capturedAt": captured_at,
                "body": {"target": target},
            },
            [issuer],
        )
        self._record_pos(stream, seq, ref)
        return ref

    def add_principal(
        self,
        signer: Ed25519Signer,
        *,
        captured_at: str = "2026-11-10T00:30:00Z",
        stream: str = "urn:stream:prin",
    ) -> str:
        seq, prev = self._next_pos(stream)
        ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Principal",
                "schemaRef": self.fx.defs_index[PRINCIPAL_KIND],
                "profileRef": self.prof_ref,
                "issuer": signer.keyid,
                "actor": "urn:actor:prin",
                "stream": stream,
                "seq": seq,
                "previous": prev,
                "capturedAt": captured_at,
                "body": {
                    "key": signer.keyid,
                    "publicKey": {"algorithm": "ed25519", "bytes": b64(signer.pub)},
                    "holder": "operator",
                },
            },
            [signer],
        )
        self._record_pos(stream, seq, ref)
        return ref

    def add_observation(
        self,
        issuer: Ed25519Signer,
        *,
        captured_at: str = "2026-11-10T03:00:00Z",
        stream: str = "urn:stream:work",
        actor: str = "urn:actor:worker",
        on_behalf_of: str | None = None,
        profile_ref: str | None = None,
    ) -> str:
        seq, prev = self._next_pos(stream)
        payload: dict[str, Any] = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": self.fx.defs_index["provenance.r5e.io/v2/Observation"],
            "profileRef": profile_ref or self.prof_ref,
            "issuer": issuer.keyid,
            "actor": actor,
            "stream": stream,
            "seq": seq,
            "previous": prev,
            "capturedAt": captured_at,
            "body": {"topic": "obs", "contentRefs": []},
        }
        if on_behalf_of is not None:
            payload["onBehalfOf"] = on_behalf_of
        ref = self.fx.sign_record(payload, [issuer])
        self._record_pos(stream, seq, ref)
        return ref

    def add_epoch_seal(
        self,
        sealer: Ed25519Signer,
        sealed_stream: str,
        events: list[str],
        *,
        first_seq: int = 1,
        previous_seal: str | None = None,
        captured_at: str = "2026-11-10T04:00:00Z",
        seal_stream: str = "urn:stream:seals",
    ) -> str:
        last_seq = first_seq + len(events) - 1
        manifest_ref = self.fx.add_json_blob(
            {"format": PROVENANCE_EPOCH_FORMAT, "events": events}
        )
        root = merkle_root_for_events(events)
        seq, prev = self._next_pos(seal_stream)
        seal_body: dict[str, Any] = {
            "stream": sealed_stream,
            "firstSeq": first_seq,
            "lastSeq": last_seq,
            "root": root,
            "manifestRef": manifest_ref,
        }
        if previous_seal is not None:
            seal_body["previousSeal"] = previous_seal
        seal_ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": self.fx.defs_index[EPOCH_SEAL_KIND],
                "profileRef": self.prof_ref,
                "issuer": sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": seal_stream,
                "seq": seq,
                "previous": prev,
                "capturedAt": captured_at,
                "body": seal_body,
            },
            [sealer],
        )
        self._record_pos(seal_stream, seq, seal_ref)
        self.fx.seals.append(seal_ref)
        return seal_ref

    def add_membership_seal(
        self,
        sealer: Ed25519Signer,
        sealed_stream: str,
        rec_ref: str,
        *,
        first_seq: int = 1,
        captured_at: str = "2026-11-10T04:00:00Z",
        seal_stream: str = "urn:stream:seals-mem",
    ) -> str:
        """Add an EpochSeal without manifest blob, proving coverage solely via bundle.proofs."""
        uncarried_manifest = "bytes:sha256:" + "d" * 64
        root = merkle_root_for_events([rec_ref])
        seq, prev = self._next_pos(seal_stream)
        seal_ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": self.fx.defs_index[EPOCH_SEAL_KIND],
                "profileRef": self.prof_ref,
                "issuer": sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": seal_stream,
                "seq": seq,
                "previous": prev,
                "capturedAt": captured_at,
                "body": {
                    "stream": sealed_stream,
                    "firstSeq": first_seq,
                    "lastSeq": first_seq,
                    "root": root,
                    "manifestRef": uncarried_manifest,
                },
            },
            [sealer],
        )
        self._record_pos(seal_stream, seq, seal_ref)
        self.fx.proofs.append(
            {"record": rec_ref, "seal": seal_ref, "index": 0, "siblings": []}
        )
        return seal_ref


class AuthorityWalkA5Tests(unittest.TestCase):
    @staticmethod
    def _auth_by_subject(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            f["subject"]: f for f in report["findings"] if f["check"] == "authority"
        }

    def test_a5_link_narrowing_may_endorse_self_endorsement_and_principal_omission(self) -> None:
        h = _A5Harness()
        root = h.new_signer()
        mid = h.new_signer()
        non_endorsing = h.new_signer()
        worker = h.new_signer()
        leaf_extra = h.new_signer()
        stranger = h.new_signer()
        h.finalize_profile()

        prin_ref = h.add_principal(root)
        # Parentless endorsement by stranger -> no_standing
        stranger_root_end = h.add_endorsement(stranger, worker, stream="urn:stream:s1")
        # Self-endorsement by root (parentless) and by stranger (parentless)
        root_self_end = h.add_endorsement(root, root, stream="urn:stream:s2")
        stranger_self_end = h.add_endorsement(stranger, stranger, stream="urn:stream:s3")
        stranger_obs = h.add_observation(stranger, stream="urn:stream:s4")
        root_obs_without_grant = h.add_observation(root, stream="urn:stream:s5")

        # Valid L0 to mid (mayEndorse=True) and L0_no_endorse to non_endorsing (mayEndorse=False)
        l0_mid = h.add_endorsement(
            root,
            mid,
            kinds=["provenance.r5e.io/v2/Observation"],
            not_before="2026-11-10T01:00:00Z",
            not_after="2026-11-10T10:00:00Z",
            may_endorse=True,
            stream="urn:stream:a1",
        )
        l0_leaf = h.add_endorsement(
            root,
            non_endorsing,
            kinds=["provenance.r5e.io/v2/Observation"],
            may_endorse=False,
            stream="urn:stream:a2",
        )

        # Mid self-endorsement with parent -> not_covered
        mid_self = h.add_endorsement(mid, mid, parent=l0_mid, stream="urn:stream:a3")
        # Badge issued by non-endorsing key -> not_covered
        bad_badge_no_endorse = h.add_badge(
            non_endorsing, worker, l0_leaf, stream="urn:stream:a4"
        )
        # Child naming extra kind parent did not grant -> not_covered
        bad_child_kind = h.add_endorsement(
            mid,
            worker,
            parent=l0_mid,
            kinds=["provenance.r5e.io/v2/Observation", "provenance.r5e.io/v2/ToolCall"],
            not_before="2026-11-10T02:00:00Z",
            not_after="2026-11-10T09:00:00Z",
            stream="urn:stream:a5",
        )
        # Child with wider window -> not_covered
        bad_child_window = h.add_endorsement(
            mid,
            worker,
            parent=l0_mid,
            kinds=["provenance.r5e.io/v2/Observation"],
            not_before="2026-11-10T02:00:00Z",
            not_after="2026-11-10T11:00:00Z",
            stream="urn:stream:a6",
        )
        # Child issued outside parent's window (§4.6) -> not_covered
        bad_child_issued_late = h.add_endorsement(
            mid,
            worker,
            parent=l0_mid,
            captured_at="2026-11-10T12:00:00Z",
            kinds=["provenance.r5e.io/v2/Observation"],
            not_before="2026-11-10T02:00:00Z",
            not_after="2026-11-10T09:00:00Z",
            stream="urn:stream:a7",
        )
        # Valid badge under l0_mid, plus an invalid child trying to extend a Badge (§4.3)
        good_badge = h.add_badge(
            mid,
            worker,
            l0_mid,
            captured_at="2026-11-10T02:00:00Z",
            not_before="2026-11-10T02:00:00Z",
            not_after="2026-11-10T09:00:00Z",
            stream="urn:stream:a8",
        )
        child_under_badge = h.add_endorsement(
            worker,
            leaf_extra,
            parent=good_badge,
            captured_at="2026-11-10T03:00:00Z",
            not_before="2026-11-10T03:00:00Z",
            not_after="2026-11-10T08:00:00Z",
            stream="urn:stream:a9",
        )
        # Record with missing profile blob still gets authority finding under §6.3a
        missing_prof = "bytes:sha256:" + "f" * 64
        obs_missing_prof = h.add_observation(
            worker,
            captured_at="2026-11-10T04:00:00Z",
            profile_ref=missing_prof,
            stream="urn:stream:w1",
        )
        pub_ref = h.fx.add_publication(
            h.prof_ref,
            [
                {
                    "kind": "provenance.r5e.io/v2/Observation",
                    "definition": h.fx.defs_index["provenance.r5e.io/v2/Observation"],
                }
            ],
            stream="urn:stream:pub1",
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[root.keyid])
        auth = self._auth_by_subject(rep)

        self.assertNotIn(prin_ref, auth)
        self.assertNotIn(pub_ref, auth)
        rep_no_roots = verify_provenance_bundle(
            h.fx.bundle(), trusted_profiles=[h.prof_ref], trusted_roots=None
        )
        auth_no_roots = self._auth_by_subject(rep_no_roots)
        self.assertEqual(auth_no_roots[prin_ref]["code"], "ok")
        self.assertEqual(auth_no_roots[pub_ref]["code"], "ok")
        self.assertEqual(auth[stranger_root_end]["code"], "no_standing")
        self.assertEqual(auth[root_self_end]["code"], "not_covered")
        self.assertEqual(auth[stranger_self_end]["code"], "not_covered")
        self.assertEqual(auth[stranger_obs]["code"], "no_standing")
        self.assertEqual(auth[root_obs_without_grant]["code"], "not_covered")
        self.assertEqual(auth[mid_self]["code"], "not_covered")
        self.assertEqual(auth[bad_badge_no_endorse]["code"], "not_covered")
        self.assertEqual(auth[bad_child_kind]["code"], "not_covered")
        self.assertEqual(auth[bad_child_window]["code"], "not_covered")
        self.assertEqual(auth[bad_child_issued_late]["code"], "not_covered")
        self.assertEqual(auth[good_badge]["code"], "ok")
        self.assertEqual(auth[good_badge]["about"], l0_mid)
        self.assertEqual(auth[child_under_badge]["code"], "not_covered")
        self.assertEqual(auth[obs_missing_prof]["code"], "ok")
        self.assertEqual(auth[obs_missing_prof]["about"], good_badge)

    def test_a5_acts_for_actor_prefixes_and_stream_prefixes_including_seal(self) -> None:
        h = _A5Harness()
        root = h.new_signer()
        mid = h.new_signer()
        worker = h.new_signer()
        sealer = h.new_signer()
        h.finalize_profile()

        l0 = h.add_endorsement(
            root,
            mid,
            kinds=["provenance.r5e.io/v2/Observation", EPOCH_SEAL_KIND],
            stream_prefixes=["urn:stream:work:"],
            actor_prefixes=["urn:actor:team:"],
            acts_for="urn:org:acme",
            stream="urn:stream:auth1",
        )
        # Child dropping actsFor -> not_covered
        drop_acts_for = h.add_endorsement(
            mid,
            worker,
            parent=l0,
            stream_prefixes=["urn:stream:work:sub:"],
            actor_prefixes=["urn:actor:team:bot"],
            acts_for=None,
            stream="urn:stream:auth2",
        )
        # Child widening streamPrefixes -> not_covered
        widen_stream = h.add_endorsement(
            mid,
            worker,
            parent=l0,
            stream_prefixes=["urn:stream:"],
            actor_prefixes=["urn:actor:team:bot"],
            acts_for="urn:org:acme",
            stream="urn:stream:auth3",
        )
        # Child widening actorPrefixes -> not_covered
        widen_actor = h.add_endorsement(
            mid,
            worker,
            parent=l0,
            stream_prefixes=["urn:stream:work:sub:"],
            actor_prefixes=["urn:actor:"],
            acts_for="urn:org:acme",
            stream="urn:stream:auth4",
        )
        # Valid narrowed child
        good_child = h.add_endorsement(
            mid,
            worker,
            parent=l0,
            may_endorse=False,
            stream_prefixes=["urn:stream:work:sub:"],
            actor_prefixes=["urn:actor:team:bot"],
            acts_for="urn:org:acme",
            stream="urn:stream:auth5",
        )

        obs_ok = h.add_observation(
            worker,
            stream="urn:stream:work:sub:1",
            actor="urn:actor:team:bot1",
            on_behalf_of="urn:org:acme",
        )
        obs_missing_obo = h.add_observation(
            worker,
            stream="urn:stream:work:sub:2",
            actor="urn:actor:team:bot1",
            on_behalf_of=None,
        )
        obs_bad_actor = h.add_observation(
            worker,
            stream="urn:stream:work:sub:3",
            actor="urn:actor:other:bot1",
            on_behalf_of="urn:org:acme",
        )

        # EpochSeal streamPrefixes tests body.stream, NOT seal.stream (§3)
        l0_sealer = h.add_endorsement(
            root,
            sealer,
            kinds=[EPOCH_SEAL_KIND],
            may_endorse=False,
            stream_prefixes=["urn:stream:work:sub:"],
            stream="urn:stream:auth6",
        )
        seal_ok = h.add_epoch_seal(
            sealer,
            "urn:stream:work:sub:1",
            [obs_ok],
            seal_stream="urn:stream:outside-seals",
        )
        other_obs = h.add_observation(worker, stream="urn:stream:other:1")
        seal_bad_stream = h.add_epoch_seal(
            sealer,
            "urn:stream:other:1",
            [other_obs],
            seal_stream="urn:stream:work:sub:seal-envelope",
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[root.keyid])
        auth = self._auth_by_subject(rep)

        self.assertEqual(auth[drop_acts_for]["code"], "not_covered")
        self.assertEqual(auth[widen_stream]["code"], "not_covered")
        self.assertEqual(auth[widen_actor]["code"], "not_covered")
        self.assertEqual(auth[good_child]["code"], "ok")
        self.assertEqual(auth[obs_ok]["code"], "ok")
        self.assertEqual(auth[obs_ok]["about"], good_child)
        self.assertEqual(auth[obs_missing_obo]["code"], "not_covered")
        self.assertEqual(auth[obs_bad_actor]["code"], "not_covered")
        self.assertEqual(auth[seal_ok]["code"], "ok")
        self.assertEqual(auth[seal_ok]["about"], l0_sealer)
        self.assertEqual(auth[seal_bad_stream]["code"], "not_covered")

    def test_a5_missing_parent_does_not_mask_failure_and_16_link_cap(self) -> None:
        h = _A5Harness()
        root = h.new_signer()
        orphan_s0, orphan_s1, orphan_s2, orphan_s3 = [h.new_signer() for _ in range(4)]
        signers = [h.new_signer() for _ in range(18)]
        h.finalize_profile()

        # Missing parent when carried badge ALREADY fails kind coverage -> not_covered, NOT chain_not_carried
        missing_parent_ref = "evidence:sha256:" + "a" * 64
        orphan_badge = h.add_badge(
            orphan_s0,
            orphan_s1,
            missing_parent_ref,
            kinds=["provenance.r5e.io/v2/ToolCall"],
            stream="urn:stream:mp1",
        )
        obs_wrong_kind_under_orphan = h.add_observation(orphan_s1, stream="urn:stream:mp2")

        # Missing parent when carried endorsement IS revoked before record -> not_covered, NOT chain_not_carried
        orphan_end = h.add_endorsement(
            orphan_s2,
            orphan_s3,
            parent=missing_parent_ref,
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:mp3",
        )
        h.add_revocation(
            orphan_s2, orphan_end, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:mp4"
        )
        obs_after_revoked_orphan = h.add_observation(
            orphan_s3, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:mp5"
        )

        # Build a 17-link chain from root: L0 (1) .. L15 (16th link, ok) .. L16 (17th link, not_covered)
        links: list[str] = []
        prev_link = h.add_endorsement(
            root,
            signers[0],
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:chain",
        )
        links.append(prev_link)
        for idx in range(16):
            prev_link = h.add_endorsement(
                signers[idx],
                signers[idx + 1],
                parent=prev_link,
                captured_at="2026-11-10T01:00:00Z",
                stream="urn:stream:chain",
            )
            links.append(prev_link)

        obs_at_16 = h.add_observation(signers[15], stream="urn:stream:c16")
        obs_at_17 = h.add_observation(signers[16], stream="urn:stream:c17")

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[root.keyid])
        auth = self._auth_by_subject(rep)

        self.assertEqual(auth[orphan_badge]["code"], "chain_not_carried")
        self.assertEqual(auth[obs_wrong_kind_under_orphan]["code"], "not_covered")
        self.assertEqual(auth[obs_after_revoked_orphan]["code"], "not_covered")
        self.assertEqual(auth[links[15]]["code"], "ok")  # 16th link
        self.assertEqual(auth[links[16]]["code"], "not_covered")  # 17th link exceeds 16
        self.assertEqual(auth[obs_at_16]["code"], "ok")
        self.assertEqual(auth[obs_at_16]["about"], links[15])
        self.assertEqual(auth[obs_at_17]["code"], "not_covered")

    def test_a5_successions_root_chain_fork_cycle_badge_and_seals(self) -> None:
        # 1. Root succession + sealer endorsed by old root before hand-over + predecessor timing
        h = _A5Harness()
        root = h.new_signer()
        new_root = h.new_signer()
        sealer = h.new_signer()
        p_key = h.new_signer()
        s_key = h.new_signer()
        p2_key = h.new_signer()
        s2_key = h.new_signer()
        badge_holder = h.new_signer()
        badge_succ = h.new_signer()
        new_root_subject = h.new_signer()
        h.finalize_profile()

        # Root endorses sealer and p_key at t=01:00, then hands over to new_root at t=05:00
        l0_sealer = h.add_endorsement(
            root,
            sealer,
            captured_at="2026-11-10T01:00:00Z",
            kinds=[EPOCH_SEAL_KIND],
            may_endorse=False,
            stream="urn:stream:r1",
        )
        l0_p = h.add_endorsement(
            root,
            p_key,
            captured_at="2026-11-10T01:00:00Z",
            kinds=["provenance.r5e.io/v2/Observation"],
            may_endorse=True,
            stream="urn:stream:r2",
        )
        root_succ_ref = h.add_succession(
            root, new_root, captured_at="2026-11-10T05:00:00Z", stream="urn:stream:r3"
        )
        # NewRoot before t=05:00 -> no_standing; at/after t=05:00 -> ok; old Root after t=05:00 -> ended
        new_root_early = h.add_endorsement(
            new_root, s_key, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:r4"
        )
        new_root_ok = h.add_endorsement(
            new_root, new_root_subject, captured_at="2026-11-10T06:00:00Z", stream="urn:stream:r5"
        )
        old_root_late = h.add_endorsement(
            root, s_key, captured_at="2026-11-10T06:00:00Z", stream="urn:stream:r6"
        )

        # Badge subject cannot succeed ("a badge dies with its key")
        badge_ref = h.add_badge(
            p_key,
            badge_holder,
            l0_p,
            captured_at="2026-11-10T01:30:00Z",
            stream="urn:stream:b1",
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:b1",
            [badge_ref],
            captured_at="2026-11-10T01:45:00Z",
            seal_stream="urn:stream:sb1",
        )
        h.add_succession(
            badge_holder, badge_succ, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:b2"
        )
        badge_succ_obs = h.add_observation(
            badge_succ, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:b3"
        )

        # p_key records vs p_key -> s_key succession at t=04:00 (unsealed succession):
        # - obs_sealed_before: t=02:00, sealed at s=03:00 < 04:00 (sealer under rotated root!) -> ok
        # - obs_unsealed_before: t=02:00, unsealed -> time_rests_on_the_signer
        # - obs_unsealed_after: t=06:00, unsealed -> ended
        # - obs_sealed_after_unsealed_succ: t=04:30 >= 04:00, sealed at s=04:45 (first seal since succ unsealed!) -> time_rests_on_the_signer
        obs_sealed_before = h.add_observation(
            p_key, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:pw1"
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:pw1",
            [obs_sealed_before],
            captured_at="2026-11-10T03:00:00Z",
            seal_stream="urn:stream:spw1",
        )
        obs_unsealed_before = h.add_observation(
            p_key, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:pw2"
        )
        obs_unsealed_after = h.add_observation(
            p_key, captured_at="2026-11-10T06:00:00Z", stream="urn:stream:pw3"
        )
        obs_sealed_after = h.add_observation(
            p_key, captured_at="2026-11-10T04:30:00Z", stream="urn:stream:pw4"
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:pw4",
            [obs_sealed_after],
            captured_at="2026-11-10T04:45:00Z",
            seal_stream="urn:stream:spw4",
        )
        p_succ_ref = h.add_succession(
            p_key, s_key, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:ps"
        )
        # s_key stands in for p_key after t=04:00 (even though root also rotated at t=05:00!)
        s_obs_ok = h.add_observation(
            s_key, captured_at="2026-11-10T07:00:00Z", stream="urn:stream:sw1"
        )

        # When p2_key -> s2_key succession at 04:00 IS sealed via membership proof at sE=04:15,
        # p2_key's 04:30 record sealed at s=04:45 has sE <= s (no first seal) -> ended!
        h.add_endorsement(
            root,
            p2_key,
            captured_at="2026-11-10T01:00:00Z",
            kinds=["provenance.r5e.io/v2/Observation"],
            stream="urn:stream:p20",
        )
        p2_succ_ref = h.add_succession(
            p2_key, s2_key, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:p2s"
        )
        h.add_membership_seal(
            sealer, "urn:stream:p2s", p2_succ_ref, captured_at="2026-11-10T04:15:00Z"
        )
        obs_after_sealed_succ = h.add_observation(
            p2_key, captured_at="2026-11-10T04:30:00Z", stream="urn:stream:p2w"
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:p2w",
            [obs_after_sealed_succ],
            captured_at="2026-11-10T04:45:00Z",
            seal_stream="urn:stream:sp2w",
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[root.keyid])
        auth = self._auth_by_subject(rep)

        self.assertNotIn(root_succ_ref, auth)
        self.assertNotIn(p_succ_ref, auth)
        self.assertEqual(auth[l0_sealer]["code"], "ok")
        self.assertEqual(auth[l0_p]["code"], "ok")
        # A6 Slice 2 §4.1: Succession never makes another key a root and never ends a root
        self.assertEqual(auth[new_root_early]["code"], "no_standing")
        self.assertEqual(auth[new_root_ok]["code"], "no_standing")
        self.assertEqual(auth[old_root_late]["code"], "ok")
        self.assertEqual(auth[old_root_late]["about"], root.keyid)
        self.assertEqual(auth[badge_succ_obs]["code"], "no_standing")
        self.assertEqual(auth[obs_sealed_before]["code"], "ok")
        self.assertEqual(auth[obs_unsealed_before]["code"], "time_rests_on_the_signer")
        self.assertEqual(auth[obs_unsealed_before]["about"], p_succ_ref)
        self.assertEqual(auth[obs_unsealed_after]["code"], "ended")
        self.assertEqual(auth[obs_unsealed_after]["about"], p_succ_ref)
        self.assertEqual(auth[obs_sealed_after]["code"], "time_rests_on_the_signer")
        self.assertEqual(auth[s_obs_ok]["code"], "ok")
        self.assertEqual(
            auth[s_obs_ok]["about"],
            min([l0_p, old_root_late], key=lambda r: r.encode("utf-8")),
        )
        self.assertEqual(auth[obs_after_sealed_succ]["code"], "ended")
        self.assertEqual(auth[obs_after_sealed_succ]["about"], p2_succ_ref)

        # 2. Forked succession, cyclic succession, and 16 vs 17 succession hops
        h2 = _A5Harness()
        root2 = h2.new_signer()
        fork_p = h2.new_signer()
        fork_s1 = h2.new_signer()
        fork_s2 = h2.new_signer()
        cyc_a = h2.new_signer()
        cyc_b = h2.new_signer()
        sealer2 = h2.new_signer()
        chain_keys = [h2.new_signer() for _ in range(18)]
        h2.finalize_profile()

        h2.add_endorsement(root2, fork_p, stream="urn:stream:f0")
        fork_e1 = h2.add_succession(
            fork_p, fork_s1, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:f1"
        )
        h2.add_succession(
            fork_p, fork_s2, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:f2"
        )
        obs_fork_s1 = h2.add_observation(
            fork_s1, captured_at="2026-11-10T05:00:00Z", stream="urn:stream:f3"
        )
        obs_fork_p = h2.add_observation(
            fork_p, captured_at="2026-11-10T03:30:00Z", stream="urn:stream:f4"
        )

        h2.add_endorsement(root2, cyc_a, stream="urn:stream:ca0")
        h2.add_endorsement(root2, cyc_b, stream="urn:stream:cb0")
        cyc_e1 = h2.add_succession(
            cyc_a, cyc_b, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:cy1"
        )
        h2.add_succession(
            cyc_b, cyc_a, captured_at="2026-11-10T06:00:00Z", stream="urn:stream:cy2"
        )
        # cyc_b is in a cycle whose earliest succession is cyc_e1 (02:00), so cyc_b at 03:00 is ended by cyc_e1!
        obs_cyc_b = h2.add_observation(
            cyc_b, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:cy3"
        )

        h2.add_endorsement(
            root2,
            sealer2,
            kinds=[EPOCH_SEAL_KIND],
            may_endorse=False,
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:s20",
        )
        l0_chain = h2.add_endorsement(root2, chain_keys[0], stream="urn:stream:ch0")
        for idx in range(16):
            h2.add_succession(
                chain_keys[idx],
                chain_keys[idx + 1],
                captured_at="2026-11-10T02:00:00Z",
                stream=f"urn:stream:chs{idx}",
            )
        obs_16_hops = h2.add_observation(
            chain_keys[16], captured_at="2026-11-10T08:00:00Z", stream="urn:stream:cho16"
        )
        h2.add_epoch_seal(
            sealer2,
            "urn:stream:cho16",
            [obs_16_hops],
            captured_at="2026-11-10T08:30:00Z",
            seal_stream="urn:stream:scho16",
        )
        # 17th hop at 09:00: chain_keys[16]'s sealed 08:00 record stays ok, while chain_keys[17] exceeds 16 steps
        h2.add_succession(
            chain_keys[16],
            chain_keys[17],
            captured_at="2026-11-10T09:00:00Z",
            stream="urn:stream:chs16",
        )
        obs_17_hops = h2.add_observation(
            chain_keys[17], captured_at="2026-11-10T09:30:00Z", stream="urn:stream:cho17"
        )

        rep2 = verify_provenance_bundle(h2.fx.bundle(), trusted_roots=[root2.keyid])
        auth2 = self._auth_by_subject(rep2)

        self.assertEqual(auth2[obs_fork_s1]["code"], "no_standing")
        self.assertEqual(auth2[obs_fork_p]["code"], "ended")
        self.assertEqual(auth2[obs_fork_p]["about"], fork_e1)
        self.assertEqual(auth2[obs_cyc_b]["code"], "ended")
        self.assertEqual(auth2[obs_cyc_b]["about"], cyc_e1)
        self.assertEqual(auth2[obs_16_hops]["code"], "ok")
        self.assertEqual(auth2[obs_16_hops]["about"], l0_chain)
        self.assertEqual(auth2[obs_17_hops]["code"], "no_standing")

    def test_a5_revocations_entitlement_steps_comparison_and_unqualified_sealer(self) -> None:
        h = _A5Harness()
        root = h.new_signer()
        mid = h.new_signer()
        mid_succ = h.new_signer()
        worker1 = h.new_signer()
        worker2 = h.new_signer()
        worker3 = h.new_signer()
        worker_unsealed_mid = h.new_signer()
        mid2 = h.new_signer()
        worker4 = h.new_signer()
        stranger = h.new_signer()
        revoked_sealer = h.new_signer()
        good_sealer = h.new_signer()
        h.finalize_profile()

        l0_mid = h.add_endorsement(
            root, mid, captured_at="2026-11-10T01:00:00Z", stream="urn:stream:m0"
        )
        # Ancestor revocation: root revokes badge1 issued by mid
        badge1 = h.add_badge(
            mid, worker1, l0_mid, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:m1"
        )
        rev_by_stranger = h.add_revocation(
            stranger, badge1, captured_at="2026-11-10T02:30:00Z", stream="urn:stream:rv1"
        )
        obs_after_stranger_rev = h.add_observation(
            worker1, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:w1"
        )
        rev_by_ancestor = h.add_revocation(
            root, badge1, captured_at="2026-11-10T05:00:00Z", stream="urn:stream:rv2"
        )

        # Revoked sealer does NOT qualify under §6 Condition 3!
        l0_rev_sealer = h.add_endorsement(
            root,
            revoked_sealer,
            kinds=[EPOCH_SEAL_KIND],
            may_endorse=False,
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:rs0",
        )
        h.add_revocation(
            root, l0_rev_sealer, captured_at="2026-11-10T09:00:00Z", stream="urn:stream:rs1"
        )
        h.add_epoch_seal(
            revoked_sealer,
            "urn:stream:w1",
            [obs_after_stranger_rev],
            captured_at="2026-11-10T03:30:00Z",
            seal_stream="urn:stream:rs2",
        )

        # Subject self-revocation (worker2 gives up its own badge2 at 05:00) + good sealer at 03:30
        h.add_endorsement(
            root,
            good_sealer,
            kinds=[EPOCH_SEAL_KIND],
            may_endorse=False,
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:gs0",
        )
        badge2 = h.add_badge(
            mid, worker2, l0_mid, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:m2"
        )
        # Seal badge2 before mid's succession at 04:00 so step badge2 is shown to precede mid's succession
        h.add_epoch_seal(
            good_sealer,
            "urn:stream:m2",
            [badge2],
            captured_at="2026-11-10T02:15:00Z",
            seal_stream="urn:stream:gsm2",
        )
        obs_self_rev_sealed = h.add_observation(
            worker2, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:w2"
        )
        h.add_epoch_seal(
            good_sealer,
            "urn:stream:w2",
            [obs_self_rev_sealed],
            captured_at="2026-11-10T03:30:00Z",
            seal_stream="urn:stream:gs1",
        )
        rev_by_subject = h.add_revocation(
            worker2, badge2, captured_at="2026-11-10T05:00:00Z", stream="urn:stream:rv3"
        )

        # Unsealed badge by mid before mid's succession (04:00): even when worker's obs is sealed at 03:30,
        # mid's unsealed step rests on mid's clock!
        badge_unsealed_mid = h.add_badge(
            mid,
            worker_unsealed_mid,
            l0_mid,
            captured_at="2026-11-10T02:00:00Z",
            stream="urn:stream:mu",
        )
        obs_under_unsealed_mid_badge = h.add_observation(
            worker_unsealed_mid, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:wu"
        )
        h.add_epoch_seal(
            good_sealer,
            "urn:stream:wu",
            [obs_under_unsealed_mid_badge],
            captured_at="2026-11-10T03:30:00Z",
            seal_stream="urn:stream:gswu",
        )

        # Succession then revocation by successor (mid -> mid_succ at 04:00, mid_succ revokes badge3 at 06:00;
        # old mid trying to revoke at 04:30 has no_standing!)
        badge3 = h.add_badge(
            mid, worker3, l0_mid, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:m3"
        )
        h.add_epoch_seal(
            good_sealer,
            "urn:stream:m3",
            [badge3],
            captured_at="2026-11-10T02:15:00Z",
            seal_stream="urn:stream:gsm3",
        )
        mid_succ_ref = h.add_succession(
            mid, mid_succ, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:ms1"
        )
        rev_by_old_mid = h.add_revocation(
            mid, badge3, captured_at="2026-11-10T04:30:00Z", stream="urn:stream:rv4"
        )
        obs_before_succ_rev = h.add_observation(
            worker3, captured_at="2026-11-10T05:00:00Z", stream="urn:stream:w3"
        )
        h.add_epoch_seal(
            good_sealer,
            "urn:stream:w3",
            [obs_before_succ_rev],
            captured_at="2026-11-10T05:30:00Z",
            seal_stream="urn:stream:gs2",
        )
        rev_by_succ = h.add_revocation(
            mid_succ, badge3, captured_at="2026-11-10T06:00:00Z", stream="urn:stream:rv5"
        )

        # Revocation of L0 compared with intermediate step L1 (§6 line 114):
        # l0_revoked is revoked at 04:00; child badge minted at 05:00 >= 04:00; worker backdates obs to 03:00 -> ended!
        l0_revoked = h.add_endorsement(
            root, mid2, captured_at="2026-11-10T01:00:00Z", stream="urn:stream:lr0"
        )
        rev_l0 = h.add_revocation(
            root, l0_revoked, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:lr1"
        )
        badge_minted_after_rev = h.add_badge(
            mid2,
            worker4,
            l0_revoked,
            captured_at="2026-11-10T05:00:00Z",
            not_before="2026-11-10T02:00:00Z",
            stream="urn:stream:lr2",
        )
        backdated_obs = h.add_observation(
            worker4, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:lr3"
        )

        # Revocation targeting missing record -> chain_not_carried; targeting Observation or bad-sig Badge -> not_covered
        rev_missing_target = h.add_revocation(
            root, "evidence:sha256:" + "9" * 64, stream="urn:stream:rv6"
        )
        rev_non_grant = h.add_revocation(root, obs_self_rev_sealed, stream="urn:stream:rv7")
        bad_sig_badge = h.add_badge(
            mid_succ,
            worker1,
            l0_mid,
            captured_at="2026-11-10T07:00:00Z",
            corrupt_second_sig=True,
            stream="urn:stream:bsb",
        )
        rev_bad_sig_badge = h.add_revocation(
            mid_succ, bad_sig_badge, captured_at="2026-11-10T08:00:00Z", stream="urn:stream:rv8"
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[root.keyid])
        auth = self._auth_by_subject(rep)

        self.assertEqual(auth[rev_by_stranger]["code"], "no_standing")
        self.assertEqual(auth[rev_by_ancestor]["code"], "ok")
        self.assertEqual(auth[rev_by_ancestor]["about"], badge1)
        # Because revoked_sealer did NOT qualify, obs_after_stranger_rev (03:00 < 05:00) rests on signer's clock!
        self.assertEqual(auth[obs_after_stranger_rev]["code"], "time_rests_on_the_signer")
        self.assertEqual(auth[obs_after_stranger_rev]["about"], rev_by_ancestor)

        self.assertEqual(auth[rev_by_subject]["code"], "ok")
        self.assertEqual(auth[obs_self_rev_sealed]["code"], "ok")
        self.assertEqual(auth[badge_unsealed_mid]["code"], "time_rests_on_the_signer")
        self.assertEqual(auth[obs_under_unsealed_mid_badge]["code"], "time_rests_on_the_signer")
        self.assertEqual(auth[obs_under_unsealed_mid_badge]["about"], mid_succ_ref)

        self.assertEqual(auth[rev_by_old_mid]["code"], "no_standing")
        self.assertEqual(auth[rev_by_succ]["code"], "ok")
        self.assertEqual(auth[obs_before_succ_rev]["code"], "ok")

        self.assertEqual(auth[badge_minted_after_rev]["code"], "ended")
        self.assertEqual(auth[backdated_obs]["code"], "ended")
        self.assertEqual(auth[backdated_obs]["about"], rev_l0)

        self.assertEqual(auth[rev_missing_target]["code"], "chain_not_carried")
        self.assertEqual(auth[rev_non_grant]["code"], "not_covered")
        self.assertEqual(auth[rev_bad_sig_badge]["code"], "not_covered")

    def test_a5_revocation_by_handed_over_key_sealed_vs_unsealed_and_root_pre_handover(self) -> None:
        h = _A5Harness()
        root = h.new_signer()
        sealer = h.new_signer()
        mid = h.new_signer()
        mid_succ = h.new_signer()
        worker1 = h.new_signer()
        worker2 = h.new_signer()
        root2 = h.new_signer()
        root2_succ = h.new_signer()
        worker3 = h.new_signer()
        h.finalize_profile()

        h.add_endorsement(
            root,
            sealer,
            kinds=[EPOCH_SEAL_KIND],
            may_endorse=False,
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:seal-auth",
        )
        l0_mid = h.add_endorsement(
            root, mid, captured_at="2026-11-10T01:00:00Z", stream="urn:stream:mid-auth"
        )

        # Two badges issued by mid at 02:00 and sealed at 02:15 (before mid -> mid_succ at 04:00)
        badge_sealed_rev = h.add_badge(
            mid, worker1, l0_mid, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:b1"
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:b1",
            [badge_sealed_rev],
            captured_at="2026-11-10T02:15:00Z",
            seal_stream="urn:stream:sb1",
        )
        badge_unsealed_rev = h.add_badge(
            mid, worker2, l0_mid, captured_at="2026-11-10T02:00:00Z", stream="urn:stream:b2"
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:b2",
            [badge_unsealed_rev],
            captured_at="2026-11-10T02:15:00Z",
            seal_stream="urn:stream:sb2",
        )

        # 1. Revocation by handed-over non-root key `mid` at 03:00 WITH a qualifying seal at 03:15 < 04:00
        rev_sealed = h.add_revocation(
            mid,
            badge_sealed_rev,
            captured_at="2026-11-10T03:00:00Z",
            stream="urn:stream:rev-sealed",
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:rev-sealed",
            [rev_sealed],
            captured_at="2026-11-10T03:15:00Z",
            seal_stream="urn:stream:srev1",
        )

        # 2. Contrast: Revocation by handed-over non-root key `mid` at 03:00 WITHOUT a seal
        rev_unsealed = h.add_revocation(
            mid,
            badge_unsealed_rev,
            captured_at="2026-11-10T03:00:00Z",
            stream="urn:stream:rev-unsealed",
        )

        # mid hands over to mid_succ at 04:00
        h.add_succession(
            mid, mid_succ, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:mid-succ"
        )

        obs_w1 = h.add_observation(
            worker1, captured_at="2026-11-10T03:30:00Z", stream="urn:stream:obs-w1"
        )
        obs_w2 = h.add_observation(
            worker2, captured_at="2026-11-10T03:30:00Z", stream="urn:stream:obs-w2"
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:obs-w2",
            [obs_w2],
            captured_at="2026-11-10T03:45:00Z",
            seal_stream="urn:stream:sobs2",
        )

        # 3. Contrast: Trusted root `root2` revokes at 03:00 WITHOUT a seal before handing over at 04:00
        l0_w3 = h.add_endorsement(
            root2,
            worker3,
            kinds=["provenance.r5e.io/v2/Observation"],
            may_endorse=False,
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:r2-l0",
        )
        rev_root_pre = h.add_revocation(
            root2, l0_w3, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:r2-rev"
        )
        h.add_succession(
            root2, root2_succ, captured_at="2026-11-10T04:00:00Z", stream="urn:stream:r2-succ"
        )
        obs_w3 = h.add_observation(
            worker3, captured_at="2026-11-10T03:30:00Z", stream="urn:stream:obs-w3"
        )

        rep = verify_provenance_bundle(
            h.fx.bundle(), trusted_roots=[root.keyid, root2.keyid]
        )
        auth = self._auth_by_subject(rep)

        # Sealed pre-handover revocation by `mid` succeeds and ends `badge_sealed_rev`
        self.assertEqual(auth[rev_sealed]["result"], "ok")
        self.assertEqual(auth[rev_sealed]["about"], badge_sealed_rev)
        self.assertEqual(auth[obs_w1]["result"], "failed")
        self.assertEqual(auth[obs_w1]["code"], "ended")
        self.assertEqual(auth[obs_w1]["about"], rev_sealed)

        # Unsealed pre-handover revocation by `mid` fails `no_standing` and does NOT end `badge_unsealed_rev`
        self.assertEqual(auth[rev_unsealed]["result"], "failed")
        self.assertEqual(auth[rev_unsealed]["code"], "no_standing")
        self.assertEqual(auth[rev_unsealed]["about"], mid.keyid)
        self.assertEqual(auth[obs_w2]["result"], "ok")
        self.assertEqual(auth[obs_w2]["about"], badge_unsealed_rev)

        # Trusted root's own `capturedAt` (03:00 < 04:00) establishes pre-handover revocation without a seal
        self.assertEqual(auth[rev_root_pre]["result"], "ok")
        self.assertEqual(auth[rev_root_pre]["about"], l0_w3)
        self.assertEqual(auth[obs_w3]["result"], "failed")
        self.assertEqual(auth[obs_w3]["code"], "ended")
        self.assertEqual(auth[obs_w3]["about"], rev_root_pre)

    def test_a5_lead_in_loop_might_yet_be_valid_grant_and_revocation_rows(self) -> None:
        h = _A5Harness()
        root_a = h.new_signer()
        lead_a = h.new_signer()
        succ_b = h.new_signer()
        succ_c = h.new_signer()
        worker_b = h.new_signer()
        missing_root = Ed25519Signer(211)  # intentionally NOT added to bundle.keys!
        worker_missing_parent = h.new_signer()
        worker_forged_parent = h.new_signer()
        orphan_gateway = h.new_signer()
        orphan_worker = h.new_signer()
        maybe_anc = h.new_signer()
        retired_anc = h.new_signer()
        retired_anc_succ = h.new_signer()
        sealer = h.new_signer()
        h.finalize_profile()

        # 1. Lead-in into non-root succession loop:
        #    root_a -> lead_a (Endorsement, mayEndorse=True), then
        #    lead_a -> succ_b (01:00), succ_b -> succ_c (05:00), succ_c -> succ_b (06:00)
        h.add_endorsement(
            root_a,
            sealer,
            kinds=[EPOCH_SEAL_KIND],
            may_endorse=False,
            captured_at="2026-11-10T00:15:00Z",
            stream="urn:stream:sealer-l0",
        )
        l0_lead_a = h.add_endorsement(
            root_a,
            lead_a,
            kinds=["provenance.r5e.io/v2/Observation"],
            may_endorse=True,
            captured_at="2026-11-10T00:30:00Z",
            stream="urn:stream:la0",
        )
        ref_ab = h.add_succession(
            lead_a, succ_b, captured_at="2026-11-10T01:00:00Z", stream="urn:stream:sab"
        )
        ref_bc = h.add_succession(
            succ_b, succ_c, captured_at="2026-11-10T05:00:00Z", stream="urn:stream:sbc"
        )
        h.add_succession(
            succ_c, succ_b, captured_at="2026-11-10T06:00:00Z", stream="urn:stream:scb"
        )
        # succ_b stands in for lead_a before the loop began (02:00 < 05:00):
        # sealed before 05:00 -> ok; unsealed -> time_rests_on_the_signer against ref_bc!
        child_by_b = h.add_endorsement(
            succ_b,
            worker_b,
            parent=l0_lead_a,
            kinds=["provenance.r5e.io/v2/Observation"],
            may_endorse=False,
            captured_at="2026-11-10T02:00:00Z",
            stream="urn:stream:lb1",
        )
        h.add_epoch_seal(
            sealer, "urn:stream:lb1", [child_by_b], captured_at="2026-11-10T03:30:00Z"
        )
        obs_by_wb = h.add_observation(
            worker_b, captured_at="2026-11-10T03:00:00Z", stream="urn:stream:owb"
        )
        h.add_epoch_seal(
            sealer, "urn:stream:owb", [obs_by_wb], captured_at="2026-11-10T03:45:00Z"
        )
        child_by_b_unsealed = h.add_endorsement(
            succ_b,
            worker_b,
            parent=l0_lead_a,
            kinds=["provenance.r5e.io/v2/Observation"],
            may_endorse=False,
            captured_at="2026-11-10T02:15:00Z",
            stream="urn:stream:lb1-unsealed",
        )
        # lead_a after 01:00 -> ended (ref_ab); succ_b after 05:00 -> ended (ref_bc); succ_c -> not_covered under l0_lead_a
        end_by_a_late = h.add_endorsement(
            lead_a,
            worker_b,
            parent=l0_lead_a,
            kinds=["provenance.r5e.io/v2/Observation"],
            captured_at="2026-11-10T02:00:00Z",
            stream="urn:stream:la-late",
        )
        end_by_b_late = h.add_endorsement(
            succ_b,
            worker_b,
            parent=l0_lead_a,
            kinds=["provenance.r5e.io/v2/Observation"],
            captured_at="2026-11-10T05:30:00Z",
            stream="urn:stream:lb-late",
        )
        end_by_c = h.add_endorsement(
            succ_c,
            worker_b,
            parent=l0_lead_a,
            kinds=["provenance.r5e.io/v2/Observation"],
            captured_at="2026-11-10T06:30:00Z",
            stream="urn:stream:lc",
        )

        # 2. Endorsement with failed body (notBefore > notAfter) -> own authority is failed: not_covered
        bad_body_end = h.add_endorsement(
            root_a,
            worker_b,
            captured_at="2026-11-10T00:30:00Z",
            not_before="2026-11-10T10:00:00Z",
            not_after="2026-11-10T05:00:00Z",
            stream="urn:stream:bad-body",
        )

        # 3. Root Endorsement signed by `missing_root` (key absent -> missing_key, body ok):
        #    own authority is judged from what it says (`ok`), and it "might yet be a valid grant"!
        l0_missing_key = h.add_endorsement(
            missing_root,
            orphan_gateway,
            captured_at="2026-11-10T01:00:00Z",
            stream="urn:stream:mk0",
        )
        badge_under_missing_key = h.add_badge(
            orphan_gateway,
            worker_missing_parent,
            l0_missing_key,
            captured_at="2026-11-10T02:00:00Z",
            stream="urn:stream:mk1",
        )
        rev_targeting_missing_key = h.add_revocation(
            orphan_gateway,
            l0_missing_key,
            captured_at="2026-11-10T03:00:00Z",
            stream="urn:stream:mk2",
        )

        # 4. Forged root Endorsement (`bad_signature`, body ok):
        #    own authority is `ok`, but child Badge and Revocation targeting it both get `not_covered`!
        forged_l0 = h.add_endorsement(
            root_a,
            orphan_gateway,
            captured_at="2026-11-10T02:00:00Z",
            stream="urn:stream:fg0",
        )
        h.fx.records[-1]["envelope"]["signatures"][0]["sig"] = b64(b"\x00" * 64)
        badge_under_forged = h.add_badge(
            orphan_gateway,
            worker_forged_parent,
            forged_l0,
            captured_at="2026-11-10T02:30:00Z",
            stream="urn:stream:fg1",
        )
        rev_targeting_forged = h.add_revocation(
            root_a,
            forged_l0,
            captured_at="2026-11-10T03:00:00Z",
            stream="urn:stream:fg2",
        )

        # 5. Revocation Row 2: carried valid Badge whose `parent` is uncarried
        uncarried_l0 = "evidence:sha256:" + "8" * 64
        orphan_badge = h.add_badge(
            orphan_gateway,
            orphan_worker,
            uncarried_l0,
            captured_at="2026-11-10T02:00:00Z",
            stream="urn:stream:ob1",
        )
        rev_by_maybe_anc = h.add_revocation(
            maybe_anc,
            orphan_badge,
            captured_at="2026-11-10T03:00:00Z",
            stream="urn:stream:ob2",
        )
        h.add_succession(
            retired_anc,
            retired_anc_succ,
            captured_at="2026-11-10T02:00:00Z",
            stream="urn:stream:ra1",
        )
        rev_by_retired_anc = h.add_revocation(
            retired_anc,
            orphan_badge,
            captured_at="2026-11-10T03:00:00Z",
            stream="urn:stream:ra2",
        )

        rep = verify_provenance_bundle(
            h.fx.bundle(), trusted_roots=[root_a.keyid, missing_root.keyid]
        )
        auth = self._auth_by_subject(rep)

        self.assertEqual(auth[child_by_b]["code"], "ok")
        self.assertEqual(auth[obs_by_wb]["code"], "ok")
        self.assertEqual(auth[child_by_b_unsealed]["code"], "time_rests_on_the_signer")
        self.assertEqual(auth[child_by_b_unsealed]["about"], ref_bc)
        self.assertEqual(auth[end_by_a_late]["code"], "ended")
        self.assertEqual(auth[end_by_a_late]["about"], ref_ab)
        self.assertEqual(auth[end_by_b_late]["code"], "ended")
        self.assertEqual(auth[end_by_b_late]["about"], ref_bc)
        self.assertEqual(auth[end_by_c]["code"], "not_covered")

        self.assertEqual(auth[bad_body_end]["code"], "not_covered")
        self.assertIsNone(auth[bad_body_end]["about"])

        self.assertEqual(auth[l0_missing_key]["code"], "ok")
        self.assertEqual(auth[l0_missing_key]["about"], missing_root.keyid)
        self.assertEqual(auth[badge_under_missing_key]["code"], "chain_not_carried")
        self.assertEqual(auth[badge_under_missing_key]["about"], l0_missing_key)
        self.assertEqual(auth[rev_targeting_missing_key]["code"], "chain_not_carried")
        self.assertEqual(auth[rev_targeting_missing_key]["about"], l0_missing_key)

        self.assertEqual(auth[forged_l0]["code"], "ok")
        self.assertEqual(auth[badge_under_forged]["code"], "not_covered")
        self.assertIsNone(auth[badge_under_forged]["about"])
        self.assertEqual(auth[rev_targeting_forged]["code"], "not_covered")

        self.assertEqual(auth[rev_by_maybe_anc]["code"], "chain_not_carried")
        self.assertEqual(auth[rev_by_maybe_anc]["about"], uncarried_l0)
        self.assertEqual(auth[rev_by_retired_anc]["code"], "no_standing")
        self.assertEqual(auth[rev_by_retired_anc]["about"], retired_anc.keyid)


class _A6StartHarness:
    """Self-contained helper for Amendment A6 Slice 1 (`start` & `ChainStarted` `publication`) tests."""

    def __init__(self, slug: str = "acme") -> None:
        self.slug = slug
        self.stream = f"urn:r5e:stream:{slug}:start"
        self.fx = ProvenanceFixtureBuilder()
        self._next_seed = 90
        self.bootstrap = self.new_signer()
        self.publisher = self.new_signer()
        self.root1 = self.new_signer()
        self.root2 = self.new_signer()
        self.worker = self.new_signer()
        self.prof_ref = ""

    def new_signer(self) -> Ed25519Signer:
        s = Ed25519Signer(self._next_seed)
        self._next_seed += 1
        if not any(k["keyid"] == s.keyid for k in self.fx.keys):
            self.fx.keys.append(s.key_entry())
        return s

    def finalize_profile(
        self,
        *,
        issuer_keys: list[str] | None = None,
        extra_schemas: dict[str, str] | None = None,
    ) -> str:
        schemas = dict(self.fx.defs_index)
        if extra_schemas:
            schemas.update(extra_schemas)
        allowed = (
            issuer_keys
            if issuer_keys is not None
            else [k["keyid"] for k in self.fx.keys]
        )
        profile = {
            "format": "r5e.capture-profile/v2",
            "schemas": schemas,
            "authority": {
                "bindings": [
                    {
                        "streamPrefix": "urn:r5e:stream:",
                        "actorPrefixes": ["urn:actor:"],
                        "issuerKeys": allowed,
                        "sealerKeys": allowed,
                    },
                    {
                        "streamPrefix": "urn:stream:",
                        "actorPrefixes": ["urn:actor:"],
                        "issuerKeys": allowed,
                        "sealerKeys": allowed,
                    },
                ],
                "checkpointKeys": [],
            },
            "durability": {
                "failureDomain": "local",
                "requiredPayloads": "submitted",
                "onFailure": "refuse",
            },
            "policyRequiredKinds": [],
            "deploymentPolicyRef": self.fx.policy_ref,
        }
        self.prof_ref = self.fx.add_json_blob(profile)
        return self.prof_ref

    def base_definitions_list(self) -> list[dict[str, str]]:
        return [
            {"kind": k, "definition": d}
            for k, d in sorted(self.fx.defs_index.items())
        ]

    @staticmethod
    def root_entry(signer: Ed25519Signer) -> dict[str, Any]:
        return {
            "key": signer.keyid,
            "publicKey": {"algorithm": signer.alg, "bytes": b64(signer.pub)},
        }

    def add_base_publication(
        self,
        *,
        definitions: list[dict[str, str]] | None = None,
        signer: Ed25519Signer | None = None,
        stream: str = "urn:stream:pub",
        seq: int = 1,
        previous: str | None = None,
    ) -> tuple[str, list[dict[str, str]]]:
        pub_signer = signer or self.publisher
        defs = (
            list(definitions)
            if definitions is not None
            else self.base_definitions_list()
        )
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "DefinitionPublished",
            "schemaRef": self.fx.defs_index[DEFINITION_PUBLISHED_KIND],
            "profileRef": self.prof_ref,
            "issuer": pub_signer.keyid,
            "actor": "urn:actor:pub",
            "stream": stream,
            "seq": seq,
            "previous": previous,
            "capturedAt": "2026-11-10T00:00:00Z",
            "body": {"definitions": defs},
        }
        return self.fx.sign_record(payload, [pub_signer]), defs

    def add_chain_started(
        self,
        pub_ref: str,
        defs: list[dict[str, str]],
        *,
        deployment: str | None = None,
        bootstrap: Ed25519Signer | None = None,
        publisher_kid: str | None = None,
        stream: str | None = None,
        seq: Any = 1,
        previous: str | None = None,
        schema_ref: str | None = None,
        body_override: dict[str, Any] | None = None,
        signers: list[Ed25519Signer | EcSigner] | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        bs = bootstrap or self.bootstrap
        body: dict[str, Any] = (
            body_override
            if body_override is not None
            else {
                "deployment": deployment if deployment is not None else self.slug,
                "bootstrap": bs.keyid,
                "bootstrapKey": {"algorithm": bs.alg, "bytes": b64(bs.pub)},
                "publication": pub_ref,
                "publisher": (
                    publisher_kid
                    if publisher_kid is not None
                    else self.publisher.keyid
                ),
                "definitions": defs,
            }
        )
        if details is not None and body_override is None:
            body["details"] = details
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "ChainStarted",
            "schemaRef": (
                schema_ref
                if schema_ref is not None
                else self.fx.defs_index[CHAIN_STARTED_KIND]
            ),
            "profileRef": self.prof_ref,
            "issuer": bs.keyid,
            "actor": "urn:actor:node",
            "stream": stream if stream is not None else self.stream,
            "seq": seq,
            "previous": previous,
            "capturedAt": "2026-11-10T00:01:00Z",
            "body": body,
        }
        return self.fx.sign_record(payload, signers or [bs])

    def add_deployment(
        self,
        accepts_ref: str,
        *,
        bootstrap: Ed25519Signer | None = None,
        claimed_by: Ed25519Signer | None = None,
        roots: list[dict[str, Any]] | None = None,
        threshold: int = 1,
        recovery_keys: list[str] | None = None,
        custodians: list[dict[str, str]] | None = None,
        stream: str | None = None,
        seq: Any = 2,
        previous: str | None = "AUTO",
        body_override: dict[str, Any] | None = None,
        signers: list[Ed25519Signer | EcSigner] | None = None,
    ) -> str:
        bs = bootstrap or self.bootstrap
        claimer = claimed_by or self.root1
        body: dict[str, Any] = (
            body_override
            if body_override is not None
            else {
                "accepts": accepts_ref,
                "bootstrap": bs.keyid,
                "claimedBy": claimer.keyid,
                "roots": roots if roots is not None else [self.root_entry(claimer)],
                "threshold": threshold,
            }
        )
        if body_override is None:
            if recovery_keys is not None:
                body["recoveryKeys"] = recovery_keys
            if custodians is not None:
                body["custodians"] = custodians
        actual_prev = accepts_ref if previous == "AUTO" else previous
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Deployment",
            "schemaRef": self.fx.defs_index[DEPLOYMENT_KIND],
            "profileRef": self.prof_ref,
            "issuer": bs.keyid,
            "actor": "urn:actor:node",
            "stream": stream if stream is not None else self.stream,
            "seq": seq,
            "previous": actual_prev,
            "capturedAt": "2026-11-10T00:02:00Z",
            "body": body,
        }
        return self.fx.sign_record(payload, signers or [bs, claimer])

    def add_observation(
        self,
        signer: Ed25519Signer,
        *,
        stream: str = "urn:stream:work",
        seq: int = 1,
        previous: str | None = None,
        captured_at: str = "2026-11-10T00:10:00Z",
    ) -> str:
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": self.fx.defs_index["provenance.r5e.io/v2/Observation"],
            "profileRef": self.prof_ref,
            "issuer": signer.keyid,
            "actor": "urn:actor:worker",
            "stream": stream,
            "seq": seq,
            "previous": previous,
            "capturedAt": captured_at,
            "body": {"event": "ping"},
        }
        return self.fx.sign_record(payload, [signer])


class StartAndChainStartedTests(unittest.TestCase):
    """Focused tests for Amendment A6 Slice 1 (`VERIFY-V2.md` §6.3b)."""

    @staticmethod
    def _finding(
        report: dict[str, Any], check: str, subject: str
    ) -> dict[str, Any]:
        matches = [
            f
            for f in report["findings"]
            if f["check"] == check and f["subject"] == subject
        ]
        assert len(matches) == 1, f"expected 1 ({check}, {subject}), got {matches}"
        return matches[0]

    def test_chain_started_publication_tightened_table_all_rows_and_body_fallback(
        self,
    ) -> None:
        # 1. Non-ok ChainStarted body falls back to §6.2a ordinary table:
        #    even when body.publication names an uncarried ref, a carried trusted DefinitionPublished
        #    satisfies §6.2a (ok, about = pub_ref) rather than A6 §3 Row 1 (publication_not_carried).
        h_bad_body = _A6StartHarness()
        h_bad_body.finalize_profile()
        pub_fb, _ = h_bad_body.add_base_publication()
        uncarried_pub = "evidence:sha256:" + "a" * 64
        cs_bad_body = h_bad_body.add_chain_started(
            uncarried_pub,
            [],  # nonEmpty violation -> body: failed (invalid_body)
        )
        rep = verify_provenance_bundle(
            h_bad_body.fx.bundle(),
            trusted_publishers=[h_bad_body.publisher.keyid],
            trusted_profiles=[h_bad_body.prof_ref],
        )
        self.assertEqual(self._finding(rep, "body", cs_bad_body)["result"], "failed")
        pub_f = self._finding(rep, "publication", cs_bad_body)
        self.assertEqual(pub_f["result"], "ok")
        self.assertEqual(pub_f["about"], pub_fb)

        # 2. Record-order independence: ChainStarted placed BEFORE DefinitionPublished in records.
        h_order = _A6StartHarness()
        h_order.finalize_profile()
        pub_ref, defs = h_order.add_base_publication()
        cs_ref = h_order.add_chain_started(pub_ref, defs)
        dep_ref = h_order.add_deployment(cs_ref)
        b_reordered = h_order.fx.bundle()
        b_reordered["records"] = list(reversed(b_reordered["records"]))
        rep_reordered = verify_provenance_bundle(
            b_reordered,
            trusted_publishers=[h_order.publisher.keyid],
            trusted_profiles=[h_order.prof_ref],
            trusted_chain=dep_ref,
            min_start_seq=2,
        )
        self.assertEqual(rep_reordered["summary"]["failed"], 0)
        self.assertEqual(rep_reordered["summary"]["incomplete"], 0)
        self.assertEqual(
            self._finding(rep_reordered, "publication", cs_ref),
            {
                "layer": 2,
                "check": "publication",
                "subject": cs_ref,
                "about": pub_ref,
                "result": "ok",
                "code": "ok",
            },
        )
        self.assertEqual(
            rep_reordered["start"],
            {
                "chain": dep_ref,
                "deployment": "acme",
                "headCapturedAt": "2026-11-10T00:02:00Z",
                "headRef": dep_ref,
                "headSeq": 2,
                "stream": h_order.stream,
            },
        )

        # 3. Row 1: publication_not_carried (incomplete, about = P_ref).
        h_r1 = _A6StartHarness()
        h_r1.finalize_profile()
        cs_r1 = h_r1.add_chain_started(uncarried_pub, h_r1.base_definitions_list())
        rep_r1 = verify_provenance_bundle(
            h_r1.fx.bundle(), trusted_publishers=[h_r1.publisher.keyid]
        )
        self.assertEqual(
            self._finding(rep_r1, "publication", cs_r1),
            {
                "layer": 2,
                "check": "publication",
                "subject": cs_r1,
                "about": uncarried_pub,
                "result": "incomplete",
                "code": "publication_not_carried",
            },
        )

        # 4. Row 2: cited_publication_mismatch across all 4 failure triggers.
        # (a) P is not DefinitionPublished
        h_r2a = _A6StartHarness()
        h_r2a.finalize_profile()
        obs_as_pub = h_r2a.add_observation(h_r2a.publisher)
        cs_r2a = h_r2a.add_chain_started(obs_as_pub, h_r2a.base_definitions_list())
        f_r2a = self._finding(
            verify_provenance_bundle(
                h_r2a.fx.bundle(), trusted_publishers=[h_r2a.publisher.keyid]
            ),
            "publication",
            cs_r2a,
        )
        self.assertEqual(f_r2a["code"], "cited_publication_mismatch")
        self.assertEqual(f_r2a["about"], obs_as_pub)

        # (b) P's body finding is not ok (empty definitions violates nonEmpty)
        h_r2b = _A6StartHarness()
        h_r2b.finalize_profile()
        bad_pub_ref, _ = h_r2b.add_base_publication(definitions=[])
        cs_r2b = h_r2b.add_chain_started(bad_pub_ref, h_r2b.base_definitions_list())
        f_r2b = self._finding(
            verify_provenance_bundle(
                h_r2b.fx.bundle(), trusted_publishers=[h_r2b.publisher.keyid]
            ),
            "publication",
            cs_r2b,
        )
        self.assertEqual(f_r2b["code"], "cited_publication_mismatch")
        self.assertEqual(f_r2b["about"], bad_pub_ref)

        # (c) P.issuer != P_pub
        h_r2c = _A6StartHarness()
        h_r2c.finalize_profile()
        pub_r2c, defs_r2c = h_r2c.add_base_publication(signer=h_r2c.publisher)
        cs_r2c = h_r2c.add_chain_started(
            pub_r2c, defs_r2c, publisher_kid=h_r2c.worker.keyid
        )
        f_r2c = self._finding(
            verify_provenance_bundle(
                h_r2c.fx.bundle(), trusted_publishers=[h_r2c.publisher.keyid]
            ),
            "publication",
            cs_r2c,
        )
        self.assertEqual(f_r2c["code"], "cited_publication_mismatch")
        self.assertEqual(f_r2c["about"], pub_r2c)

        # (d) P has a failed signature finding
        h_r2d = _A6StartHarness()
        h_r2d.finalize_profile()
        pub_r2d, defs_r2d = h_r2d.add_base_publication()
        for rec in h_r2d.fx.records:
            if rec["ref"] == pub_r2d:
                rec["envelope"]["signatures"][0]["sig"] = b64(b"\x00" * 64)
        cs_r2d = h_r2d.add_chain_started(pub_r2d, defs_r2d)
        f_r2d = self._finding(
            verify_provenance_bundle(
                h_r2d.fx.bundle(), trusted_publishers=[h_r2d.publisher.keyid]
            ),
            "publication",
            cs_r2d,
        )
        self.assertEqual(f_r2d["code"], "cited_publication_mismatch")
        self.assertEqual(f_r2d["about"], pub_r2d)

        # 5. Row 3: publication_not_verified (incomplete, about = P_ref) when P's key is uncarried.
        h_r3 = _A6StartHarness()
        h_r3.finalize_profile()
        pub_r3, defs_r3 = h_r3.add_base_publication()
        h_r3.fx.keys = [
            k for k in h_r3.fx.keys if k["keyid"] != h_r3.publisher.keyid
        ]
        cs_r3 = h_r3.add_chain_started(pub_r3, defs_r3)
        f_r3 = self._finding(
            verify_provenance_bundle(
                h_r3.fx.bundle(), trusted_publishers=[h_r3.publisher.keyid]
            ),
            "publication",
            cs_r3,
        )
        self.assertEqual(f_r3["result"], "incomplete")
        self.assertEqual(f_r3["code"], "publication_not_verified")
        self.assertEqual(f_r3["about"], pub_r3)

        # 6. Row 4: definitions_differ_from_publication across all 3 sub-clauses.
        # (a) duplicate kind (with distinct definition ref so unique: true passes!) in ChainStarted.body.definitions
        h_r4a = _A6StartHarness()
        h_r4a.finalize_profile()
        pub_r4a, defs_r4a = h_r4a.add_base_publication()
        dup_defs = defs_r4a + [{"kind": defs_r4a[0]["kind"], "definition": "bytes:sha256:" + "0" * 64}]
        cs_r4a = h_r4a.add_chain_started(pub_r4a, dup_defs)
        rep_r4a = verify_provenance_bundle(
            h_r4a.fx.bundle(), trusted_publishers=[h_r4a.publisher.keyid]
        )
        f_r4a = self._finding(rep_r4a, "publication", cs_r4a)
        self.assertEqual(f_r4a["code"], "definitions_differ_from_publication")
        self.assertEqual(f_r4a["about"], pub_r4a)
        self.assertEqual(
            self._finding(rep_r4a, "start", cs_r4a)["code"], "invalid_start_record"
        )

        # (b) subset mismatch against P.body.definitions
        h_r4b = _A6StartHarness()
        h_r4b.finalize_profile()
        pub_r4b, defs_r4b = h_r4b.add_base_publication()
        trimmed = [d for d in defs_r4b if d["kind"] != BADGE_KIND]
        cs_r4b = h_r4b.add_chain_started(pub_r4b, trimmed)
        f_r4b = self._finding(
            verify_provenance_bundle(
                h_r4b.fx.bundle(), trusted_publishers=[h_r4b.publisher.keyid]
            ),
            "publication",
            cs_r4b,
        )
        self.assertEqual(f_r4b["code"], "definitions_differ_from_publication")

        # (c) matching pair sets between P and ChainStarted, but omitting (ChainStarted, R.schemaRef)
        h_r4c = _A6StartHarness()
        h_r4c.finalize_profile()
        without_cs = [
            d for d in h_r4c.base_definitions_list() if d["kind"] != CHAIN_STARTED_KIND
        ]
        pub_r4c, _ = h_r4c.add_base_publication(definitions=without_cs)
        cs_r4c = h_r4c.add_chain_started(pub_r4c, without_cs)
        f_r4c = self._finding(
            verify_provenance_bundle(
                h_r4c.fx.bundle(), trusted_publishers=[h_r4c.publisher.keyid]
            ),
            "publication",
            cs_r4c,
        )
        self.assertEqual(f_r4c["code"], "definitions_differ_from_publication")
        self.assertEqual(f_r4c["about"], pub_r4c)

        # 7. Row 5: publisher_not_trusted (incomplete, about = P_ref).
        h_r5 = _A6StartHarness()
        h_r5.finalize_profile()
        pub_r5, defs_r5 = h_r5.add_base_publication(signer=h_r5.publisher)
        cs_r5 = h_r5.add_chain_started(pub_r5, defs_r5)
        f_r5 = self._finding(
            verify_provenance_bundle(h_r5.fx.bundle(), trusted_publishers=[]),
            "publication",
            cs_r5,
        )
        self.assertEqual(f_r5["result"], "incomplete")
        self.assertEqual(f_r5["code"], "publisher_not_trusted")
        self.assertEqual(f_r5["about"], pub_r5)

    def test_start_check_stream_shape_positions_forks_and_record_validity(
        self,
    ) -> None:
        # 1. Row 1: multiple_start_streams across >1 candidate stream (about = lowest stream URI != R.stream).
        h_ms = _A6StartHarness("alpha")
        h_ms.finalize_profile()
        pub_ms, defs_ms = h_ms.add_base_publication()
        cs_alpha = h_ms.add_chain_started(pub_ms, defs_ms)
        cs_beta = h_ms.add_chain_started(
            pub_ms,
            defs_ms,
            deployment="beta",
            stream="urn:r5e:stream:beta:start",
        )
        cs_stray = h_ms.add_chain_started(
            pub_ms,
            defs_ms,
            deployment="alpha",
            stream="urn:stream:not-a-start-stream",
        )
        rep_ms = verify_provenance_bundle(h_ms.fx.bundle())
        self.assertNotIn("start", rep_ms)
        expected_about = {
            cs_alpha: "urn:r5e:stream:beta:start",
            cs_beta: "urn:r5e:stream:alpha:start",
            cs_stray: "urn:r5e:stream:alpha:start",
        }
        for ref, exp_ab in expected_about.items():
            sf = self._finding(rep_ms, "start", ref)
            self.assertEqual(sf["result"], "failed")
            self.assertEqual(sf["code"], "multiple_start_streams")
            self.assertEqual(sf["about"], exp_ab)

        # 2. Row 2: not_a_start_record on candidate start stream at seq = 3 (about = R's kind path).
        h_ns = _A6StartHarness()
        h_ns.finalize_profile()
        pub_ns, defs_ns = h_ns.add_base_publication()
        cs_ns = h_ns.add_chain_started(pub_ns, defs_ns)
        dep_ns = h_ns.add_deployment(cs_ns)
        obs_ns = h_ns.add_observation(
            h_ns.worker, stream=h_ns.stream, seq=3, previous=dep_ns
        )
        rep_ns = verify_provenance_bundle(
            h_ns.fx.bundle(), trusted_chain=dep_ns
        )
        sf_ns = self._finding(rep_ns, "start", obs_ns)
        self.assertEqual(sf_ns["code"], "not_a_start_record")
        self.assertEqual(sf_ns["about"], "provenance.r5e.io/v2/Observation")
        self.assertEqual(rep_ns["start"]["headSeq"], 2)

        # 3. Row 3: wrong_start_position (malformed stream URI, ChainStarted seq!=1, Deployment seq!=2, non-int seq).
        # (a) malformed start stream URI
        h_wp_uri = _A6StartHarness()
        h_wp_uri.finalize_profile()
        pub_u, defs_u = h_wp_uri.add_base_publication()
        cs_bad_uri = h_wp_uri.add_chain_started(
            pub_u, defs_u, stream="urn:r5e:stream:UPPER:start", seq=1
        )
        sf_uri = self._finding(
            verify_provenance_bundle(h_wp_uri.fx.bundle()), "start", cs_bad_uri
        )
        self.assertEqual(sf_uri["code"], "wrong_start_position")
        self.assertEqual(sf_uri["about"], "seq:1")

        # (b) Deployment at seq = 1 and ChainStarted at seq = 2
        h_wp_swap = _A6StartHarness()
        h_wp_swap.finalize_profile()
        pub_sw, defs_sw = h_wp_swap.add_base_publication()
        fake_prev = "evidence:sha256:" + "1" * 64
        dep_seq1 = h_wp_swap.add_deployment(fake_prev, seq=1, previous=None)
        cs_seq2 = h_wp_swap.add_chain_started(
            pub_sw, defs_sw, seq=2, previous=dep_seq1
        )
        rep_swap = verify_provenance_bundle(h_wp_swap.fx.bundle())
        self.assertNotIn("start", rep_swap)
        self.assertEqual(
            self._finding(rep_swap, "start", dep_seq1),
            {
                "layer": 2,
                "check": "start",
                "subject": dep_seq1,
                "about": "seq:1",
                "result": "failed",
                "code": "wrong_start_position",
            },
        )
        self.assertEqual(
            self._finding(rep_swap, "start", cs_seq2)["code"],
            "wrong_start_position",
        )
        self.assertEqual(
            self._finding(rep_swap, "start", cs_seq2)["about"], "seq:2"
        )

        # (c) non-int seq on ChainStarted envelope -> about is None
        h_wp_nonint = _A6StartHarness()
        h_wp_nonint.finalize_profile()
        pub_ni, defs_ni = h_wp_nonint.add_base_publication()
        cs_nonint = h_wp_nonint.add_chain_started(pub_ni, defs_ni, seq="one")
        sf_ni = self._finding(
            verify_provenance_bundle(h_wp_nonint.fx.bundle()), "start", cs_nonint
        )
        self.assertEqual(sf_ni["code"], "wrong_start_position")
        self.assertIsNone(sf_ni["about"])

        # 4. Row 4 & Row 14: forked seq = 1 and C tie-breaking (matching accepts vs lowest byte-order ref).
        for match_accepts in (True, False):
            with self.subTest(match_accepts=match_accepts):
                h_fk = _A6StartHarness()
                h_fk.finalize_profile()
                pub_fk, defs_fk = h_fk.add_base_publication()
                c1 = h_fk.add_chain_started(pub_fk, defs_fk, details={"branch": 1})
                c2 = h_fk.add_chain_started(pub_fk, defs_fk, details={"branch": 2})
                hi_ref = max(c1, c2)
                lo_ref = min(c1, c2)
                chosen_accepts = (
                    hi_ref
                    if match_accepts
                    else ("evidence:sha256:" + "f" * 64)
                )
                dep_fk = h_fk.add_deployment(chosen_accepts)
                rep_fk = verify_provenance_bundle(h_fk.fx.bundle())
                self.assertNotIn("start", rep_fk)
                for c_ref in (c1, c2):
                    sf_c = self._finding(rep_fk, "start", c_ref)
                    self.assertEqual(sf_c["code"], "forked_start_stream")
                    self.assertEqual(sf_c["about"], "seq:1")
                sf_dep = self._finding(rep_fk, "start", dep_fk)
                self.assertEqual(sf_dep["code"], "accepts_is_not_chain_started")
                # C in Row 14 is hi_ref when accepts == hi_ref, else lowest byte-order ref lo_ref!
                self.assertEqual(
                    sf_dep["about"], hi_ref if match_accepts else lo_ref
                )

        # 5. Row 5: invalid_start_record (failed body on ChainStarted, failed signature on Deployment; about = None).
        h_inv = _A6StartHarness()
        h_inv.finalize_profile()
        pub_inv, _ = h_inv.add_base_publication()
        cs_bad = h_inv.add_chain_started(pub_inv, [])  # empty definitions -> invalid_body
        dep_bad_sig = h_inv.add_deployment(cs_bad)
        for rec in h_inv.fx.records:
            if rec["ref"] == dep_bad_sig:
                rec["envelope"]["signatures"][1]["sig"] = b64(b"\x00" * 64)
        rep_inv = verify_provenance_bundle(h_inv.fx.bundle())
        sf_cs_bad = self._finding(rep_inv, "start", cs_bad)
        self.assertEqual(sf_cs_bad["code"], "invalid_start_record")
        self.assertIsNone(sf_cs_bad["about"])
        sf_dep_bad = self._finding(rep_inv, "start", dep_bad_sig)
        self.assertEqual(sf_dep_bad["code"], "invalid_start_record")
        self.assertIsNone(sf_dep_bad["about"])

        # 6. Row 6: unverified_start_record (incomplete signature on ChainStarted; about = None).
        h_unv = _A6StartHarness()
        h_unv.finalize_profile()
        pub_unv, defs_unv = h_unv.add_base_publication()
        cs_unv = h_unv.add_chain_started(pub_unv, defs_unv)
        h_unv.fx.keys = [
            k for k in h_unv.fx.keys if k["keyid"] != h_unv.bootstrap.keyid
        ]
        rep_unv = verify_provenance_bundle(h_unv.fx.bundle())
        sf_unv = self._finding(rep_unv, "start", cs_unv)
        self.assertEqual(sf_unv["result"], "incomplete")
        self.assertEqual(sf_unv["code"], "unverified_start_record")
        self.assertIsNone(sf_unv["about"])

        # 7. Row 7: deployment_stream_mismatch (stream slug != body.deployment; about = R.stream).
        h_dsm = _A6StartHarness("alpha")
        h_dsm.finalize_profile()
        pub_dsm, defs_dsm = h_dsm.add_base_publication()
        cs_dsm = h_dsm.add_chain_started(pub_dsm, defs_dsm, deployment="beta")
        sf_dsm = self._finding(
            verify_provenance_bundle(h_dsm.fx.bundle()), "start", cs_dsm
        )
        self.assertEqual(sf_dsm["result"], "failed")
        self.assertEqual(sf_dsm["code"], "deployment_stream_mismatch")
        self.assertEqual(sf_dsm["about"], h_dsm.stream)

        # 8. Row 9: deployment_not_carried (valid ChainStarted alone at seq = 1 -> incomplete, about = None).
        h_dnc = _A6StartHarness()
        h_dnc.finalize_profile()
        pub_dnc, defs_dnc = h_dnc.add_base_publication()
        cs_dnc = h_dnc.add_chain_started(pub_dnc, defs_dnc)
        rep_dnc = verify_provenance_bundle(h_dnc.fx.bundle())
        sf_dnc = self._finding(rep_dnc, "start", cs_dnc)
        self.assertEqual(sf_dnc["result"], "incomplete")
        self.assertEqual(sf_dnc["code"], "deployment_not_carried")
        self.assertIsNone(sf_dnc["about"])
        self.assertNotIn("start", rep_dnc)

    def test_deployment_terms_accepts_bootstrap_and_chain_pins(self) -> None:
        # 1. Row 11: all 7 invalid_deployment_terms violations + valid keyless custodians.
        r1 = Ed25519Signer(101)
        r2 = Ed25519Signer(102)
        rec_k1 = Ed25519Signer(103)
        rec_k2 = Ed25519Signer(104)
        bad_terms_cases: list[tuple[str, dict[str, Any]]] = [
            (
                "duplicate_root_key",
                {
                    "roots": [
                        _A6StartHarness.root_entry(r1),
                        {**_A6StartHarness.root_entry(r1), "holder": "person"},
                    ],
                    "threshold": 1,
                },
            ),
            (
                "threshold_exceeds_roots",
                {"roots": [_A6StartHarness.root_entry(r1)], "threshold": 2},
            ),
            (
                "claimed_by_not_in_roots",
                {"roots": [_A6StartHarness.root_entry(r2)], "threshold": 1},
            ),
            (
                "recovery_overlaps_roots",
                {
                    "roots": [_A6StartHarness.root_entry(r1)],
                    "threshold": 1,
                    "recovery_keys": [r1.keyid],
                },
            ),
            (
                "duplicate_custodian_identity",
                {
                    "roots": [_A6StartHarness.root_entry(r1)],
                    "threshold": 1,
                    "custodians": [
                        {"identity": "mailto:alice@example.com"},
                        {"identity": "mailto:alice@example.com", "key": rec_k1.keyid},
                    ],
                },
            ),
            (
                "duplicate_custodian_key",
                {
                    "roots": [_A6StartHarness.root_entry(r1)],
                    "threshold": 1,
                    "custodians": [
                        {
                            "identity": "mailto:alice@example.com",
                            "key": rec_k1.keyid,
                        },
                        {
                            "identity": "mailto:bob@example.com",
                            "key": rec_k1.keyid,
                        },
                    ],
                },
            ),
        ]
        for label, kwargs in bad_terms_cases:
            with self.subTest(term_case=label):
                h = _A6StartHarness()
                for s in (r1, r2, rec_k1, rec_k2):
                    h.fx.keys.append(s.key_entry())
                h.finalize_profile()
                pub_ref, defs = h.add_base_publication()
                cs_ref = h.add_chain_started(pub_ref, defs)
                dep_ref = h.add_deployment(cs_ref, claimed_by=r1, **kwargs)
                rep = verify_provenance_bundle(h.fx.bundle())
                self.assertEqual(
                    self._finding(rep, "body", dep_ref)["result"], "ok"
                )
                sf = self._finding(rep, "start", dep_ref)
                self.assertEqual(sf["result"], "failed")
                self.assertEqual(sf["code"], "invalid_deployment_terms")
                self.assertIsNone(sf["about"])

        # Under A9, duplicate_recovery_keys fails `unique: true` on `body` -> start Row 6 `invalid_start_record`.
        h_dup_rk = _A6StartHarness()
        for s in (r1, rec_k1):
            h_dup_rk.fx.keys.append(s.key_entry())
        h_dup_rk.finalize_profile()
        pub_rk, defs_rk = h_dup_rk.add_base_publication()
        cs_rk = h_dup_rk.add_chain_started(pub_rk, defs_rk)
        dep_rk = h_dup_rk.add_deployment(
            cs_rk,
            claimed_by=r1,
            roots=[_A6StartHarness.root_entry(r1)],
            threshold=1,
            recovery_keys=[rec_k1.keyid, rec_k1.keyid],
        )
        rep_rk = verify_provenance_bundle(h_dup_rk.fx.bundle())
        self.assertEqual(self._finding(rep_rk, "body", dep_rk)["code"], "body_does_not_match_definition")
        self.assertEqual(self._finding(rep_rk, "start", dep_rk)["code"], "invalid_start_record")

        # Multiple keyless custodians + distinct recovery keys are valid (start: ok, about = C.ref).
        h_ok_cust = _A6StartHarness()
        h_ok_cust.finalize_profile()
        pub_okc, defs_okc = h_ok_cust.add_base_publication()
        cs_okc = h_ok_cust.add_chain_started(pub_okc, defs_okc)
        dep_okc = h_ok_cust.add_deployment(
            cs_okc,
            recovery_keys=[rec_k1.keyid, rec_k2.keyid],
            custodians=[
                {"identity": "mailto:alice@example.com"},
                {"identity": "mailto:bob@example.com"},
            ],
        )
        rep_okc = verify_provenance_bundle(
            h_ok_cust.fx.bundle(), trusted_chain=dep_okc
        )
        sf_okc = self._finding(rep_okc, "start", dep_okc)
        self.assertEqual(sf_okc["code"], "ok")
        self.assertEqual(sf_okc["about"], cs_okc)

        # 2. Row 12: R.previous != R.body.accepts -> accepts_is_not_chain_started (about = R.body.accepts).
        h_r12 = _A6StartHarness()
        h_r12.finalize_profile()
        pub_12, defs_12 = h_r12.add_base_publication()
        cs_12 = h_r12.add_chain_started(pub_12, defs_12)
        dep_12 = h_r12.add_deployment(
            cs_12, previous="evidence:sha256:" + "9" * 64
        )
        sf_12 = self._finding(
            verify_provenance_bundle(h_r12.fx.bundle()), "start", dep_12
        )
        self.assertEqual(sf_12["code"], "accepts_is_not_chain_started")
        self.assertEqual(sf_12["about"], cs_12)

        # 3. Row 13: chain_started_not_carried (only seq=2 carried -> incomplete, about = R.body.accepts).
        h_r13 = _A6StartHarness()
        h_r13.finalize_profile()
        uncarried_cs = "evidence:sha256:" + "8" * 64
        dep_13 = h_r13.add_deployment(uncarried_cs)
        rep_13 = verify_provenance_bundle(h_r13.fx.bundle())
        sf_13 = self._finding(rep_13, "start", dep_13)
        self.assertEqual(sf_13["result"], "incomplete")
        self.assertEqual(sf_13["code"], "chain_started_not_carried")
        self.assertEqual(sf_13["about"], uncarried_cs)
        self.assertNotIn("start", rep_13)

        # 4. Row 15: bootstrap_signer_mismatch (about = C.body.bootstrap), preceding Row 16 when C's key is uncarried.
        h_r15 = _A6StartHarness()
        bs_other = h_r15.new_signer()
        h_r15.finalize_profile()
        pub_15, defs_15 = h_r15.add_base_publication()
        cs_15 = h_r15.add_chain_started(pub_15, defs_15, bootstrap=h_r15.bootstrap)
        dep_15 = h_r15.add_deployment(cs_15, bootstrap=bs_other)
        h_r15.fx.keys = [
            k for k in h_r15.fx.keys if k["keyid"] != h_r15.bootstrap.keyid
        ]
        rep_15 = verify_provenance_bundle(h_r15.fx.bundle())
        self.assertEqual(
            self._finding(rep_15, "start", cs_15)["code"],
            "unverified_start_record",
        )
        sf_15 = self._finding(rep_15, "start", dep_15)
        self.assertEqual(sf_15["result"], "failed")
        self.assertEqual(sf_15["code"], "bootstrap_signer_mismatch")
        self.assertEqual(sf_15["about"], h_r15.bootstrap.keyid)

        # 5. Row 16: Deployment gets unverified_start_record (about = C.ref) when C.start is incomplete and bootstrap matches.
        h_r16 = _A6StartHarness()
        unknown_cs_schema = "bytes:sha256:" + "7" * 64
        h_r16.finalize_profile(extra_schemas={CHAIN_STARTED_KIND: unknown_cs_schema})
        pub_16, defs_16 = h_r16.add_base_publication()
        cs_16 = h_r16.add_chain_started(
            pub_16, defs_16, schema_ref=unknown_cs_schema
        )
        dep_16 = h_r16.add_deployment(cs_16)
        rep_16 = verify_provenance_bundle(h_r16.fx.bundle())
        self.assertEqual(
            self._finding(rep_16, "start", cs_16)["code"],
            "unverified_start_record",
        )
        sf_16 = self._finding(rep_16, "start", dep_16)
        self.assertEqual(sf_16["result"], "incomplete")
        self.assertEqual(sf_16["code"], "unverified_start_record")
        self.assertEqual(sf_16["about"], cs_16)

        # 6. Row 17 (chain_mismatch, failed, about = trustedChain) and Row 18 (chain_not_trusted, incomplete, about = R.ref;
        #    trustedRoots containing claimedBy satisfies Row 18 -> ok!).
        h_pins = _A6StartHarness()
        h_pins.finalize_profile()
        pub_p, defs_p = h_pins.add_base_publication()
        cs_p = h_pins.add_chain_started(pub_p, defs_p)
        dep_p = h_pins.add_deployment(cs_p)
        other_chain = "evidence:sha256:" + "6" * 64
        rep_mismatch = verify_provenance_bundle(
            h_pins.fx.bundle(), trusted_chain=other_chain
        )
        sf_mm = self._finding(rep_mismatch, "start", dep_p)
        self.assertEqual(sf_mm["result"], "failed")
        self.assertEqual(sf_mm["code"], "chain_mismatch")
        self.assertEqual(sf_mm["about"], other_chain)

        rep_untrusted = verify_provenance_bundle(
            h_pins.fx.bundle(), trusted_roots=[h_pins.root2.keyid]
        )
        sf_ut = self._finding(rep_untrusted, "start", dep_p)
        self.assertEqual(sf_ut["result"], "incomplete")
        self.assertEqual(sf_ut["code"], "chain_not_trusted")
        self.assertEqual(sf_ut["about"], dep_p)

        rep_root_pinned = verify_provenance_bundle(
            h_pins.fx.bundle(), trusted_roots=[h_pins.root1.keyid]
        )
        self.assertEqual(
            self._finding(rep_root_pinned, "start", dep_p)["code"], "ok"
        )

    def test_completeness_authority_exemptions_multi_root_a5_and_cli_mutual_exclusion(
        self,
    ) -> None:
        # 1. §4.3 chain_start_not_carried + start_below_minimum_position ("bundle" subject, about="seq:2") + incomplete A5.
        h_empty = _A6StartHarness()
        h_empty.finalize_profile()
        obs_empty = h_empty.add_observation(h_empty.worker)
        pub_empty, _ = h_empty.add_base_publication()
        pinned_missing = "evidence:sha256:" + "5" * 64
        rep_empty = verify_provenance_bundle(
            h_empty.fx.bundle(), trusted_chain=pinned_missing, min_start_seq=2
        )
        self.assertNotIn("start", rep_empty)
        self.assertEqual(
            self._finding(rep_empty, "start", pinned_missing),
            {
                "layer": 2,
                "check": "start",
                "subject": pinned_missing,
                "about": None,
                "result": "incomplete",
                "code": "chain_start_not_carried",
            },
        )
        self.assertEqual(
            self._finding(rep_empty, "start", "bundle"),
            {
                "layer": 2,
                "check": "start",
                "subject": "bundle",
                "about": "seq:2",
                "result": "incomplete",
                "code": "start_below_minimum_position",
            },
        )
        # Non-exempt Observation gets incomplete chain_not_carried (about = trustedChain); DefinitionPublished is exempt.
        self.assertEqual(
            self._finding(rep_empty, "authority", obs_empty),
            {
                "layer": 2,
                "check": "authority",
                "subject": obs_empty,
                "about": pinned_missing,
                "result": "incomplete",
                "code": "chain_not_carried",
            },
        )
        self.assertFalse(
            any(
                f["check"] == "authority" and f["subject"] == pub_empty
                for f in rep_empty["findings"]
            )
        )

        # Also when trustedChain matches a carried non-Deployment record (e.g. Observation).
        rep_non_dep = verify_provenance_bundle(
            h_empty.fx.bundle(), trusted_chain=obs_empty
        )
        self.assertEqual(
            self._finding(rep_non_dep, "start", obs_empty)["code"],
            "chain_start_not_carried",
        )

        # 2. §4.4 Multi-root Deployment establishing A5 roots (non-claimedBy root2 authorizes work; bootstrap does not),
        #    plus authority exemptions across trust modes.
        h_mr = _A6StartHarness()
        h_mr.finalize_profile()
        pub_mr, defs_mr = h_mr.add_base_publication()
        cs_mr = h_mr.add_chain_started(pub_mr, defs_mr)
        dep_mr = h_mr.add_deployment(
            cs_mr,
            claimed_by=h_mr.root1,
            roots=[
                h_mr.root_entry(h_mr.root1),
                h_mr.root_entry(h_mr.root2),
            ],
            threshold=2,
        )
        # Endorsement signed by root2 (NOT claimedBy!) granting worker Observation authority.
        end_payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": h_mr.fx.defs_index[ENDORSEMENT_KIND],
            "profileRef": h_mr.prof_ref,
            "issuer": h_mr.root2.keyid,
            "actor": "urn:actor:root2",
            "stream": "urn:stream:auth",
            "seq": 1,
            "previous": None,
            "capturedAt": "2026-11-10T00:05:00Z",
            "body": {
                "subject": h_mr.worker.keyid,
                "kinds": ["provenance.r5e.io/v2/Observation"],
                "mayEndorse": False,
                "notBefore": "2026-11-10T00:00:00Z",
                "notAfter": "2026-11-10T23:00:00Z",
            },
        }
        end_ref = h_mr.fx.sign_record(end_payload, [h_mr.root2])
        obs_worker = h_mr.add_observation(
            h_mr.worker, stream="urn:stream:w1", seq=1
        )
        obs_bootstrap = h_mr.add_observation(
            h_mr.bootstrap, stream="urn:stream:w2", seq=1
        )

        rep_mr = verify_provenance_bundle(
            h_mr.fx.bundle(), trusted_chain=dep_mr, min_start_seq=2
        )
        self.assertEqual(
            self._finding(rep_mr, "authority", end_ref),
            {
                "layer": 2,
                "check": "authority",
                "subject": end_ref,
                "about": h_mr.root2.keyid,
                "result": "ok",
                "code": "ok",
            },
        )
        self.assertEqual(
            self._finding(rep_mr, "authority", obs_worker),
            {
                "layer": 2,
                "check": "authority",
                "subject": obs_worker,
                "about": end_ref,
                "result": "ok",
                "code": "ok",
            },
        )
        self.assertEqual(
            self._finding(rep_mr, "authority", obs_bootstrap)["code"],
            "no_standing",
        )
        for exempt_ref in (pub_mr, cs_mr, dep_mr):
            self.assertFalse(
                any(
                    f["check"] == "authority" and f["subject"] == exempt_ref
                    for f in rep_mr["findings"]
                )
            )

        # Without trustedRoots or trustedChain, §6.3 applies to ChainStarted and Deployment too.
        rep_no_trust = verify_provenance_bundle(
            h_mr.fx.bundle(), trusted_profiles=[h_mr.prof_ref]
        )
        for ref in (pub_mr, cs_mr, dep_mr):
            self.assertEqual(
                self._finding(rep_no_trust, "authority", ref)["code"], "ok"
            )

        # 3. §4.4 Overlap precedence: valid seq=1 & seq=2 (ref == trustedChain), plus invalid seq=3 on start stream
        #    -> any_start_failed takes precedence so A5 runs with trustedRoots=[].
        h_tail_fail = _A6StartHarness()
        h_tail_fail.finalize_profile()
        pub_tf, defs_tf = h_tail_fail.add_base_publication()
        cs_tf = h_tail_fail.add_chain_started(pub_tf, defs_tf)
        dep_tf = h_tail_fail.add_deployment(cs_tf)
        _bad_seq3 = h_tail_fail.add_observation(
            h_tail_fail.root1, stream=h_tail_fail.stream, seq=3, previous=dep_tf
        )
        obs_by_root1 = h_tail_fail.add_observation(
            h_tail_fail.root1, stream="urn:stream:rootwork", seq=1
        )
        rep_tf = verify_provenance_bundle(
            h_tail_fail.fx.bundle(), trusted_chain=dep_tf
        )
        self.assertEqual(rep_tf["start"]["headSeq"], 2)
        self.assertEqual(
            self._finding(rep_tf, "authority", obs_by_root1)["code"],
            "no_standing",
        )

        # 4. Python API & CLI option validation and mutual exclusion (exit 2).
        valid_bundle = h_ok_check = _A6StartHarness()
        valid_bundle.finalize_profile()
        pub_v, defs_v = valid_bundle.add_base_publication()
        cs_v = valid_bundle.add_chain_started(pub_v, defs_v)
        dep_v = valid_bundle.add_deployment(cs_v)
        b_dict = h_ok_check.fx.bundle()

        with self.assertRaises(ProvenanceInputError):
            verify_provenance_bundle(
                b_dict, trusted_roots=[], trusted_chain=dep_v
            )
        with self.assertRaises(ProvenanceInputError):
            verify_provenance_bundle(b_dict, trusted_chain="not-an-evidence-ref")
        with self.assertRaises(ProvenanceInputError):
            verify_provenance_bundle(b_dict, min_start_seq=1)
        with self.assertRaises(ProvenanceInputError):
            verify_provenance_bundle(b_dict, min_start_seq=True)
        with self.assertRaises(ProvenanceInputError):
            verify_provenance_bundle(b_dict, min_start_seq=MAX_SAFE_INT + 1)

        with tempfile.TemporaryDirectory() as tmp:
            bundle_path = Path(tmp) / "bundle.json"
            bundle_path.write_bytes(canonical_json_bytes(b_dict))

            def run_cli(args: list[str]) -> tuple[int, bytes, str]:
                out_buf = io.BytesIO()
                err_buf = io.StringIO()

                class _FakeStdout:
                    buffer = out_buf

                with (
                    patch("sys.stdout", _FakeStdout()),
                    patch("sys.stderr", err_buf),
                ):
                    rc = cli_main(args)
                return rc, out_buf.getvalue(), err_buf.getvalue()

            bad_cli_invocations = [
                [
                    str(bundle_path),
                    "--trusted-root",
                    valid_bundle.root1.keyid,
                    "--trusted-chain",
                    dep_v,
                ],
                [
                    str(bundle_path),
                    "--root",
                    valid_bundle.root1.keyid,
                    "--chain",
                    dep_v,
                ],
                [
                    str(bundle_path),
                    "--establish-authority",
                    "--trusted-chain",
                    dep_v,
                ],
                [
                    str(bundle_path),
                    "--trusted-chain",
                    dep_v,
                    "--chain",
                    dep_v,
                ],
                [
                    str(bundle_path),
                    "--min-start-seq",
                    "2",
                    "--min-start-seq",
                    "3",
                ],
                [str(bundle_path), "--trusted-chain", "bytes:sha256:" + "0" * 64],
                [str(bundle_path), "--min-start-seq", "1"],
                [str(bundle_path), "--min-start-seq", "two"],
            ]
            for argv in bad_cli_invocations:
                with self.subTest(argv=argv):
                    rc, out_err, err = run_cli(argv)
                    self.assertEqual(rc, 2)
                    self.assertEqual(out_err, b"")
                    self.assertTrue(len(err) > 0)

            # Happy-path CLI with --chain alias and --min-start-seq 2 exits 0 and emits canonical JSON with "start".
            rc_ok, out_ok, err_ok = run_cli(
                [
                    str(bundle_path),
                    "--trusted-publisher",
                    valid_bundle.publisher.keyid,
                    "--trusted-profile",
                    valid_bundle.prof_ref,
                    "--chain",
                    dep_v,
                    "--min-start-seq",
                    "2",
                ]
            )
            self.assertEqual(rc_ok, 0)
            self.assertEqual(err_ok, "")
            parsed_ok = json.loads(out_ok.decode("utf-8"))
            self.assertEqual(
                parsed_ok["start"],
                {
                    "chain": dep_v,
                    "deployment": "acme",
                    "headCapturedAt": "2026-11-10T00:02:00Z",
                    "headRef": dep_v,
                    "headSeq": 2,
                    "stream": valid_bundle.stream,
                },
            )
            self.assertEqual(out_ok, canonical_json_bytes(parsed_ok))


class _A6Slice2Harness(_A6StartHarness):
    """Extended helper for Amendment A6 Slice 2 (`RootsChanged`, `RootChangeApproval`, and A5 tenures)."""

    def add_roots_changed(
        self,
        *,
        chain_ref: str,
        replaces_ref: str,
        authorization: str,
        signer: Ed25519Signer,
        roots: list[dict[str, Any]],
        threshold: int = 1,
        recovery_keys: list[str] | None = None,
        custodians: list[dict[str, str]] | None = None,
        reason: str | None = None,
        stream: str | None = None,
        seq: Any = 3,
        previous: str | None = "AUTO",
        captured_at: str = "2026-11-10T00:05:00Z",
        schema_ref: str | None = None,
        body_override: dict[str, Any] | None = None,
        signers: list[Ed25519Signer | EcSigner] | None = None,
    ) -> str:
        body: dict[str, Any] = (
            body_override
            if body_override is not None
            else {
                "chain": chain_ref,
                "replaces": replaces_ref,
                "authorization": authorization,
                "signer": signer.keyid,
                "signerKey": {"algorithm": signer.alg, "bytes": b64(signer.pub)},
                "roots": roots,
                "threshold": threshold,
            }
        )
        if body_override is None:
            if recovery_keys is not None:
                body["recoveryKeys"] = recovery_keys
            if custodians is not None:
                body["custodians"] = custodians
            if reason is not None:
                body["reason"] = reason
        actual_prev = replaces_ref if previous == "AUTO" else previous
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootsChanged",
            "schemaRef": (
                schema_ref
                if schema_ref is not None
                else self.fx.defs_index[ROOTS_CHANGED_KIND]
            ),
            "profileRef": self.prof_ref,
            "issuer": signer.keyid,
            "actor": "urn:actor:node",
            "stream": stream if stream is not None else self.stream,
            "seq": seq,
            "previous": actual_prev,
            "capturedAt": captured_at,
            "body": body,
        }
        return self.fx.sign_record(payload, signers or [signer])

    def add_root_change_approval(
        self,
        *,
        change_ref: str,
        root_signer: Ed25519Signer,
        custodian: str,
        custodian_signer: Ed25519Signer,
        stream: str = "urn:stream:approval-1",
        seq: Any = 1,
        previous: str | None = None,
        captured_at: str = "2026-11-10T00:05:10Z",
        body_override: dict[str, Any] | None = None,
        signers: list[Ed25519Signer | EcSigner] | None = None,
    ) -> str:
        body: dict[str, Any] = (
            body_override
            if body_override is not None
            else {
                "change": change_ref,
                "root": root_signer.keyid,
                "custodian": custodian,
                "custodianKey": custodian_signer.keyid,
                "custodianPublicKey": {
                    "algorithm": custodian_signer.alg,
                    "bytes": b64(custodian_signer.pub),
                },
            }
        )
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RootChangeApproval",
            "schemaRef": self.fx.defs_index[ROOT_CHANGE_APPROVAL_KIND],
            "profileRef": self.prof_ref,
            "issuer": root_signer.keyid,
            "actor": "urn:actor:node",
            "stream": stream,
            "seq": seq,
            "previous": previous,
            "capturedAt": captured_at,
            "body": body,
        }
        return self.fx.sign_record(payload, signers or [root_signer, custodian_signer])

    def add_endorsement(
        self,
        issuer: Ed25519Signer,
        subject: Ed25519Signer,
        *,
        parent: str | None = None,
        kinds: list[str] | None = None,
        acts_for: str | None = None,
        stream_prefixes: list[str] | None = None,
        may_endorse: bool = False,
        not_before: str = "2026-11-10T00:00:00Z",
        not_after: str = "2026-11-11T00:00:00Z",
        captured_at: str = "2026-11-10T00:03:00Z",
        stream: str = "urn:stream:end-1",
        seq: int = 1,
        previous: str | None = None,
    ) -> str:
        body: dict[str, Any] = {
            "subject": subject.keyid,
            "kinds": (
                kinds
                if kinds is not None
                else ["provenance.r5e.io/v2/Observation"]
            ),
            "mayEndorse": may_endorse,
            "notBefore": not_before,
            "notAfter": not_after,
        }
        if acts_for is not None:
            body["actsFor"] = acts_for
        if parent is not None:
            body["parent"] = parent
        if stream_prefixes is not None:
            body["streamPrefixes"] = stream_prefixes
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Endorsement",
            "schemaRef": self.fx.defs_index[ENDORSEMENT_KIND],
            "profileRef": self.prof_ref,
            "issuer": issuer.keyid,
            "actor": "urn:actor:root",
            "stream": stream,
            "seq": seq,
            "previous": previous,
            "capturedAt": captured_at,
            "body": body,
        }
        return self.fx.sign_record(payload, [issuer])

    def add_principal(
        self,
        signer: Ed25519Signer,
        *,
        holder: str = "agent",
        identity: str = "urn:actor:bot",
        stream: str = "urn:stream:prin-1",
        captured_at: str = "2026-11-10T00:02:30Z",
    ) -> str:
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Principal",
            "schemaRef": self.fx.defs_index[PRINCIPAL_KIND],
            "profileRef": self.prof_ref,
            "issuer": signer.keyid,
            "actor": "urn:actor:node",
            "stream": stream,
            "seq": 1,
            "previous": None,
            "capturedAt": captured_at,
            "body": {
                "identity": identity,
                "key": signer.keyid,
                "publicKey": {"algorithm": signer.alg, "bytes": b64(signer.pub)},
                "holder": holder,
            },
        }
        return self.fx.sign_record(payload, [signer])

    def add_revocation(
        self,
        issuer: Ed25519Signer,
        target: str,
        *,
        stream: str = "urn:stream:rev-1",
        captured_at: str = "2026-11-10T00:04:00Z",
    ) -> str:
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Revocation",
            "schemaRef": self.fx.defs_index[REVOCATION_KIND],
            "profileRef": self.prof_ref,
            "issuer": issuer.keyid,
            "actor": "urn:actor:root",
            "stream": stream,
            "seq": 1,
            "previous": None,
            "capturedAt": captured_at,
            "body": {"target": target, "reason": "revoked"},
        }
        return self.fx.sign_record(payload, [issuer])

    def add_epoch_seal(
        self,
        sealer: Ed25519Signer,
        sealed_stream: str,
        events: list[str],
        *,
        first_seq: int = 1,
        previous_seal: str | None = None,
        seal_stream: str = "urn:stream:seal-1",
        seq: int = 1,
        previous: str | None = None,
        captured_at: str = "2026-11-10T00:04:00Z",
    ) -> str:
        last_seq = first_seq + len(events) - 1
        manifest_ref = self.fx.add_json_blob(
            {"format": PROVENANCE_EPOCH_FORMAT, "events": events}
        )
        root = merkle_root_for_events(events)
        seal_body: dict[str, Any] = {
            "stream": sealed_stream,
            "firstSeq": first_seq,
            "lastSeq": last_seq,
            "root": root,
            "manifestRef": manifest_ref,
        }
        if previous_seal is not None:
            seal_body["previousSeal"] = previous_seal
        seal_ref = self.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": self.fx.defs_index[EPOCH_SEAL_KIND],
                "profileRef": self.prof_ref,
                "issuer": sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": seal_stream,
                "seq": seq,
                "previous": previous,
                "capturedAt": captured_at,
                "body": seal_body,
            },
            [sealer],
        )
        self.fx.seals.append(seal_ref)
        return seal_ref


class RootsChangedSlice2Tests(unittest.TestCase):
    """Focused tests for Amendment A6 Slice 2 (`RootsChanged`, `RootChangeApproval`, and A5 root tenures)."""

    @staticmethod
    def _finding(
        report: dict[str, Any], check: str, subject: str
    ) -> dict[str, Any]:
        matches = [
            f
            for f in report["findings"]
            if f["check"] == check and f["subject"] == subject
        ]
        assert len(matches) == 1, f"expected 1 ({check}, {subject}), got {matches}"
        return matches[0]

    def test_tightened_terms_clauses_5_and_6_on_deployment_and_roots_changed(
        self,
    ) -> None:
        # 1. Clause 5a on Deployment: custodian key overlaps roots[*].key -> invalid_deployment_terms
        h1 = _A6Slice2Harness()
        rec_k = h1.new_signer()
        h1.finalize_profile()
        pub1, defs1 = h1.add_base_publication()
        cs1 = h1.add_chain_started(pub1, defs1)
        dep1 = h1.add_deployment(
            cs1,
            custodians=[{"identity": "mailto:alice@acme.example", "key": h1.root1.keyid}],
        )
        rep1 = verify_provenance_bundle(h1.fx.bundle(), trusted_roots=[h1.root1.keyid])
        self.assertEqual(
            self._finding(rep1, "start", dep1),
            {
                "layer": 2,
                "subject": dep1,
                "check": "start",
                "result": "failed",
                "code": "invalid_deployment_terms",
                "about": None,
            },
        )

        # 2. Clause 5b on Deployment: custodian key overlaps recoveryKeys -> invalid_deployment_terms
        h2 = _A6Slice2Harness()
        rec_k2 = h2.new_signer()
        h2.finalize_profile()
        pub2, defs2 = h2.add_base_publication()
        cs2 = h2.add_chain_started(pub2, defs2)
        dep2 = h2.add_deployment(
            cs2,
            recovery_keys=[rec_k2.keyid],
            custodians=[{"identity": "mailto:alice@acme.example", "key": rec_k2.keyid}],
        )
        rep2 = verify_provenance_bundle(h2.fx.bundle(), trusted_roots=[h2.root1.keyid])
        self.assertEqual(self._finding(rep2, "start", dep2)["code"], "invalid_deployment_terms")

        # 3. Clause 6 on Deployment: roots[*].holder == "agent" -> invalid_deployment_terms
        h3 = _A6Slice2Harness()
        h3.finalize_profile()
        pub3, defs3 = h3.add_base_publication()
        cs3 = h3.add_chain_started(pub3, defs3)
        agent_root_entry = {**h3.root_entry(h3.root1), "holder": "agent"}
        dep3 = h3.add_deployment(cs3, roots=[agent_root_entry])
        rep3 = verify_provenance_bundle(h3.fx.bundle(), trusted_roots=[h3.root1.keyid])
        self.assertEqual(self._finding(rep3, "start", dep3)["code"], "invalid_deployment_terms")

        # 4. Clauses 5 & 6 on RootsChanged (Row 20):
        #    holder="operator" succeeds, while custodian key in recoveryKeys or holder="agent" fails.
        h4 = _A6Slice2Harness()
        rec_k4 = h4.new_signer()
        rec_k4_next = h4.new_signer()
        h4.finalize_profile()
        pub4, defs4 = h4.add_base_publication()
        cs4 = h4.add_chain_started(pub4, defs4)
        dep4 = h4.add_deployment(cs4, recovery_keys=[rec_k4.keyid])
        rc_bad_cust = h4.add_roots_changed(
            chain_ref=dep4,
            replaces_ref=dep4,
            authorization="recovery",
            signer=rec_k4,
            roots=[{**h4.root_entry(h4.root2), "holder": "operator"}],
            recovery_keys=[rec_k4_next.keyid],
            custodians=[{"identity": "mailto:bob@acme.example", "key": rec_k4_next.keyid}],
        )
        rep4 = verify_provenance_bundle(h4.fx.bundle(), trusted_chain=dep4)
        self.assertEqual(
            self._finding(rep4, "start", rc_bad_cust)["code"], "invalid_deployment_terms"
        )

        h5 = _A6Slice2Harness()
        rec_k5 = h5.new_signer()
        h5.finalize_profile()
        pub5, defs5 = h5.add_base_publication()
        cs5 = h5.add_chain_started(pub5, defs5)
        dep5 = h5.add_deployment(cs5, recovery_keys=[rec_k5.keyid])
        rc_bad_holder = h5.add_roots_changed(
            chain_ref=dep5,
            replaces_ref=dep5,
            authorization="recovery",
            signer=rec_k5,
            roots=[{**h5.root_entry(h5.root2), "holder": "agent"}],
        )
        rep5 = verify_provenance_bundle(h5.fx.bundle(), trusted_chain=dep5)
        self.assertEqual(
            self._finding(rep5, "start", rc_bad_holder)["code"], "invalid_deployment_terms"
        )
        _ = rec_k

    def test_root_change_approval_rows_a1_through_a12_and_start_stream_rejection(
        self,
    ) -> None:
        # Approval placed on `:start` stream fails Row 2 (`not_a_start_record`).
        h_on_start = _A6Slice2Harness()
        cust = h_on_start.new_signer()
        h_on_start.finalize_profile()
        pub, defs = h_on_start.add_base_publication()
        cs = h_on_start.add_chain_started(pub, defs)
        dep = h_on_start.add_deployment(
            cs,
            custodians=[{"identity": "mailto:alice@acme.example", "key": cust.keyid}],
        )
        app_on_start = h_on_start.add_root_change_approval(
            change_ref=dep,
            root_signer=h_on_start.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust,
            stream=h_on_start.stream,
            seq=3,
            previous=dep,
        )
        rep_on_start = verify_provenance_bundle(h_on_start.fx.bundle(), trusted_chain=dep)
        self.assertEqual(
            self._finding(rep_on_start, "start", app_on_start),
            {
                "layer": 2,
                "subject": app_on_start,
                "check": "start",
                "result": "failed",
                "code": "not_a_start_record",
                "about": ROOT_CHANGE_APPROVAL_KIND,
            },
        )

        # Off-stream Rows A1, A2, A3, A4, A5 (non-RootsChanged & recovery), A10, A11, A12
        h = _A6Slice2Harness()
        cust1 = h.new_signer()
        cust2 = h.new_signer()
        wrong_cust_key = h.new_signer()
        stranger_root = h.new_signer()
        rec_key = h.new_signer()
        agent_root = h.new_signer()
        agent_cust = h.new_signer()
        missing_cust = Ed25519Signer(222)  # omitted from bundle.keys
        h.finalize_profile(
            issuer_keys=[k["keyid"] for k in h.fx.keys] + [missing_cust.keyid]
        )
        pub, defs = h.add_base_publication()
        cs = h.add_chain_started(pub, defs)
        dep = h.add_deployment(
            cs,
            roots=[h.root_entry(h.root1), h.root_entry(agent_root)],
            threshold=1,
            recovery_keys=[rec_key.keyid],
            custodians=[
                {"identity": "mailto:alice@acme.example", "key": cust1.keyid},
                {"identity": "mailto:agent@acme.example", "key": agent_cust.keyid},
            ],
        )
        h.add_principal(agent_root, holder="agent", stream="urn:stream:prin-root")
        h.add_principal(agent_cust, holder="agent", stream="urn:stream:prin-cust")
        rc = h.add_roots_changed(
            chain_ref=dep,
            replaces_ref=dep,
            authorization="quorum",
            signer=h.root1,
            roots=[h.root_entry(h.root2)],
        )

        # Valid approval so `rc` itself succeeds (`ok`) despite off-stream failed approvals!
        a_ok = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-ok",
        )
        # Row A1: bad signature -> invalid_root_change_approval
        a_a1 = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-a1",
        )
        h.fx.records[-1]["envelope"]["signatures"][1]["sig"] = b64(b"\x00" * 64)
        # Row A2: missing key -> unverified_root_change_approval
        a_a2 = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=missing_cust,
            stream="urn:stream:app-a2",
        )
        # Row A3a: seq != 1 -> approval_not_alone_on_stream (about = stream)
        a_a3_seq = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-a3-seq",
            seq=2,
            previous="evidence:sha256:" + "1" * 64,
        )
        # Row A3b: another record on the same stream -> approval_not_alone_on_stream
        a_a3_shared = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-a3-shared",
        )
        h.add_observation(
            h.worker,
            stream="urn:stream:app-a3-shared",
            seq=2,
            previous=a_a3_shared,
        )
        # Row A4: change not carried -> approved_change_not_carried
        missing_change = "evidence:sha256:" + "9" * 64
        a_a4 = h.add_root_change_approval(
            change_ref=missing_change,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-a4",
        )
        # Row A5: change points to Deployment (not RootsChanged at seq >= 3) -> approval_not_for_quorum_change
        a_a5_dep = h.add_root_change_approval(
            change_ref=dep,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-a5-dep",
        )
        # Row A10a: root not in T.roots -> approver_not_in_quorum (about = stranger_root.keyid)
        a_a10_nonroot = h.add_root_change_approval(
            change_ref=rc,
            root_signer=stranger_root,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-a10-nonroot",
        )
        # Row A10b: custodianKey in T.recoveryKeys -> approver_not_in_quorum (about = rec_key.keyid)
        a_a10_reckey = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=rec_key,
            stream="urn:stream:app-a10-reckey",
        )
        # Row A10c: root has Principal(holder="agent") -> approver_not_in_quorum (about = agent_root.keyid)
        a_a10_agent_root = h.add_root_change_approval(
            change_ref=rc,
            root_signer=agent_root,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust1,
            stream="urn:stream:app-a10-agent-root",
        )
        # Row A10d: custodianKey has Principal(holder="agent") -> approver_not_in_quorum (about = agent_cust.keyid)
        a_a10_agent_cust = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:agent@acme.example",
            custodian_signer=agent_cust,
            stream="urn:stream:app-a10-agent-cust",
        )
        # Row A11: custodian URI not in T.custodians -> approver_not_in_quorum (about = custodian URI)
        a_a11 = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:unknown@acme.example",
            custodian_signer=cust2,
            stream="urn:stream:app-a11",
        )
        # Row A12: pre-bound custodian key mismatch -> custodian_key_not_bound (about = wrong_cust_key.keyid)
        a_a12 = h.add_root_change_approval(
            change_ref=rc,
            root_signer=h.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=wrong_cust_key,
            stream="urn:stream:app-a12",
        )

        rep = verify_provenance_bundle(
            h.fx.bundle(),
            trusted_chain=dep,
            trusted_publishers=[h.publisher.keyid],
            trusted_profiles=[h.prof_ref],
        )
        self.assertEqual(self._finding(rep, "start", a_ok)["code"], "ok")
        self.assertEqual(self._finding(rep, "start", rc)["code"], "ok")
        # Both RootChangeApproval and RootsChanged are exempt from A5 authority under trustedChain!
        self.assertEqual(
            [
                f
                for f in rep["findings"]
                if f["check"] == "authority" and f["subject"] in {rc, a_ok, a_a1}
            ],
            [],
        )

        self.assertEqual(self._finding(rep, "start", a_a1)["code"], "invalid_root_change_approval")
        self.assertEqual(
            self._finding(rep, "start", a_a2)["code"], "unverified_root_change_approval"
        )
        self.assertEqual(
            self._finding(rep, "start", a_a3_seq),
            {
                "layer": 2,
                "subject": a_a3_seq,
                "check": "start",
                "result": "failed",
                "code": "approval_not_alone_on_stream",
                "about": "urn:stream:app-a3-seq",
            },
        )
        self.assertEqual(
            self._finding(rep, "start", a_a3_shared)["code"], "approval_not_alone_on_stream"
        )
        self.assertEqual(
            self._finding(rep, "start", a_a4),
            {
                "layer": 2,
                "subject": a_a4,
                "check": "start",
                "result": "incomplete",
                "code": "approved_change_not_carried",
                "about": missing_change,
            },
        )
        self.assertEqual(
            self._finding(rep, "start", a_a5_dep),
            {
                "layer": 2,
                "subject": a_a5_dep,
                "check": "start",
                "result": "failed",
                "code": "approval_not_for_quorum_change",
                "about": dep,
            },
        )
        self.assertEqual(
            self._finding(rep, "start", a_a10_nonroot),
            {
                "layer": 2,
                "subject": a_a10_nonroot,
                "check": "start",
                "result": "failed",
                "code": "approver_not_in_quorum",
                "about": stranger_root.keyid,
            },
        )
        self.assertEqual(
            self._finding(rep, "start", a_a10_reckey)["about"], rec_key.keyid
        )
        self.assertEqual(
            self._finding(rep, "start", a_a10_agent_root)["about"], agent_root.keyid
        )
        self.assertEqual(
            self._finding(rep, "start", a_a10_agent_cust)["about"], agent_cust.keyid
        )
        self.assertEqual(
            self._finding(rep, "start", a_a11),
            {
                "layer": 2,
                "subject": a_a11,
                "check": "start",
                "result": "failed",
                "code": "approver_not_in_quorum",
                "about": "mailto:unknown@acme.example",
            },
        )
        self.assertEqual(
            self._finding(rep, "start", a_a12),
            {
                "layer": 2,
                "subject": a_a12,
                "check": "start",
                "result": "failed",
                "code": "custodian_key_not_bound",
                "about": wrong_cust_key.keyid,
            },
        )

        # Also test Rows A5 (recovery), A6 (R body incomplete), A7 (prior missing), A8 (P.ref != replaces), A9 (P incomplete != new_roots_not_trusted)
        h_a6 = _A6Slice2Harness()
        cust_a6 = h_a6.new_signer()
        rec_a6 = h_a6.new_signer()
        unbundled_schema = "bytes:sha256:" + "7" * 64
        h_a6.finalize_profile(extra_schemas={ROOTS_CHANGED_KIND: unbundled_schema})
        pub_a6, defs_a6 = h_a6.add_base_publication()
        cs_a6 = h_a6.add_chain_started(pub_a6, defs_a6)
        dep_a6 = h_a6.add_deployment(
            cs_a6,
            recovery_keys=[rec_a6.keyid],
            custodians=[{"identity": "mailto:alice@acme.example", "key": cust_a6.keyid}],
        )
        rc_unverified_body = h_a6.add_roots_changed(
            chain_ref=dep_a6,
            replaces_ref=dep_a6,
            authorization="quorum",
            signer=h_a6.root1,
            roots=[h_a6.root_entry(h_a6.root2)],
            schema_ref=unbundled_schema,
        )
        app_a6 = h_a6.add_root_change_approval(
            change_ref=rc_unverified_body,
            root_signer=h_a6.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust_a6,
            stream="urn:stream:app-a6",
        )
        rep_a6 = verify_provenance_bundle(h_a6.fx.bundle(), trusted_chain=dep_a6)
        self.assertEqual(
            self._finding(rep_a6, "start", app_a6),
            {
                "layer": 2,
                "subject": app_a6,
                "check": "start",
                "result": "incomplete",
                "code": "unverified_start_record",
                "about": rc_unverified_body,
            },
        )

        # Row A5 (recovery), A7 (missing seq=2), A8 (replaces mismatch), A9 (P unverified_start_record)
        h_a789 = _A6Slice2Harness()
        cust_789 = h_a789.new_signer()
        rec_789 = h_a789.new_signer()
        missing_bs = Ed25519Signer(223)
        h_a789.finalize_profile(
            issuer_keys=[k["keyid"] for k in h_a789.fx.keys] + [missing_bs.keyid]
        )
        pub_789, defs_789 = h_a789.add_base_publication()
        cs_789 = h_a789.add_chain_started(pub_789, defs_789)
        dep_789 = h_a789.add_deployment(
            cs_789,
            recovery_keys=[rec_789.keyid],
            custodians=[{"identity": "mailto:alice@acme.example", "key": cust_789.keyid}],
        )
        rc_rec = h_a789.add_roots_changed(
            chain_ref=dep_789,
            replaces_ref=dep_789,
            authorization="recovery",
            signer=rec_789,
            roots=[h_a789.root_entry(h_a789.root2)],
        )
        app_for_rec = h_a789.add_root_change_approval(
            change_ref=rc_rec,
            root_signer=h_a789.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust_789,
            stream="urn:stream:app-rec",
        )
        fake_prev = "evidence:sha256:" + "5" * 64
        rc_seq4_bad_replaces = h_a789.add_roots_changed(
            chain_ref=dep_789,
            replaces_ref=fake_prev,
            authorization="quorum",
            signer=h_a789.root2,
            roots=[h_a789.root_entry(h_a789.root1)],
            seq=4,
            previous=fake_prev,
            captured_at="2026-11-10T00:06:00Z",
        )
        app_a8 = h_a789.add_root_change_approval(
            change_ref=rc_seq4_bad_replaces,
            root_signer=h_a789.root2,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust_789,
            stream="urn:stream:app-a8",
        )
        rep_78 = verify_provenance_bundle(h_a789.fx.bundle(), trusted_chain=dep_789)
        self.assertEqual(
            self._finding(rep_78, "start", app_for_rec)["code"],
            "approval_not_for_quorum_change",
        )
        self.assertEqual(
            self._finding(rep_78, "start", app_a8),
            {
                "layer": 2,
                "subject": app_a8,
                "check": "start",
                "result": "failed",
                "code": "approval_not_for_quorum_change",
                "about": rc_rec,
            },
        )
        # Drop rc_rec (seq=3) so rc_seq4_bad_replaces has no prior at seq=3 -> Row A7 prior_start_not_carried!
        b_no_seq3 = h_a789.fx.bundle()
        b_no_seq3["records"] = [r for r in b_no_seq3["records"] if r["ref"] != rc_rec]
        rep_a7 = verify_provenance_bundle(b_no_seq3, trusted_chain=dep_789)
        self.assertEqual(
            self._finding(rep_a7, "start", app_a8),
            {
                "layer": 2,
                "subject": app_a8,
                "check": "start",
                "result": "incomplete",
                "code": "prior_start_not_carried",
                "about": fake_prev,
            },
        )

        # Row A9: P has start == incomplete with unverified_start_record (Deployment missing bootstrap key)
        h_a9 = _A6Slice2Harness()
        cust_a9 = h_a9.new_signer()
        h_a9.finalize_profile(
            issuer_keys=[k["keyid"] for k in h_a9.fx.keys] + [missing_bs.keyid]
        )
        pub_a9, defs_a9 = h_a9.add_base_publication()
        cs_a9 = h_a9.add_chain_started(pub_a9, defs_a9, bootstrap=missing_bs)
        dep_a9 = h_a9.add_deployment(
            cs_a9,
            bootstrap=missing_bs,
            custodians=[{"identity": "mailto:alice@acme.example", "key": cust_a9.keyid}],
        )
        rc_a9 = h_a9.add_roots_changed(
            chain_ref=dep_a9,
            replaces_ref=dep_a9,
            authorization="quorum",
            signer=h_a9.root1,
            roots=[h_a9.root_entry(h_a9.root2)],
        )
        app_a9 = h_a9.add_root_change_approval(
            change_ref=rc_a9,
            root_signer=h_a9.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust_a9,
            stream="urn:stream:app-a9",
        )
        rep_a9 = verify_provenance_bundle(h_a9.fx.bundle(), trusted_chain=dep_a9)
        self.assertEqual(
            self._finding(rep_a9, "start", app_a9),
            {
                "layer": 2,
                "subject": app_a9,
                "check": "start",
                "result": "incomplete",
                "code": "unverified_start_record",
                "about": dep_a9,
            },
        )

    def test_late_bound_custodian_key_rows_a13_a14_a15_and_pre_change_seal(
        self,
    ) -> None:
        # Late-bound custodian entry `{identity: "mailto:alice@acme.example"}` (no `key` in Deployment)
        # 1. Row A13: no valid unrevoked pre-change Endorsement -> custodian_key_not_bound
        h13 = _A6Slice2Harness()
        cust_k = h13.new_signer()
        sealer = h13.new_signer()
        h13.finalize_profile()
        pub, defs = h13.add_base_publication()
        cs = h13.add_chain_started(pub, defs)
        dep = h13.add_deployment(
            cs, custodians=[{"identity": "mailto:alice@acme.example"}]
        )
        # Endorsement signed AFTER R.capturedAt (00:06 > 00:05) and unsealed, plus another revoked before R.capturedAt
        e_revoked = h13.add_endorsement(
            h13.root1,
            cust_k,
            kinds=[ROOT_CHANGE_APPROVAL_KIND],
            acts_for="mailto:alice@acme.example",
            captured_at="2026-11-10T00:03:00Z",
            stream="urn:stream:e-rev",
        )
        h13.add_revocation(
            h13.root1,
            e_revoked,
            captured_at="2026-11-10T00:04:00Z",
            stream="urn:stream:rev-e",
        )
        h13.add_endorsement(
            h13.root1,
            cust_k,
            kinds=[ROOT_CHANGE_APPROVAL_KIND],
            acts_for="mailto:alice@acme.example",
            captured_at="2026-11-10T00:06:00Z",
            stream="urn:stream:e-late",
        )
        rc13 = h13.add_roots_changed(
            chain_ref=dep,
            replaces_ref=dep,
            authorization="quorum",
            signer=h13.root1,
            roots=[h13.root_entry(h13.root2)],
            captured_at="2026-11-10T00:05:00Z",
        )
        app13 = h13.add_root_change_approval(
            change_ref=rc13,
            root_signer=h13.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust_k,
            captured_at="2026-11-10T00:05:10Z",
        )
        rep13 = verify_provenance_bundle(h13.fx.bundle(), trusted_chain=dep)
        self.assertEqual(
            self._finding(rep13, "start", app13),
            {
                "layer": 2,
                "subject": app13,
                "check": "start",
                "result": "failed",
                "code": "custodian_key_not_bound",
                "about": cust_k.keyid,
            },
        )
        _ = sealer

        # 2. Row A14 vs Row A15: two valid Endorsements dated < R.capturedAt;
        #    before sealing -> custodian_key_not_sealed_before_change (lowest E.ref);
        #    seal at S.capturedAt >= R.capturedAt still -> custodian_key_not_sealed_before_change;
        #    seal at S.capturedAt < R.capturedAt by root-vouched sealer -> Row A15 ok!
        h14 = _A6Slice2Harness()
        cust_k14 = h14.new_signer()
        sealer14 = h14.new_signer()
        h14.finalize_profile()
        pub14, defs14 = h14.add_base_publication()
        cs14 = h14.add_chain_started(pub14, defs14)
        dep14 = h14.add_deployment(
            cs14, custodians=[{"identity": "mailto:alice@acme.example"}]
        )
        h14.add_endorsement(
            h14.root1,
            sealer14,
            kinds=[EPOCH_SEAL_KIND],
            captured_at="2026-11-10T00:02:30Z",
            stream="urn:stream:sealer-grant",
        )
        e1 = h14.add_endorsement(
            h14.root1,
            cust_k14,
            kinds=[ROOT_CHANGE_APPROVAL_KIND],
            acts_for="mailto:alice@acme.example",
            captured_at="2026-11-10T00:03:00Z",
            stream="urn:stream:cust-e1",
        )
        e2 = h14.add_endorsement(
            h14.root1,
            cust_k14,
            kinds=[ROOT_CHANGE_APPROVAL_KIND],
            acts_for="mailto:alice@acme.example",
            captured_at="2026-11-10T00:03:30Z",
            stream="urn:stream:cust-e2",
        )
        rc14 = h14.add_roots_changed(
            chain_ref=dep14,
            replaces_ref=dep14,
            authorization="quorum",
            signer=h14.root1,
            roots=[h14.root_entry(h14.root2)],
            captured_at="2026-11-10T00:05:00Z",
        )
        app14 = h14.add_root_change_approval(
            change_ref=rc14,
            root_signer=h14.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=cust_k14,
            captured_at="2026-11-10T00:05:30Z",  # > rc14.capturedAt is allowed!
        )
        # Seal at 00:05:00Z (== R.capturedAt, not strictly < R.capturedAt) does NOT satisfy §3.5
        h14.add_epoch_seal(
            sealer14,
            "urn:stream:cust-e1",
            [e1],
            seal_stream="urn:stream:seal-too-late",
            captured_at="2026-11-10T00:05:00Z",
        )
        rep14 = verify_provenance_bundle(h14.fx.bundle(), trusted_chain=dep14)
        self.assertEqual(
            self._finding(rep14, "start", app14),
            {
                "layer": 2,
                "subject": app14,
                "check": "start",
                "result": "incomplete",
                "code": "custodian_key_not_sealed_before_change",
                "about": min(e1, e2),
            },
        )
        self.assertEqual(
            self._finding(rep14, "start", rc14)["code"], "quorum_not_carried"
        )

        # Now add pre-change seal at 00:04:00Z (< 00:05:00Z) covering e2 -> Row A15 ok & RootsChanged ok!
        h14.add_epoch_seal(
            sealer14,
            "urn:stream:cust-e2",
            [e2],
            seal_stream="urn:stream:seal-pre-change",
            captured_at="2026-11-10T00:04:00Z",
        )
        rep15 = verify_provenance_bundle(h14.fx.bundle(), trusted_chain=dep14)
        self.assertEqual(
            self._finding(rep15, "start", app14),
            {
                "layer": 2,
                "subject": app14,
                "check": "start",
                "result": "ok",
                "code": "ok",
                "about": rc14,
            },
        )
        self.assertEqual(self._finding(rep15, "start", rc14)["code"], "ok")
        self.assertEqual(rep15["start"]["headSeq"], 3)
        self.assertEqual(rep15["start"]["headRef"], rc14)
        self.assertEqual(rep15["start"]["chain"], dep14)

    def test_roots_changed_rows_3_and_21_through_35_cumulative_recovery_and_quorum_veto(
        self,
    ) -> None:
        # Row 3: RootsChanged at seq=2 -> wrong_start_position (about="seq:2")
        h_pos = _A6Slice2Harness()
        rec_pos = h_pos.new_signer()
        h_pos.finalize_profile()
        pub_p, defs_p = h_pos.add_base_publication()
        cs_p = h_pos.add_chain_started(pub_p, defs_p)
        rc_at_2 = h_pos.add_roots_changed(
            chain_ref=cs_p,
            replaces_ref=cs_p,
            authorization="recovery",
            signer=rec_pos,
            roots=[h_pos.root_entry(h_pos.root1)],
            seq=2,
            previous=cs_p,
        )
        rep_pos = verify_provenance_bundle(h_pos.fx.bundle(), trusted_roots=[h_pos.root1.keyid])
        self.assertEqual(
            self._finding(rep_pos, "start", rc_at_2),
            {
                "layer": 2,
                "subject": rc_at_2,
                "check": "start",
                "result": "failed",
                "code": "wrong_start_position",
                "about": "seq:2",
            },
        )

        # Rows 21, 22, 23, 24 (at seq=3 and seq=4), 25, 26, 28 (cumulative spent recovery key at seq=4),
        # 29 (proposer_not_a_root), 30 (quorum_not_configured), 31 (quorum veto), 32 (chain_mismatch), 34 (chain_not_trusted)
        def make_base() -> tuple[_A6Slice2Harness, str, Ed25519Signer, Ed25519Signer]:
            hb = _A6Slice2Harness()
            rk1 = hb.new_signer()
            rk2 = hb.new_signer()
            hb.finalize_profile()
            pb, df = hb.add_base_publication()
            csb = hb.add_chain_started(pb, df)
            depb = hb.add_deployment(csb, recovery_keys=[rk1.keyid, rk2.keyid])
            return hb, depb, rk1, rk2

        # Row 21: R.previous != R.body.replaces -> replaces_is_not_prior_start (about = replaces)
        h21, dep21, rk21, _ = make_base()
        rc21 = h21.add_roots_changed(
            chain_ref=dep21,
            replaces_ref=dep21,
            authorization="recovery",
            signer=rk21,
            roots=[h21.root_entry(h21.root2)],
            previous="evidence:sha256:" + "a" * 64,
        )
        rep21 = verify_provenance_bundle(h21.fx.bundle(), trusted_chain=dep21)
        self.assertEqual(
            self._finding(rep21, "start", rc21),
            {
                "layer": 2,
                "subject": rc21,
                "check": "start",
                "result": "failed",
                "code": "replaces_is_not_prior_start",
                "about": dep21,
            },
        )

        # Row 22: seq=2 omitted -> prior_start_not_carried (about = replaces)
        b22 = h21.fx.bundle()
        h22, dep22, rk22, _ = make_base()
        rc22 = h22.add_roots_changed(
            chain_ref=dep22,
            replaces_ref=dep22,
            authorization="recovery",
            signer=rk22,
            roots=[h22.root_entry(h22.root2)],
        )
        b22 = h22.fx.bundle()
        b22["records"] = [r for r in b22["records"] if r["ref"] != dep22]
        rep22 = verify_provenance_bundle(b22, trusted_chain=dep22)
        self.assertEqual(
            self._finding(rep22, "start", rc22),
            {
                "layer": 2,
                "subject": rc22,
                "check": "start",
                "result": "incomplete",
                "code": "prior_start_not_carried",
                "about": dep22,
            },
        )

        # Row 23: P.ref != replaces -> replaces_is_not_prior_start (about = P.ref)
        h23, dep23, rk23, _ = make_base()
        wrong_rep = "evidence:sha256:" + "b" * 64
        rc23 = h23.add_roots_changed(
            chain_ref=dep23,
            replaces_ref=wrong_rep,
            authorization="recovery",
            signer=rk23,
            roots=[h23.root_entry(h23.root2)],
            previous=wrong_rep,
        )
        rep23 = verify_provenance_bundle(h23.fx.bundle(), trusted_chain=dep23)
        self.assertEqual(
            self._finding(rep23, "start", rc23),
            {
                "layer": 2,
                "subject": rc23,
                "check": "start",
                "result": "failed",
                "code": "replaces_is_not_prior_start",
                "about": dep23,
            },
        )

        # Row 24 (start_chain_mismatch at seq=3 and seq=4) & Row 25 (start_timestamp_regression)
        h24, dep24, rk24, rk24_b = make_base()
        rc24_bad = h24.add_roots_changed(
            chain_ref="evidence:sha256:" + "c" * 64,
            replaces_ref=dep24,
            authorization="recovery",
            signer=rk24,
            roots=[h24.root_entry(h24.root2)],
        )
        rep24 = verify_provenance_bundle(h24.fx.bundle(), trusted_chain=dep24)
        self.assertEqual(
            self._finding(rep24, "start", rc24_bad),
            {
                "layer": 2,
                "subject": rc24_bad,
                "check": "start",
                "result": "failed",
                "code": "start_chain_mismatch",
                "about": dep24,
            },
        )

        h25, dep25, rk25, rk25_b = make_base()
        rc25_ok = h25.add_roots_changed(
            chain_ref=dep25,
            replaces_ref=dep25,
            authorization="recovery",
            signer=rk25,
            roots=[h25.root_entry(h25.root2)],
            recovery_keys=[rk25_b.keyid],
            captured_at="2026-11-10T00:05:00Z",
        )
        rc25_regress = h25.add_roots_changed(
            chain_ref=dep25,
            replaces_ref=rc25_ok,
            authorization="recovery",
            signer=rk25_b,
            roots=[h25.root_entry(h25.root1)],
            seq=4,
            captured_at="2026-11-10T00:04:59Z",  # < rc25_ok.capturedAt!
        )
        rep25 = verify_provenance_bundle(h25.fx.bundle(), trusted_chain=dep25)
        self.assertEqual(
            self._finding(rep25, "start", rc25_regress),
            {
                "layer": 2,
                "subject": rc25_regress,
                "check": "start",
                "result": "failed",
                "code": "start_timestamp_regression",
                "about": rc25_ok,
            },
        )
        _ = rk24_b

        # Row 26: P has new_roots_not_trusted under trustedRoots -> passes Row 26 so seq=4 evaluates!
        # AND Row 28: cumulative spent_recovery_keys at seq=4 rejects rk1 spent at seq=3 even when rk1 was absent from seq=3's recoveryKeys!
        h28, dep28, rk28_1, rk28_2 = make_base()
        rc28_3 = h28.add_roots_changed(
            chain_ref=dep28,
            replaces_ref=dep28,
            authorization="recovery",
            signer=rk28_1,
            roots=[h28.root_entry(h28.root2)],  # root2 NOT in trusted_roots=[root1] -> new_roots_not_trusted!
            recovery_keys=[rk28_2.keyid],
            captured_at="2026-11-10T00:05:00Z",
        )
        rc28_4 = h28.add_roots_changed(
            chain_ref=dep28,
            replaces_ref=rc28_3,
            authorization="recovery",
            signer=rk28_2,
            roots=[h28.root_entry(h28.root1)],
            recovery_keys=[rk28_1.keyid],  # rk28_1 was spent at seq=3!
            seq=4,
            captured_at="2026-11-10T00:06:00Z",
        )
        rep28_tr = verify_provenance_bundle(h28.fx.bundle(), trusted_roots=[h28.root1.keyid])
        self.assertEqual(
            self._finding(rep28_tr, "start", rc28_3)["code"], "new_roots_not_trusted"
        )
        self.assertEqual(
            self._finding(rep28_tr, "start", rc28_4),
            {
                "layer": 2,
                "subject": rc28_4,
                "check": "start",
                "result": "failed",
                "code": "spent_recovery_key_retained",
                "about": rk28_1.keyid,
            },
        )

        # Row 29 (proposer_not_a_root) & Row 30 (quorum_not_configured)
        h29, dep29, rk29, _ = make_base()
        rc29 = h29.add_roots_changed(
            chain_ref=dep29,
            replaces_ref=dep29,
            authorization="quorum",
            signer=rk29,  # not in P.roots!
            roots=[h29.root_entry(h29.root2)],
        )
        rep29 = verify_provenance_bundle(h29.fx.bundle(), trusted_chain=dep29)
        self.assertEqual(
            self._finding(rep29, "start", rc29),
            {
                "layer": 2,
                "subject": rc29,
                "check": "start",
                "result": "failed",
                "code": "proposer_not_a_root",
                "about": rk29.keyid,
            },
        )

        h30, dep30, _, _ = make_base()  # make_base has no custodians on Deployment!
        rc30 = h30.add_roots_changed(
            chain_ref=dep30,
            replaces_ref=dep30,
            authorization="quorum",
            signer=h30.root1,
            roots=[h30.root_entry(h30.root2)],
        )
        rep30 = verify_provenance_bundle(h30.fx.bundle(), trusted_chain=dep30)
        self.assertEqual(
            self._finding(rep30, "start", rc30),
            {
                "layer": 2,
                "subject": rc30,
                "check": "start",
                "result": "failed",
                "code": "quorum_not_configured",
                "about": None,
            },
        )

        # Row 31 veto rules + Rows 32 & 34:
        # 1) conflicting (c, k) pairs under the same root disqualify that root;
        # 2) two roots sharing the same custodian disqualify both;
        # 3) duplicate identical (r, c, k) approvals do NOT veto and count once!
        hq = _A6Slice2Harness()
        c_alice = hq.new_signer()
        c_bob = hq.new_signer()
        hq.finalize_profile()
        pub_q, defs_q = hq.add_base_publication()
        cs_q = hq.add_chain_started(pub_q, defs_q)
        dep_q = hq.add_deployment(
            cs_q,
            roots=[hq.root_entry(hq.root1), hq.root_entry(hq.root2)],
            threshold=2,
            custodians=[
                {"identity": "mailto:alice@acme.example", "key": c_alice.keyid},
                {"identity": "mailto:bob@acme.example", "key": c_bob.keyid},
            ],
        )
        new_root = hq.new_signer()
        rc_q = hq.add_roots_changed(
            chain_ref=dep_q,
            replaces_ref=dep_q,
            authorization="quorum",
            signer=hq.root1,
            roots=[hq.root_entry(new_root)],
        )
        # Both root1 and root2 cite alice -> shared custodian disqualifies both (quorum_count = 0 < 2)
        hq.add_root_change_approval(
            change_ref=rc_q,
            root_signer=hq.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=c_alice,
            stream="urn:stream:q-r1-alice",
        )
        a_r2_alice = hq.add_root_change_approval(
            change_ref=rc_q,
            root_signer=hq.root2,
            custodian="mailto:alice@acme.example",
            custodian_signer=c_alice,
            stream="urn:stream:q-r2-alice",
        )
        rep_shared = verify_provenance_bundle(hq.fx.bundle(), trusted_chain=dep_q)
        self.assertEqual(
            self._finding(rep_shared, "start", rc_q),
            {
                "layer": 2,
                "subject": rc_q,
                "check": "start",
                "result": "incomplete",
                "code": "quorum_not_carried",
                "about": "need:2",
            },
        )

        # Replace root2's approval with bob, plus a duplicate identical (root1, alice, c_alice) retry -> quorum_count == 2 -> ok!
        hq.fx.records = [r for r in hq.fx.records if r["ref"] != a_r2_alice]
        hq.add_root_change_approval(
            change_ref=rc_q,
            root_signer=hq.root1,
            custodian="mailto:alice@acme.example",
            custodian_signer=c_alice,
            stream="urn:stream:q-r1-alice-retry",
        )
        hq.add_root_change_approval(
            change_ref=rc_q,
            root_signer=hq.root2,
            custodian="mailto:bob@acme.example",
            custodian_signer=c_bob,
            stream="urn:stream:q-r2-bob",
        )
        rep_q_ok = verify_provenance_bundle(hq.fx.bundle(), trusted_chain=dep_q)
        self.assertEqual(self._finding(rep_q_ok, "start", rc_q)["code"], "ok")

        # Wrong trustedChain fails Deployment at seq=2 (`chain_mismatch`), which causes seq=3 Row 23 (`replaces_is_not_prior_start`)!
        wrong_chain = "evidence:sha256:" + "d" * 64
        rep_q_32 = verify_provenance_bundle(hq.fx.bundle(), trusted_chain=wrong_chain)
        self.assertEqual(
            self._finding(rep_q_32, "start", dep_q),
            {
                "layer": 2,
                "subject": dep_q,
                "check": "start",
                "result": "failed",
                "code": "chain_mismatch",
                "about": wrong_chain,
            },
        )
        self.assertEqual(
            self._finding(rep_q_32, "start", rc_q),
            {
                "layer": 2,
                "subject": rc_q,
                "check": "start",
                "result": "failed",
                "code": "replaces_is_not_prior_start",
                "about": dep_q,
            },
        )
        # Row 34: neither trustedChain nor trustedRoots -> chain_not_trusted (about = dep_q)
        rep_q_34 = verify_provenance_bundle(hq.fx.bundle())
        self.assertEqual(
            self._finding(rep_q_34, "start", rc_q),
            {
                "layer": 2,
                "subject": rc_q,
                "check": "start",
                "result": "incomplete",
                "code": "chain_not_trusted",
                "about": dep_q,
            },
        )

    def test_a5_root_tenures_readded_root_cross_root_revocation_and_post_rotation_sealer(
        self,
    ) -> None:
        # Scenario:
        #   seq=2 Deployment (00:02): root1, recovery=[rk1, rk2]
        #   seq=3 RootsChanged (00:05): root2, recovery=[rk2] (closes root1's first tenure at S_3)
        #   seq=4 RootsChanged (00:10): [root1, root2] (re-opens root1 with a second open tenure at 00:10!)
        h = _A6Slice2Harness()
        rk1 = h.new_signer()
        rk2 = h.new_signer()
        sealer = h.new_signer()
        stranger_root = h.new_signer()
        w_pre = h.new_signer()
        w_sealed = h.new_signer()
        w_unsealed = h.new_signer()
        w_readded = h.new_signer()
        w_stranger = h.new_signer()
        h.finalize_profile()

        pub, defs = h.add_base_publication()
        cs = h.add_chain_started(pub, defs)
        dep = h.add_deployment(
            cs,
            roots=[h.root_entry(h.root1)],
            recovery_keys=[rk1.keyid, rk2.keyid],
        )
        # Pre-rotation sealer grant from root1 [00:02, 01:00]
        sealer_l0_old = h.add_endorsement(
            h.root1,
            sealer,
            kinds=[EPOCH_SEAL_KIND],
            not_before="2026-11-10T00:02:00Z",
            not_after="2026-11-10T01:00:00Z",
            captured_at="2026-11-10T00:02:30Z",
            stream="urn:stream:sealer-old",
        )
        _ = sealer_l0_old

        # 1) root2 signs an Endorsement at 00:03 (< root2's admitted_at 00:05) -> not_covered!
        l0_root2_early = h.add_endorsement(
            h.root2,
            w_pre,
            captured_at="2026-11-10T00:03:00Z",
            stream="urn:stream:r2-early",
        )
        # 2) root1 signs l0_r1_sealed at 00:03, sealed by `sealer` at 00:04 (< 00:05) -> ok once root2 vouches for `sealer`!
        l0_r1_sealed = h.add_endorsement(
            h.root1,
            w_sealed,
            captured_at="2026-11-10T00:03:00Z",
            stream="urn:stream:r1-sealed",
        )
        h.add_epoch_seal(
            sealer,
            "urn:stream:r1-sealed",
            [l0_r1_sealed],
            seal_stream="urn:stream:seal-r1",
            captured_at="2026-11-10T00:04:00Z",
        )
        # 3) root1 signs l0_r1_unsealed at 00:03:30 (unsealed) -> T_latest at 00:03:30 is first tenure (ended_by=s3) -> time_rests_on_the_signer!
        l0_r1_unsealed = h.add_endorsement(
            h.root1,
            w_unsealed,
            captured_at="2026-11-10T00:03:30Z",
            stream="urn:stream:r1-unsealed",
        )

        # seq=3 RootsChanged at 00:05:00Z: root1 -> root2
        s3 = h.add_roots_changed(
            chain_ref=dep,
            replaces_ref=dep,
            authorization="recovery",
            signer=rk1,
            roots=[h.root_entry(h.root2)],
            recovery_keys=[rk2.keyid],
            seq=3,
            captured_at="2026-11-10T00:05:00Z",
        )
        # Post-rotation sealer grant from root2 with notBefore = 00:06:00Z (> seal's 00:04:00Z!)
        # satisfies §4.4 Condition 3 (`for some window` anchored at an open root tenure)!
        h.add_endorsement(
            h.root2,
            sealer,
            kinds=[EPOCH_SEAL_KIND],
            not_before="2026-11-10T00:06:00Z",
            not_after="2026-11-10T02:00:00Z",
            captured_at="2026-11-10T00:06:00Z",
            stream="urn:stream:sealer-new",
        )

        # seq=4 RootsChanged at 00:10:00Z: re-adds root1 alongside root2!
        s4 = h.add_roots_changed(
            chain_ref=dep,
            replaces_ref=s3,
            authorization="recovery",
            signer=rk2,
            roots=[h.root_entry(h.root1), h.root_entry(h.root2)],
            seq=4,
            captured_at="2026-11-10T00:10:00Z",
        )
        # 4) root1 signs l0_r1_readded at 00:12:00Z (unsealed) -> matches second open tenure -> ok!
        l0_r1_readded = h.add_endorsement(
            h.root1,
            w_readded,
            captured_at="2026-11-10T00:12:00Z",
            stream="urn:stream:r1-readded",
        )

        # 5) Stranger's parentless Endorsement revoked by active root2 -> no_standing (§4.3.2)!
        l0_stranger = h.add_endorsement(
            stranger_root,
            w_stranger,
            captured_at="2026-11-10T00:07:00Z",
            stream="urn:stream:stranger-l0",
        )
        rev_stranger_by_root2 = h.add_revocation(
            h.root2,
            l0_stranger,
            captured_at="2026-11-10T00:08:00Z",
            stream="urn:stream:rev-stranger",
        )
        # 6) Removed root1 attempting unsealed Revocation at 00:04:00Z (during closed first tenure) -> no_standing!
        l0_r2_active = h.add_endorsement(
            h.root2,
            w_pre,
            captured_at="2026-11-10T00:06:00Z",
            stream="urn:stream:r2-active",
        )
        rev_by_closed_r1_unsealed = h.add_revocation(
            h.root1,
            l0_r2_active,
            captured_at="2026-11-10T00:04:00Z",
            stream="urn:stream:rev-r1-unsealed",
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_chain=dep)
        self.assertEqual(
            rep["start"],
            {
                "chain": dep,
                "deployment": "acme",
                "headCapturedAt": "2026-11-10T00:10:00Z",
                "headRef": s4,
                "headSeq": 4,
                "stream": h.stream,
            },
        )
        self.assertEqual(
            self._finding(rep, "authority", l0_root2_early),
            {
                "layer": 2,
                "subject": l0_root2_early,
                "check": "authority",
                "result": "failed",
                "code": "not_covered",
                "about": None,
            },
        )
        self.assertEqual(self._finding(rep, "authority", l0_r1_sealed)["code"], "ok")
        self.assertEqual(
            self._finding(rep, "authority", l0_r1_unsealed),
            {
                "layer": 2,
                "subject": l0_r1_unsealed,
                "check": "authority",
                "result": "incomplete",
                "code": "time_rests_on_the_signer",
                "about": s3,
            },
        )
        self.assertEqual(self._finding(rep, "authority", l0_r1_readded)["code"], "ok")
        self.assertEqual(
            self._finding(rep, "authority", rev_stranger_by_root2),
            {
                "layer": 2,
                "subject": rev_stranger_by_root2,
                "check": "authority",
                "result": "failed",
                "code": "no_standing",
                "about": h.root2.keyid,
            },
        )
        self.assertEqual(
            self._finding(rep, "authority", rev_by_closed_r1_unsealed)["code"],
            "no_standing",
        )


class _A7RetentionHarness(_A6Slice2Harness):
    """Self-contained helper for Amendment A7 (content retention, holds, releases, disposals, multi-signer A5)."""

    def __init__(self, slug: str = "acme") -> None:
        super().__init__(slug=slug)
        self.ret_stream = f"urn:r5e:stream:{slug}:retention"
        self.work_stream = f"urn:r5e:stream:{slug}:work"
        self.gateway = self.new_signer()
        self.releaser = self.new_signer()
        self.sealer = self.new_signer()
        self._stream_heads: dict[str, tuple[int, str]] = {}

    def make_retention_profile(
        self,
        *,
        retention: dict[str, Any] | None = None,
        extra_schemas: dict[str, str] | None = None,
        issuer_keys: list[str] | None = None,
        sealer_keys: list[str] | None = None,
    ) -> str:
        schemas = dict(self.fx.defs_index)
        if extra_schemas:
            schemas.update(extra_schemas)
        allowed = issuer_keys if issuer_keys is not None else [k["keyid"] for k in self.fx.keys]
        sealers = sealer_keys if sealer_keys is not None else [self.sealer.keyid]
        profile: dict[str, Any] = {
            "format": "r5e.capture-profile/v2",
            "schemas": schemas,
            "authority": {
                "bindings": [
                    {
                        "streamPrefix": "urn:r5e:stream:",
                        "actorPrefixes": ["urn:actor:"],
                        "issuerKeys": allowed,
                        "sealerKeys": sealers,
                    },
                    {
                        "streamPrefix": "urn:stream:",
                        "actorPrefixes": ["urn:actor:"],
                        "issuerKeys": allowed,
                        "sealerKeys": sealers,
                    },
                ],
                "checkpointKeys": [],
            },
            "durability": {
                "failureDomain": "local",
                "requiredPayloads": "submitted",
                "onFailure": "refuse",
            },
            "policyRequiredKinds": [],
            "deploymentPolicyRef": self.fx.policy_ref,
        }
        if retention is not None:
            profile["retention"] = retention
        return self.fx.add_json_blob(profile)

    def _next_on(self, stream: str) -> tuple[int, str | None]:
        prev = self._stream_heads.get(stream)
        if prev is None:
            return 1, None
        return prev[0] + 1, prev[1]

    def _track(self, stream: str, seq: int, ref: str) -> str:
        self._stream_heads[stream] = (seq, ref)
        return ref

    def grant_all_retention_and_work(self) -> tuple[str, str, str, str]:
        """Grant gateway, worker, releaser, and sealer under `self.root1`."""
        gw_end = self.add_endorsement(
            self.root1,
            self.gateway,
            kinds=[
                RETENTION_HOLD_KIND,
                RETENTION_HOLD_RELEASE_KIND,
                PAYLOAD_DISPOSITION_KIND,
            ],
            stream="urn:stream:end-gw",
        )
        wk_end = self.add_endorsement(
            self.root1,
            self.worker,
            kinds=["provenance.r5e.io/v2/Observation", CHECKPOINT_KIND],
            stream="urn:stream:end-wk",
        )
        rel_end = self.add_endorsement(
            self.root1,
            self.releaser,
            kinds=[RETENTION_HOLD_RELEASE_KIND],
            stream="urn:stream:end-rel",
        )
        seal_end = self.add_endorsement(
            self.root1,
            self.sealer,
            kinds=[EPOCH_SEAL_KIND],
            stream="urn:stream:end-seal",
        )
        return gw_end, wk_end, rel_end, seal_end

    def add_action_with_refs(
        self,
        content_refs: list[str],
        *,
        profile_ref: str | None = None,
        signer: Ed25519Signer | None = None,
        stream: str | None = None,
        session: str | None = "urn:r5e:session:s1",
        captured_at: str = "2026-11-10T01:00:00Z",
        seq: int | None = None,
        previous: str | None = "AUTO",
    ) -> str:
        s = signer or self.worker
        st = stream if stream is not None else self.work_stream
        auto_seq, auto_prev = self._next_on(st)
        use_seq = seq if seq is not None else auto_seq
        use_prev = auto_prev if previous == "AUTO" else previous
        payload: dict[str, Any] = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Observation",
            "schemaRef": self.fx.defs_index["provenance.r5e.io/v2/Observation"],
            "profileRef": profile_ref if profile_ref is not None else self.prof_ref,
            "issuer": s.keyid,
            "actor": "urn:actor:worker",
            "stream": st,
            "seq": use_seq,
            "previous": use_prev,
            "capturedAt": captured_at,
            "body": {"topic": "produce", "contentRefs": content_refs},
        }
        if session is not None:
            payload["session"] = session
        ref = self.fx.sign_record(payload, [s])
        return self._track(st, use_seq, ref)

    def add_hold(
        self,
        *,
        scope: str | None = None,
        targets: list[str] | None = None,
        until: str | None = None,
        details: dict[str, Any] | None = None,
        reason: str = "legal-hold",
        signer: Ed25519Signer | None = None,
        stream: str | None = None,
        captured_at: str = "2026-11-10T01:05:00Z",
        seq: int | None = None,
        previous: str | None = "AUTO",
    ) -> str:
        s = signer or self.gateway
        st = stream if stream is not None else self.ret_stream
        auto_seq, auto_prev = self._next_on(st)
        use_seq = seq if seq is not None else auto_seq
        use_prev = auto_prev if previous == "AUTO" else previous
        body: dict[str, Any] = {"reason": reason}
        if scope is not None:
            body["scope"] = scope
        if targets is not None:
            body["targets"] = targets
        if until is not None:
            body["until"] = until
        if details is not None:
            body["details"] = details
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHold",
            "schemaRef": self.fx.defs_index[RETENTION_HOLD_KIND],
            "profileRef": self.prof_ref,
            "issuer": s.keyid,
            "actor": "urn:actor:gateway",
            "stream": st,
            "seq": use_seq,
            "previous": use_prev,
            "capturedAt": captured_at,
            "body": body,
        }
        ref = self.fx.sign_record(payload, [s])
        return self._track(st, use_seq, ref)

    def add_hold_release(
        self,
        hold_ref: str,
        *,
        gateway_signer: Ed25519Signer | None = None,
        releaser_signer: Ed25519Signer | None = None,
        signers_override: list[Ed25519Signer | EcSigner] | None = None,
        on_behalf_of: str | None = None,
        reason: str = "matter-closed",
        stream: str | None = None,
        captured_at: str = "2026-11-10T01:15:00Z",
        seq: int | None = None,
        previous: str | None = "AUTO",
    ) -> str:
        gw = gateway_signer or self.gateway
        rel = releaser_signer or self.releaser
        st = stream if stream is not None else self.ret_stream
        auto_seq, auto_prev = self._next_on(st)
        use_seq = seq if seq is not None else auto_seq
        use_prev = auto_prev if previous == "AUTO" else previous
        payload: dict[str, Any] = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "RetentionHoldRelease",
            "schemaRef": self.fx.defs_index[RETENTION_HOLD_RELEASE_KIND],
            "profileRef": self.prof_ref,
            "issuer": gw.keyid,
            "actor": "urn:actor:gateway",
            "stream": st,
            "seq": use_seq,
            "previous": use_prev,
            "capturedAt": captured_at,
            "body": {
                "hold": hold_ref,
                "releasedBy": rel.keyid,
                "reason": reason,
            },
        }
        if on_behalf_of is not None:
            payload["onBehalfOf"] = on_behalf_of
        ref = self.fx.sign_record(payload, signers_override or [gw, rel])
        return self._track(st, use_seq, ref)

    def add_disposition(
        self,
        *,
        action: str = "expired",
        scope: str | None = None,
        targets: list[str] | None = None,
        details: dict[str, Any] | None = None,
        reason: str = "ttl-elapsed",
        signer: Ed25519Signer | None = None,
        stream: str | None = None,
        captured_at: str = "2026-11-10T02:00:00Z",
        seq: int | None = None,
        previous: str | None = "AUTO",
    ) -> str:
        s = signer or self.gateway
        st = stream if stream is not None else self.ret_stream
        auto_seq, auto_prev = self._next_on(st)
        use_seq = seq if seq is not None else auto_seq
        use_prev = auto_prev if previous == "AUTO" else previous
        body: dict[str, Any] = {"action": action, "reason": reason}
        if scope is not None:
            body["scope"] = scope
        if targets is not None:
            body["targets"] = targets
        if details is not None:
            body["details"] = details
        payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "PayloadDisposition",
            "schemaRef": self.fx.defs_index[PAYLOAD_DISPOSITION_KIND],
            "profileRef": self.prof_ref,
            "issuer": s.keyid,
            "actor": "urn:actor:gateway",
            "stream": st,
            "seq": use_seq,
            "previous": use_prev,
            "capturedAt": captured_at,
            "body": body,
        }
        ref = self.fx.sign_record(payload, [s])
        return self._track(st, use_seq, ref)


class ContentRetentionA7Tests(unittest.TestCase):
    """Comprehensive unit tests for Amendment A7 (content retention, holds, releases, disposals, multi-signer A5)."""

    @staticmethod
    def _findings(report: dict[str, Any], check: str, subject: str) -> list[dict[str, Any]]:
        return [
            f
            for f in report["findings"]
            if f["check"] == check and f["subject"] == subject
        ]

    def test_target_holds_target_disposals_self_exclusion_and_rec_after_disposal(self) -> None:
        missing_b1 = bytes_ref(b"secret-payload-1")
        missing_b2 = bytes_ref(b"secret-payload-2")
        detail_b = bytes_ref(b"hold-detail-missing")

        # 1a. Target hold naming `B` and target hold naming `R.ref` + self-content exclusion on `targets`
        h = _A7RetentionHarness()
        h.prof_ref = h.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 60}
        )
        h.grant_all_retention_and_work()
        r1 = h.add_action_with_refs([missing_b1], captured_at="2026-11-10T01:00:00Z")
        r2 = h.add_action_with_refs([missing_b2], captured_at="2026-11-10T01:00:10Z")
        hold_b1 = h.add_hold(
            targets=[missing_b1],
            details={"extra": detail_b},
            captured_at="2026-11-10T01:05:00Z",
        )
        hold_r2 = h.add_hold(
            targets=[r2],
            captured_at="2026-11-10T01:06:00Z",
        )
        disp = h.add_disposition(
            scope="urn:r5e:session:s1",
            captured_at="2026-11-10T02:00:00Z",
        )
        h.add_epoch_seal(
            h.sealer,
            h.ret_stream,
            [hold_b1, hold_r2, disp],
            captured_at="2026-11-10T02:05:00Z",
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[h.root1.keyid])
        self.assertEqual(
            self._findings(rep, "content", r1),
            [
                {
                    "layer": 2,
                    "subject": r1,
                    "check": "content",
                    "result": "failed",
                    "code": "disposed_under_hold",
                    "about": hold_b1,
                }
            ],
        )
        self.assertEqual(
            self._findings(rep, "content", r2),
            [
                {
                    "layer": 2,
                    "subject": r2,
                    "check": "content",
                    "result": "failed",
                    "code": "disposed_under_hold",
                    "about": hold_r2,
                }
            ],
        )
        # `hold_b1` ignores `targets` (`missing_b1`) but still checks `details` (`detail_b`)!
        self.assertEqual(
            self._findings(rep, "content", hold_b1),
            [
                {
                    "layer": 2,
                    "subject": hold_b1,
                    "check": "content",
                    "result": "incomplete",
                    "code": "not_carried",
                    "about": detail_b,
                }
            ],
        )

        # 1b. Target disposal covers earlier `r_early` (`capturedAt <= D.capturedAt`)
        #     but NOT later `r_late` (`capturedAt > D.capturedAt`), and emits zero self-content findings!
        h2 = _A7RetentionHarness()
        h2.prof_ref = h2.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 60}
        )
        h2.grant_all_retention_and_work()
        r_early = h2.add_action_with_refs([missing_b1], captured_at="2026-11-10T01:00:00Z")
        disp_t = h2.add_disposition(
            action="deleted",
            targets=[missing_b1],
            captured_at="2026-11-10T02:00:00Z",
        )
        r_late = h2.add_action_with_refs([missing_b1], captured_at="2026-11-10T02:00:01Z")
        h2.add_epoch_seal(
            h2.sealer,
            h2.ret_stream,
            [disp_t],
            captured_at="2026-11-10T02:05:00Z",
        )

        rep2 = verify_provenance_bundle(h2.fx.bundle(), trusted_roots=[h2.root1.keyid])
        self.assertEqual(self._findings(rep2, "content", disp_t), [])
        self.assertEqual(
            self._findings(rep2, "content", r_early)[0]["code"],
            "disposed_by_record",
        )
        self.assertEqual(
            self._findings(rep2, "content", r_late)[0]["code"],
            "not_carried",
        )

    def test_hold_until_exact_boundaries_row1_and_row8_and_year9999_overflow_safety(self) -> None:
        missing_b = bytes_ref(b"boundary-content")

        # Row 1 `<` boundary: D at 01:59:59.999999999Z (< 02:00:00Z) fails; D at 02:00:00Z (== until) passes!
        for d_time, expected_res, expected_code in (
            ("2026-11-10T01:59:59.999999999Z", "failed", "disposed_under_hold"),
            ("2026-11-10T02:00:00Z", "incomplete", "disposed_by_record"),
        ):
            h = _A7RetentionHarness()
            h.prof_ref = h.make_retention_profile(
                retention={"disposal": "by-record", "keepContentForSeconds": 60}
            )
            h.grant_all_retention_and_work()
            rec = h.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
            hold = h.add_hold(
                scope="urn:r5e:session:s1",
                until="2026-11-10T02:00:00Z",
                captured_at="2026-11-10T01:05:00Z",
            )
            disp = h.add_disposition(
                scope="urn:r5e:session:s1",
                captured_at=d_time,
            )
            h.add_epoch_seal(
                h.sealer,
                h.ret_stream,
                [hold, disp],
                captured_at="2026-11-10T02:05:00Z",
            )
            rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[h.root1.keyid])
            f = self._findings(rep, "content", rec)[0]
            self.assertEqual((f["result"], f["code"]), (expected_res, expected_code))

        # Row 8 `<` boundary on T_end(H.stream), plus stranger 2099 record ignored by T_end!
        h_before = _A7RetentionHarness()
        h_before.prof_ref = h_before.make_retention_profile()
        h_before.grant_all_retention_and_work()
        stranger = h_before.new_signer()
        rec_b = h_before.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
        hold_b = h_before.add_hold(
            scope="urn:r5e:session:s1",
            until="2026-11-10T02:00:00Z",
            captured_at="2026-11-10T01:59:59.999999999Z",
        )
        # Stranger appends a RetentionHold dated 2099 on H.stream: lacks authority so does NOT count!
        h_before.add_hold(
            scope="urn:r5e:session:other",
            signer=stranger,
            captured_at="2099-01-01T00:00:00Z",
        )
        rep_before = verify_provenance_bundle(
            h_before.fx.bundle(), trusted_roots=[h_before.root1.keyid]
        )
        self.assertEqual(
            self._findings(rep_before, "content", rec_b),
            [
                {
                    "layer": 2,
                    "subject": rec_b,
                    "check": "content",
                    "result": "incomplete",
                    "code": "missing_under_hold",
                    "about": hold_b,
                }
            ],
        )

        # Now add a counting record on H.stream at exact `H.until` (`T_end == H.until`): falls through to `not_carried`!
        h_exact = _A7RetentionHarness()
        h_exact.prof_ref = h_exact.make_retention_profile()
        h_exact.grant_all_retention_and_work()
        rec_e = h_exact.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
        h_exact.add_hold(
            scope="urn:r5e:session:s1",
            until="2026-11-10T02:00:00Z",
            captured_at="2026-11-10T01:05:00Z",
        )
        h_exact.add_disposition(
            action="restored",
            scope="urn:r5e:session:s1",
            captured_at="2026-11-10T02:00:00Z",
        )
        rep_exact = verify_provenance_bundle(
            h_exact.fx.bundle(), trusted_roots=[h_exact.root1.keyid]
        )
        self.assertEqual(self._findings(rep_exact, "content", rec_e)[0]["code"], "not_carried")

        # Year-9999 + MAX_SAFE_INT `keepContentForSeconds` does not overflow calendar arithmetic
        h_9999 = _A7RetentionHarness()
        h_9999.prof_ref = h_9999.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": MAX_SAFE_INT}
        )
        h_9999.grant_all_retention_and_work()
        h_9999.add_endorsement(
            h_9999.root1,
            h_9999.worker,
            kinds=["provenance.r5e.io/v2/Observation"],
            not_before="9999-01-01T00:00:00Z",
            not_after="9999-12-31T23:59:59Z",
            captured_at="2026-11-10T00:03:00Z",
            stream="urn:stream:end-9999-wk",
        )
        h_9999.add_endorsement(
            h_9999.root1,
            h_9999.gateway,
            kinds=[PAYLOAD_DISPOSITION_KIND],
            not_before="9999-01-01T00:00:00Z",
            not_after="9999-12-31T23:59:59Z",
            captured_at="2026-11-10T00:03:00Z",
            stream="urn:stream:end-9999-gw",
        )
        rec_9999 = h_9999.add_action_with_refs(
            [missing_b], captured_at="9999-12-31T23:59:58Z"
        )
        disp_9999 = h_9999.add_disposition(
            scope="urn:r5e:session:s1", captured_at="9999-12-31T23:59:59Z"
        )
        rep_9999 = verify_provenance_bundle(
            h_9999.fx.bundle(), trusted_roots=[h_9999.root1.keyid]
        )
        self.assertEqual(
            self._findings(rep_9999, "content", rec_9999),
            [
                {
                    "layer": 2,
                    "subject": rec_9999,
                    "check": "content",
                    "result": "failed",
                    "code": "disposed_before_keep_until",
                    "about": disp_9999,
                }
            ],
        )

    def test_earliest_disposal_wins_over_later_lawful_disposal_and_restored_ignored(self) -> None:
        missing_b = bytes_ref(b"early-unlawful-disposal")
        h = _A7RetentionHarness()
        h.prof_ref = h.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 3600}
        )
        h.grant_all_retention_and_work()
        rec = h.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
        # seq 1: `action: "restored"` is never a disposal
        d_restored = h.add_disposition(
            action="restored",
            scope="urn:r5e:session:s1",
            captured_at="2026-11-10T01:05:00Z",
        )
        # seq 2: unlawful early disposal at +600s (< 3600s keepContentForSeconds)
        d_early = h.add_disposition(
            action="expired",
            scope="urn:r5e:session:s1",
            captured_at="2026-11-10T01:10:00Z",
        )
        # seq 3: later disposal at +7200s (>= 3600s) attempting to launder `d_early`
        d_late = h.add_disposition(
            action="expired",
            scope="urn:r5e:session:s1",
            captured_at="2026-11-10T03:00:00Z",
        )
        h.add_epoch_seal(
            h.sealer,
            h.ret_stream,
            [d_restored, d_early, d_late],
            captured_at="2026-11-10T03:05:00Z",
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[h.root1.keyid])
        self.assertEqual(
            self._findings(rep, "content", rec),
            [
                {
                    "layer": 2,
                    "subject": rec,
                    "check": "content",
                    "result": "failed",
                    "code": "disposed_before_keep_until",
                    "about": d_early,
                }
            ],
        )

    def test_two_missing_refs_on_one_record_and_row6_hash_chain_and_noncounting_hold(self) -> None:
        b1 = bytes_ref(b"missing-blob-one")
        b2 = bytes_ref(b"missing-blob-two")

        # Single record with TWO missing `bytes:` refs covered by same `D` -> emits TWO findings!
        h = _A7RetentionHarness()
        h.prof_ref = h.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 0}
        )
        h.grant_all_retention_and_work()
        rec = h.add_action_with_refs([b1, b2], session=None, captured_at="2026-11-10T01:00:00Z")
        # Stream-scoped (`session=None` -> `content_scope == "stream:" + work_stream`)
        disp = h.add_disposition(
            scope=f"stream:{h.work_stream}",
            captured_at="2026-11-10T01:00:00Z",
        )
        h.add_epoch_seal(
            h.sealer,
            h.ret_stream,
            [disp],
            captured_at="2026-11-10T01:05:00Z",
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[h.root1.keyid])
        c_findings = self._findings(rep, "content", rec)
        self.assertEqual(len(c_findings), 2)
        self.assertEqual(
            c_findings,
            [
                {
                    "layer": 2,
                    "subject": rec,
                    "check": "content",
                    "result": "incomplete",
                    "code": "disposed_by_record",
                    "about": disp,
                },
                {
                    "layer": 2,
                    "subject": rec,
                    "check": "content",
                    "result": "incomplete",
                    "code": "disposed_by_record",
                    "about": disp,
                },
            ],
        )

        # Row 6 hash-chain swap check: seq=1 and seq=2 both carried, but seq=2 `previous` points to an omitted hold!
        h_swap = _A7RetentionHarness()
        h_swap.prof_ref = h_swap.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 0}
        )
        h_swap.grant_all_retention_and_work()
        rec_s = h_swap.add_action_with_refs([b1], captured_at="2026-11-10T01:00:00Z")
        # Decoy record at seq=1
        h_swap.add_disposition(
            action="restored",
            scope="urn:r5e:session:other",
            seq=1,
            previous=None,
            captured_at="2026-11-10T01:01:00Z",
        )
        fake_prev = "evidence:sha256:" + ("a" * 64)
        disp_s = h_swap.add_disposition(
            scope="urn:r5e:session:s1",
            seq=2,
            previous=fake_prev,
            captured_at="2026-11-10T01:02:00Z",
        )
        # Seal `disp_s` at seq=2 via firstSeq=2 with uncarried previousSeal so epoch & seal_chain pass!
        h_swap.add_epoch_seal(
            h_swap.sealer,
            h_swap.ret_stream,
            [disp_s],
            first_seq=2,
            previous_seal="evidence:sha256:" + ("f" * 64),
            captured_at="2026-11-10T01:05:00Z",
        )
        rep_swap = verify_provenance_bundle(
            h_swap.fx.bundle(), trusted_roots=[h_swap.root1.keyid]
        )
        self.assertEqual(
            self._findings(rep_swap, "content", rec_s)[0]["code"],
            "disposed_holds_not_shown",
        )

    def test_profile_only_trust_and_pinned_chain_established_vs_unestablished(self) -> None:
        missing_b = bytes_ref(b"trust-modes-payload")

        # 6. Profile-only trust mode (`trustedProfiles` without `trustedRoots` or `trustedChain`)
        h_prof = _A7RetentionHarness()
        h_prof.prof_ref = h_prof.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 10}
        )
        rec_p = h_prof.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
        hold_p = h_prof.add_hold(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T01:00:05Z"
        )
        rel_p = h_prof.add_hold_release(hold_p, captured_at="2026-11-10T01:00:10Z")
        disp_p = h_prof.add_disposition(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T01:01:00Z"
        )
        h_prof.add_epoch_seal(
            h_prof.sealer,
            h_prof.ret_stream,
            [hold_p, rel_p, disp_p],
            captured_at="2026-11-10T01:02:00Z",
        )

        rep_prof_ok = verify_provenance_bundle(
            h_prof.fx.bundle(), trusted_profiles=[h_prof.prof_ref]
        )
        self.assertEqual(
            self._findings(rep_prof_ok, "content", rec_p)[0]["code"],
            "disposed_by_record",
        )
        # Without trusting the profile, neither the disposal nor the seal has authority -> `not_carried`!
        rep_prof_untrusted = verify_provenance_bundle(h_prof.fx.bundle(), trusted_profiles=[])
        self.assertEqual(
            self._findings(rep_prof_untrusted, "content", rec_p)[0]["code"],
            "not_carried",
        )

        # 7. Pinned `trustedChain` mode: established vs unestablished (`chain_not_carried`)
        h_chain = _A7RetentionHarness()
        h_chain.prof_ref = h_chain.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 10}
        )
        pub_ref, defs = h_chain.add_base_publication()
        cs_ref = h_chain.add_chain_started(pub_ref, defs)
        dep_ref = h_chain.add_deployment(cs_ref)
        h_chain.grant_all_retention_and_work()
        rec_c = h_chain.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
        hold_c = h_chain.add_hold(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T01:00:05Z"
        )
        rel_c = h_chain.add_hold_release(hold_c, captured_at="2026-11-10T01:00:10Z")
        disp_c = h_chain.add_disposition(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T01:01:00Z"
        )
        h_chain.add_epoch_seal(
            h_chain.sealer,
            h_chain.ret_stream,
            [hold_c, rel_c, disp_c],
            captured_at="2026-11-10T01:02:00Z",
        )

        rep_chain_est = verify_provenance_bundle(
            h_chain.fx.bundle(),
            trusted_publishers=[h_chain.publisher.keyid],
            trusted_chain=dep_ref,
        )
        self.assertEqual(
            self._findings(rep_chain_est, "content", rec_c)[0]["code"],
            "disposed_by_record",
        )

        missing_chain_ref = "evidence:sha256:" + ("f" * 64)
        rep_chain_missing = verify_provenance_bundle(
            h_chain.fx.bundle(),
            trusted_publishers=[h_chain.publisher.keyid],
            trusted_chain=missing_chain_ref,
        )
        self.assertEqual(
            self._findings(rep_chain_missing, "content", rec_c)[0]["code"],
            "not_carried",
        )

    def test_custom_two_signer_ordinary_kind_under_trusted_roots(self) -> None:
        custom_kind = "acme.example/v1/DualApproval"
        custom_def = {
            "format": KIND_DEFINITION_FORMAT,
            "kind": custom_kind,
            "description": "Two-signer ordinary approval record.",
            "conformsTo": [],
            "requiresAuthority": False,
            "substrate": "event",
            "naming": {"mode": "content"},
            "signatures": 2,
            "schema": {
                "additionalProperties": False,
                "required": ["approver", "note"],
                "nonEmpty": ["note"],
                "properties": {
                    "approver": {
                        "type": "string",
                        "pattern": "^key:[a-z0-9-]+:sha256:[0-9a-f]{64}$",
                        "matchesSigner": 2,
                    },
                    "note": {"type": "string"},
                },
            },
        }

        h = _A7RetentionHarness()
        signer1 = h.new_signer()
        signer2_ok = h.new_signer()
        signer2_stranger = h.new_signer()
        signer2_handed_over = h.new_signer()
        signer2_successor = h.new_signer()
        signer1_missing_parent = h.new_signer()

        def_ref = h.fx.add_json_blob(custom_def)
        h.prof_ref = h.make_retention_profile(extra_schemas={custom_kind: def_ref})

        end_s1 = h.add_endorsement(
            h.root1,
            signer1,
            kinds=[custom_kind],
            stream="urn:stream:end-s1",
        )
        h.add_endorsement(
            h.root1,
            signer2_ok,
            kinds=[custom_kind],
            stream="urn:stream:end-s2",
        )
        h.add_endorsement(
            h.root1,
            signer2_handed_over,
            kinds=[custom_kind],
            stream="urn:stream:end-s2h",
        )
        # Signer 2 hands over before signing `rec_handed_over`
        succ_payload = {
            "apiVersion": "provenance.r5e.io/v2",
            "kind": "Succession",
            "schemaRef": h.fx.defs_index[SUCCESSION_KIND],
            "profileRef": h.prof_ref,
            "issuer": signer2_handed_over.keyid,
            "actor": "urn:actor:worker",
            "stream": "urn:stream:succ-s2",
            "seq": 1,
            "previous": None,
            "capturedAt": "2026-11-10T00:05:00Z",
            "body": {
                "predecessor": signer2_handed_over.keyid,
                "successor": signer2_successor.keyid,
                "successorKey": {
                    "algorithm": signer2_successor.alg,
                    "bytes": b64(signer2_successor.pub),
                },
                "reason": "rotated",
            },
        }
        succ_ref = h.fx.sign_record(succ_payload, [signer2_handed_over, signer2_successor])

        # Signer 1 with a missing parent grant (`incomplete / chain_not_carried`)
        missing_parent_ref = "evidence:sha256:" + ("c" * 64)
        inter_signer = h.new_signer()
        h.add_endorsement(
            inter_signer,
            signer1_missing_parent,
            parent=missing_parent_ref,
            kinds=[custom_kind],
            stream="urn:stream:end-miss",
        )

        def make_dual(
            s1: Ed25519Signer,
            s2_body: Ed25519Signer,
            env_signers: list[Ed25519Signer | EcSigner],
            stream_suffix: str,
        ) -> str:
            payload = {
                "apiVersion": "acme.example/v1",
                "kind": "DualApproval",
                "schemaRef": def_ref,
                "profileRef": h.prof_ref,
                "issuer": s1.keyid,
                "actor": "urn:actor:worker",
                "stream": f"urn:r5e:stream:acme:{stream_suffix}",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T01:00:00Z",
                "body": {"approver": s2_body.keyid, "note": "approved"},
            }
            return h.fx.sign_record(payload, env_signers)

        rec_both_ok = make_dual(signer1, signer2_ok, [signer1, signer2_ok], "d1")
        rec_s2_stranger = make_dual(
            signer1, signer2_stranger, [signer1, signer2_stranger], "d2"
        )
        rec_inc_plus_fail = make_dual(
            signer1_missing_parent,
            signer2_stranger,
            [signer1_missing_parent, signer2_stranger],
            "d3",
        )
        rec_s2_ended = make_dual(
            signer1, signer2_handed_over, [signer1, signer2_handed_over], "d4"
        )
        rec_one_sig = make_dual(signer1, signer2_ok, [signer1], "d5")

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[h.root1.keyid])

        # Both signers ok -> `ok` with `about = end_s1`
        self.assertEqual(
            self._findings(rep, "authority", rec_both_ok),
            [
                {
                    "layer": 2,
                    "subject": rec_both_ok,
                    "check": "authority",
                    "result": "ok",
                    "code": "ok",
                    "about": end_s1,
                }
            ],
        )
        # Signer 2 stranger -> `failed / no_standing / signer2_stranger.keyid`
        self.assertEqual(
            self._findings(rep, "authority", rec_s2_stranger),
            [
                {
                    "layer": 2,
                    "subject": rec_s2_stranger,
                    "check": "authority",
                    "result": "failed",
                    "code": "no_standing",
                    "about": signer2_stranger.keyid,
                }
            ],
        )
        # Signer 1 incomplete + Signer 2 failed -> `failed` beats `incomplete`!
        self.assertEqual(
            self._findings(rep, "authority", rec_inc_plus_fail),
            [
                {
                    "layer": 2,
                    "subject": rec_inc_plus_fail,
                    "check": "authority",
                    "result": "failed",
                    "code": "no_standing",
                    "about": signer2_stranger.keyid,
                }
            ],
        )
        # Signer 2 handed over via Succession -> `failed / ended / succ_ref`
        self.assertEqual(
            self._findings(rep, "authority", rec_s2_ended),
            [
                {
                    "layer": 2,
                    "subject": rec_s2_ended,
                    "check": "authority",
                    "result": "failed",
                    "code": "ended",
                    "about": succ_ref,
                }
            ],
        )
        # 1-signature envelope claiming 2-signer kind -> body `signature_count_differs_from_definition`
        # AND authority `failed / not_covered / None`!
        self.assertEqual(
            self._findings(rep, "body", rec_one_sig)[0]["code"],
            "signature_count_differs_from_definition",
        )
        self.assertEqual(
            self._findings(rep, "authority", rec_one_sig),
            [
                {
                    "layer": 2,
                    "subject": rec_one_sig,
                    "check": "authority",
                    "result": "failed",
                    "code": "not_covered",
                    "about": None,
                }
            ],
        )

    def test_rows_3_4_5_seal_body_guard_noncounting_hold_and_row8_omissions(self) -> None:
        missing_b = bytes_ref(b"rows-3-4-5-6-8")

        # Row 3 (`disposal_dated_after_its_seal`) precedes Row 4 (`disposed_profile_not_shown`)
        h3 = _A7RetentionHarness()
        h3.prof_ref = h3.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 10}
        )
        uncarried_prof_ref = bytes_ref(b"uncarried-profile-bytes")
        h3.grant_all_retention_and_work()
        rec_r3 = h3.add_action_with_refs(
            [missing_b],
            profile_ref=uncarried_prof_ref,
            captured_at="2026-11-10T01:00:00Z",
        )
        disp_r3 = h3.add_disposition(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T02:00:00Z"
        )
        seal_before_d = h3.add_epoch_seal(
            h3.sealer,
            h3.ret_stream,
            [disp_r3],
            captured_at="2026-11-10T01:59:59Z",
        )
        rep3 = verify_provenance_bundle(h3.fx.bundle(), trusted_roots=[h3.root1.keyid])
        self.assertEqual(
            self._findings(rep3, "content", rec_r3),
            [
                {
                    "layer": 2,
                    "subject": rec_r3,
                    "check": "content",
                    "result": "failed",
                    "code": "disposal_dated_after_its_seal",
                    "about": seal_before_d,
                }
            ],
        )

        # Row 4 (`disposed_profile_not_shown`) when seal is dated >= D.capturedAt
        h4 = _A7RetentionHarness()
        h4.prof_ref = h4.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 10}
        )
        h4.grant_all_retention_and_work()
        rec_r4 = h4.add_action_with_refs(
            [missing_b],
            profile_ref=uncarried_prof_ref,
            captured_at="2026-11-10T01:00:00Z",
        )
        disp_r4 = h4.add_disposition(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T02:00:00Z"
        )
        h4.add_epoch_seal(
            h4.sealer,
            h4.ret_stream,
            [disp_r4],
            captured_at="2026-11-10T02:05:00Z",
        )
        rep4 = verify_provenance_bundle(h4.fx.bundle(), trusted_roots=[h4.root1.keyid])
        self.assertEqual(
            self._findings(rep4, "content", rec_r4),
            [
                {
                    "layer": 2,
                    "subject": rec_r4,
                    "check": "content",
                    "result": "incomplete",
                    "code": "disposed_profile_not_shown",
                    "about": uncarried_prof_ref,
                }
            ],
        )

        # Row 5 (`disposal_not_sealed`) when EpochSeal has extra unexpected body property (`body != ok`, A7 §4.6 Cond 1)
        h5 = _A7RetentionHarness()
        h5.prof_ref = h5.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 10}
        )
        h5.grant_all_retention_and_work()
        rec_r5 = h5.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
        disp_r5 = h5.add_disposition(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T02:00:00Z"
        )
        manifest_ref = h5.fx.add_json_blob({"format": PROVENANCE_EPOCH_FORMAT, "events": [disp_r5]})
        bad_seal_ref = h5.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "EpochSeal",
                "schemaRef": h5.fx.defs_index[EPOCH_SEAL_KIND],
                "profileRef": h5.prof_ref,
                "issuer": h5.sealer.keyid,
                "actor": "urn:actor:sealer",
                "stream": "urn:stream:bad-seal",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-10T02:05:00Z",
                "body": {
                    "stream": h5.ret_stream,
                    "firstSeq": 1,
                    "lastSeq": 1,
                    "root": merkle_root_for_events([disp_r5]),
                    "manifestRef": manifest_ref,
                    "unexpected": "field",
                },
            },
            [h5.sealer],
        )
        h5.fx.seals.append(bad_seal_ref)
        rep5 = verify_provenance_bundle(h5.fx.bundle(), trusted_roots=[h5.root1.keyid])
        self.assertEqual(
            self._findings(rep5, "content", rec_r5)[0]["code"],
            "disposal_not_sealed",
        )

        # Row 6 (`disposed_holds_not_shown`) when seq=1 RetentionHold lacks authority (does not count)
        h6 = _A7RetentionHarness()
        h6.prof_ref = h6.make_retention_profile(
            retention={"disposal": "by-record", "keepContentForSeconds": 10}
        )
        h6.grant_all_retention_and_work()
        unauth_hold_signer = h6.new_signer()
        rec_r6 = h6.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
        noncounting_hold = h6.add_hold(
            scope="urn:r5e:session:s1",
            signer=unauth_hold_signer,
            captured_at="2026-11-10T01:05:00Z",
        )
        disp_r6 = h6.add_disposition(
            scope="urn:r5e:session:s1", captured_at="2026-11-10T02:00:00Z"
        )
        h6.add_epoch_seal(
            h6.sealer,
            h6.ret_stream,
            [noncounting_hold, disp_r6],
            captured_at="2026-11-10T02:05:00Z",
        )
        rep6 = verify_provenance_bundle(h6.fx.bundle(), trusted_roots=[h6.root1.keyid])
        self.assertEqual(
            self._findings(rep6, "content", rec_r6)[0]["code"],
            "disposed_holds_not_shown",
        )

        # Row 8 omission exemptions: `withheld` and `not-selected` emit `omitted_*`, while `expired` emits `missing_under_hold`
        for reason, expected_code in (
            ("withheld", "omitted_withheld"),
            ("not-selected", "omitted_not_selected"),
            ("expired", "missing_under_hold"),
        ):
            h8 = _A7RetentionHarness()
            h8.prof_ref = h8.make_retention_profile()
            h8.grant_all_retention_and_work()
            rec_r8 = h8.add_action_with_refs([missing_b], captured_at="2026-11-10T01:00:00Z")
            h8.add_hold(scope="urn:r5e:session:s1", captured_at="2026-11-10T01:05:00Z")
            h8.fx.omissions.append({"ref": missing_b, "reason": reason})
            rep8 = verify_provenance_bundle(h8.fx.bundle(), trusted_roots=[h8.root1.keyid])
            self.assertEqual(self._findings(rep8, "content", rec_r8)[0]["code"], expected_code)


class AmendmentA9Tests(unittest.TestCase):
    """Comprehensive unit tests for Amendment A9 (§2.9 bounds/sets, crossChain/evidence ref, §7a seal_chain, §6.2a publisher domains)."""

    def _run_custom_def(
        self,
        schema: dict[str, Any],
        body: dict[str, Any],
        *,
        kind_path: str = "acme.example/v1/Item",
    ) -> dict[str, Any]:
        fx = ProvenanceFixtureBuilder()
        def_doc = {
            "format": KIND_DEFINITION_FORMAT,
            "kind": kind_path,
            "schema": schema,
        }
        def_ref = fx.add_json_blob(def_doc)
        prof_ref = fx.make_profile(extra_schemas={kind_path: def_ref})
        fx.add_publication(prof_ref, [{"kind": kind_path, "definition": def_ref}])
        api_version, kind = kind_path.rsplit("/", 1)
        fx.sign_record(
            {
                "apiVersion": api_version,
                "kind": kind,
                "schemaRef": def_ref,
                "profileRef": prof_ref,
                "issuer": fx.issuer.keyid,
                "actor": "urn:actor:1",
                "stream": "urn:stream:1",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-15T00:00:00Z",
                "body": body,
            },
            [fx.issuer],
        )
        return verify_provenance_bundle(
            fx.bundle(),
            trusted_profiles=[prof_ref],
            trusted_publishers=[fx.publisher.keyid],
        )

    def test_a9_definition_compile_refusals(self) -> None:
        invalid_schemas: list[dict[str, Any]] = [
            # unique on non-array or != true
            {"type": "object", "unique": True},
            {"type": "string", "unique": True},
            {"type": ["array", "string"], "unique": True},
            {"type": "array", "unique": False},
            {"type": "array", "unique": 1},
            # keys on non-object or invalid regex
            {"type": "string", "keys": "^a$"},
            {"type": "array", "keys": "^a$"},
            {"type": ["object", "string"], "keys": "^a$"},
            {"type": "object", "keys": 123},
            {"type": "object", "keys": "[unclosed"},
            # maxEntries on non-object or invalid bound
            {"type": "array", "maxEntries": 2},
            {"type": ["object", "string"], "maxEntries": 2},
            {"type": "object", "maxEntries": 0},
            {"type": "object", "maxEntries": -1},
            {"type": "object", "maxEntries": True},
            # maxLength on node admitting no string or invalid bound
            {"type": "integer", "maxLength": 10},
            {"type": "object", "maxLength": 10},
            {"type": "ref", "ref": {"bytes": True}, "maxLength": 100},
            {"type": ["integer", "boolean"], "maxLength": 10},
            {"type": "string", "maxLength": 0},
            {"type": "string", "maxLength": -5},
            {"type": "string", "maxLength": True},
            # typed ref invalid specs
            {"type": "ref", "ref": {"evidence": False}},
            {"type": "ref", "ref": {"crossChain": True}},
            {"type": "ref", "ref": {"evidence": True, "crossChain": False}},
            {"type": "ref", "ref": {"evidence": True, "bytes": True}},
        ]
        for idx, bad_schema in enumerate(invalid_schemas):
            with self.subTest(idx=idx, schema=bad_schema):
                doc = {
                    "format": KIND_DEFINITION_FORMAT,
                    "kind": "acme.example/v1/Bad",
                    "schema": bad_schema,
                }
                self.assertIsNone(parse_definition_document(canonical_json_bytes(doc)))
                rep = self._run_custom_def(bad_schema, {})
                body_f = [f for f in rep["findings"] if f["check"] == "body" and f["result"] != "ok"]
                self.assertEqual(len(body_f), 1)
                self.assertEqual(body_f[0]["result"], "incomplete")
                self.assertEqual(body_f[0]["code"], "definition_not_available")

    def test_a9_unique_keys_max_entries_max_length_utf8_bytes_and_typed_refs(self) -> None:
        schema = {
            "type": "object",
            "keys": "^[a-z][a-z0-9_]*$",
            "maxEntries": 4,
            "required": ["items", "ev_ref", "x_ref"],
            "properties": {
                "items": {"type": "array", "unique": True, "items": {"type": "object"}},
                "ev_ref": {"type": "ref", "ref": {"evidence": True}},
                "x_ref": {"type": "ref", "ref": {"evidence": True, "crossChain": True}},
            },
            "values": {"type": ["string", "integer", "boolean"], "maxLength": 4},
        }
        ev1 = "evidence:sha256:" + "a" * 64
        ev2 = "evidence:sha256:" + "b" * 64
        chain_ev = f"chain:{ev1}/{ev2}"

        # Valid: 4-byte UTF-8 emoji ("🔑") fits maxLength: 4; integer/boolean unaffected by maxLength!
        for extra_val in ("🔑", "éé", 999999, True):
            rep_ok = self._run_custom_def(
                schema,
                {
                    "items": [{"a": 1, "b": 2}, {"a": 1, "b": 3}],
                    "ev_ref": ev1,
                    "x_ref": chain_ev,
                    "extra_1": extra_val,
                },
            )
            self.assertEqual(rep_ok["summary"]["failed"], 0)

        # Valid plain same-chain evidence ref on crossChain: true
        rep_same_chain = self._run_custom_def(
            schema,
            {"items": [], "ev_ref": ev1, "x_ref": ev2},
        )
        self.assertEqual(rep_same_chain["summary"]["failed"], 0)

        bad_bodies: list[dict[str, Any]] = [
            # duplicate object items in array
            {"items": [{"x": 1, "y": 2}, {"y": 2, "x": 1}], "ev_ref": ev1, "x_ref": ev2},
            # maxLength exceeded in UTF-8 bytes ("🔑a" is 5 bytes, 2 chars!)
            {"items": [], "ev_ref": ev1, "x_ref": ev2, "extra_1": "🔑a"},
            # maxEntries exceeded (5 > 4)
            {"items": [], "ev_ref": ev1, "x_ref": ev2, "k1": 1, "k2": 2},
            # keys pattern mismatch (uppercase or trailing newline rejected by strict $)
            {"items": [], "ev_ref": ev1, "x_ref": ev2, "BadKey": 1},
            {"items": [], "ev_ref": ev1, "x_ref": ev2, "good\n": 1},
            # evidence: true rejects bytes: and rejects chain:... when crossChain not set
            {"items": [], "ev_ref": "bytes:sha256:" + "a" * 64, "x_ref": ev2},
            {"items": [], "ev_ref": chain_ev, "x_ref": ev2},
            # crossChain rejects label chain name, nested chain:, wrong target ref kind, missing slash
            {"items": [], "ev_ref": ev1, "x_ref": f"chain:dev-chain/{ev2}"},
            {"items": [], "ev_ref": ev1, "x_ref": f"chain:{ev1}/chain:{ev1}/{ev2}"},
            {"items": [], "ev_ref": ev1, "x_ref": f"chain:{ev1}/bytes:sha256:" + "b" * 64},
            {"items": [], "ev_ref": ev1, "x_ref": f"chain:{ev1}"},
        ]
        for idx, bad_body in enumerate(bad_bodies):
            with self.subTest(idx=idx, bad_body=bad_body):
                rep_bad = self._run_custom_def(schema, bad_body)
                self.assertTrue(
                    any(
                        f["check"] == "body" and f["code"] == "body_does_not_match_definition"
                        for f in rep_bad["findings"]
                    )
                )

    def test_a9_seal_chain_excludes_failed_seal_from_a5_authority_even_via_proof(self) -> None:
        h = _A5Harness()
        root1 = h.new_signer()
        worker = h.new_signer()
        sealer = h.new_signer()
        h.finalize_profile()
        end_w = h.add_endorsement(
            root1,
            worker,
            kinds=["provenance.r5e.io/v2/Observation"],
            stream="urn:stream:end-w",
        )
        h.add_endorsement(
            root1,
            sealer,
            kinds=[EPOCH_SEAL_KIND],
            stream="urn:stream:end-s",
        )
        # Worker acts at seq=2 (with uncarried seq=1) before root1 revokes end_w at 05:00Z
        obs = h.fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "Observation",
                "schemaRef": h.fx.defs_index["provenance.r5e.io/v2/Observation"],
                "profileRef": h.prof_ref,
                "issuer": worker.keyid,
                "actor": "urn:actor:worker",
                "stream": "urn:stream:work",
                "seq": 2,
                "previous": "evidence:sha256:" + "1" * 64,
                "capturedAt": "2026-11-10T02:00:00Z",
                "body": {"topic": "obs", "contentRefs": []},
            },
            [worker],
        )
        rev = h.add_revocation(
            root1,
            end_w,
            stream="urn:stream:rev",
            captured_at="2026-11-10T05:00:00Z",
        )
        # Seal at firstSeq=2 WITHOUT previousSeal via membership proof (`membership: ok`, `seal_chain: failed`)!
        seal_ref = h.add_membership_seal(
            sealer,
            "urn:stream:work",
            obs,
            first_seq=2,
            captured_at="2026-11-10T03:00:00Z",
        )
        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[root1.keyid])
        sc_f = [f for f in rep["findings"] if f["check"] == "seal_chain" and f["subject"] == seal_ref]
        self.assertEqual(len(sc_f), 1)
        self.assertEqual(sc_f[0]["result"], "failed")
        self.assertEqual(sc_f[0]["code"], "seal_predecessor_missing")
        self.assertIsNone(sc_f[0]["about"])

        # Membership proof itself is ok, yet obs's authority is NOT corroborated -> time_rests_on_the_signer!
        mem_f = [f for f in rep["findings"] if f["check"] == "membership" and f["subject"] == obs]
        self.assertEqual(mem_f[0]["result"], "ok")
        auth_f = [f for f in rep["findings"] if f["check"] == "authority" and f["subject"] == obs]
        self.assertEqual(auth_f[0]["result"], "incomplete")
        self.assertEqual(auth_f[0]["code"], "time_rests_on_the_signer")
        self.assertEqual(auth_f[0]["about"], rev)

    def test_a9_publisher_domains_union_chain_started_and_cli_publisher_flag(self) -> None:
        # 1. ChainStarted naming a publisher believed about r5e.io only when ChainStarted also lists acme.example kind
        h = _A6StartHarness()
        custom_kind = "acme.example/v1/Extra"
        custom_def_ref = h.fx.add_json_blob(
            {"format": KIND_DEFINITION_FORMAT, "kind": custom_kind, "schema": {"type": "object"}}
        )
        h.fx.defs_index[custom_kind] = custom_def_ref
        h.finalize_profile()
        pub_ref, base_defs = h.add_base_publication()
        cs_ref = h.add_chain_started(pub_ref, base_defs)

        # Believed about r5e.io only -> ChainStarted gets publisher_not_trusted!
        rep_partial = verify_provenance_bundle(
            h.fx.bundle(),
            trusted_publishers=[f"{h.publisher.keyid}=r5e.io"],
        )
        cs_pub_f = next(
            f for f in rep_partial["findings"] if f["check"] == "publication" and f["subject"] == cs_ref
        )
        self.assertEqual(cs_pub_f["result"], "incomplete")
        self.assertEqual(cs_pub_f["code"], "publisher_not_trusted")
        self.assertEqual(cs_pub_f["about"], pub_ref)

        # Repeated key id entries union domains (`r5e.io` + `acme.example`) -> ChainStarted gets publication: ok!
        rep_union = verify_provenance_bundle(
            h.fx.bundle(),
            trusted_publishers=[
                f"{h.publisher.keyid}=r5e.io",
                f"{h.publisher.keyid}=acme.example",
            ],
        )
        cs_pub_ok = next(
            f for f in rep_union["findings"] if f["check"] == "publication" and f["subject"] == cs_ref
        )
        self.assertEqual(cs_pub_ok["result"], "ok")
        self.assertEqual(cs_pub_ok["about"], pub_ref)

        # Bare key id + domain entry (in either order) -> believed about all domains!
        for order in (
            [h.publisher.keyid, f"{h.publisher.keyid}=r5e.io"],
            [f"{h.publisher.keyid}=r5e.io", h.publisher.keyid],
        ):
            rep_all = verify_provenance_bundle(h.fx.bundle(), trusted_publishers=order)
            f_all = next(
                f for f in rep_all["findings"] if f["check"] == "publication" and f["subject"] == cs_ref
            )
            self.assertEqual(f_all["result"], "ok")

        # CLI `--publisher` flag (both `--publisher KEY=dom` and `--publisher=KEY=dom`) + invalid domain refusal
        with tempfile.TemporaryDirectory() as tmp:
            bpath = Path(tmp) / "bundle.json"
            bpath.write_bytes(canonical_json_bytes(h.fx.bundle()))
            out_buf = io.BytesIO()
            err_buf = io.StringIO()
            with (
                patch("sys.stdout", new=type("S", (), {"buffer": out_buf})()),
                patch("sys.stderr", new=err_buf),
            ):
                rc = cli_main(
                    [
                        str(bpath),
                        "--publisher",
                        f"{h.publisher.keyid}=r5e.io",
                        f"--publisher={h.publisher.keyid}=acme.example",
                    ]
                )
            self.assertIn(rc, (0, 3))
            cli_rep = parse_canonical_json(out_buf.getvalue())
            self.assertTrue(json_eq(cli_rep, rep_union))

            for bad_pub in ("=r5e.io", f"{h.publisher.keyid}=", f"{h.publisher.keyid}=a,,b"):
                err_b = io.StringIO()
                with patch("sys.stderr", new=err_b):
                    rc_bad = cli_main([str(bpath), "--publisher", bad_pub])
                self.assertEqual(rc_bad, 2)

    def test_astral_object_key_in_signed_payload_fails_payload_not_canonical(self) -> None:
        fx = ProvenanceFixtureBuilder()
        prof_ref = fx.make_profile()
        payload_dict = {
            "actor": "urn:actor:1",
            "apiVersion": "provenance.r5e.io/v2",
            "body": {
                "contentRefs": [],
                "details": {"a": "1", "\U0001f511": "v"},
                "topic": "astral.key",
            },
            "capturedAt": "2026-11-15T12:00:00Z",
            "issuer": fx.issuer.keyid,
            "kind": "Observation",
            "previous": None,
            "profileRef": prof_ref,
            "schemaRef": fx.defs_index["provenance.r5e.io/v2/Observation"],
            "seq": 1,
            "stream": "urn:stream:1",
        }
        raw_payload = json.dumps(
            payload_dict, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        rec_ref = fx.sign_record(payload_dict, [fx.issuer], raw_payload_override=raw_payload)
        rep = verify_provenance_bundle(fx.bundle(), trusted_profiles=[prof_ref])
        self.assertEqual(
            rep,
            {
                "format": "r5e.provenance-verify-report/v2",
                "summary": {"ok": 0, "failed": 1, "incomplete": 0},
                "findings": [
                    {
                        "layer": 1,
                        "subject": rec_ref,
                        "check": "identity",
                        "result": "failed",
                        "code": "payload_not_canonical",
                        "about": None,
                    }
                ],
            },
        )

    def test_a9_publication_outside_domain_and_malformed_definitions_safety(self) -> None:
        fx = ProvenanceFixtureBuilder()
        cust_pub = Ed25519Signer(77)
        fx.keys.append(cust_pub.key_entry())
        custom_kind = "acme.example/v1/Item"
        custom_def = fx.add_json_blob(
            {"format": KIND_DEFINITION_FORMAT, "kind": custom_kind, "schema": {"type": "object"}}
        )
        prof_ref = fx.make_profile(
            extra_schemas={custom_kind: custom_def},
            issuer_keys=[fx.issuer.keyid, fx.publisher.keyid, cust_pub.keyid],
        )
        r5e_pub_ref = fx.add_publication(
            prof_ref,
            [{"kind": k, "definition": d} for k, d in sorted(fx.defs_index.items())],
            signer=fx.publisher,
            stream="urn:stream:pub-r5e",
        )
        # Customer publisher lists ONLY acme.example/v1/Item -> ok (about r5e_pub_ref)!
        cust_in_dom = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "DefinitionPublished",
                "schemaRef": fx.defs_index[DEFINITION_PUBLISHED_KIND],
                "profileRef": prof_ref,
                "issuer": cust_pub.keyid,
                "actor": "urn:actor:pub",
                "stream": "urn:stream:pub-cust-ok",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-15T00:00:00Z",
                "body": {"definitions": [{"kind": custom_kind, "definition": custom_def}]},
            },
            [cust_pub],
        )
        # Customer publisher ALSO lists an r5e.io kind -> incomplete / publisher_not_trusted (about itself)!
        cust_out_dom = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "DefinitionPublished",
                "schemaRef": fx.defs_index[DEFINITION_PUBLISHED_KIND],
                "profileRef": prof_ref,
                "issuer": cust_pub.keyid,
                "actor": "urn:actor:pub",
                "stream": "urn:stream:pub-cust-bad",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-15T00:00:00Z",
                "body": {
                    "definitions": [
                        {"kind": custom_kind, "definition": custom_def},
                        {
                            "kind": DEFINITION_PUBLISHED_KIND,
                            "definition": fx.defs_index[DEFINITION_PUBLISHED_KIND],
                        },
                    ]
                },
            },
            [cust_pub],
        )
        # Malformed DefinitionPublished body with non-dict / non-string kind does not crash!
        cust_malformed = fx.sign_record(
            {
                "apiVersion": "provenance.r5e.io/v2",
                "kind": "DefinitionPublished",
                "schemaRef": fx.defs_index[DEFINITION_PUBLISHED_KIND],
                "profileRef": prof_ref,
                "issuer": cust_pub.keyid,
                "actor": "urn:actor:pub",
                "stream": "urn:stream:pub-cust-mal",
                "seq": 1,
                "previous": None,
                "capturedAt": "2026-11-15T00:00:00Z",
                "body": {"definitions": [123, {"kind": 456}]},
            },
            [cust_pub],
        )
        rep = verify_provenance_bundle(
            fx.bundle(),
            trusted_profiles=[prof_ref],
            trusted_publishers=[f"{fx.publisher.keyid}=r5e.io", f"{cust_pub.keyid}=acme.example"],
        )
        pub_by_subj = {
            f["subject"]: f for f in rep["findings"] if f["check"] == "publication"
        }
        self.assertEqual(pub_by_subj[cust_in_dom]["result"], "ok")
        self.assertEqual(pub_by_subj[cust_in_dom]["about"], r5e_pub_ref)
        self.assertEqual(pub_by_subj[cust_out_dom]["result"], "incomplete")
        self.assertEqual(pub_by_subj[cust_out_dom]["code"], "publisher_not_trusted")
        self.assertEqual(pub_by_subj[cust_out_dom]["about"], cust_out_dom)
        self.assertEqual(pub_by_subj[cust_malformed]["result"], "ok")

    def test_a9_seal_ranges_overlap_precedence_lowest_ref_and_cover_exclusion(self) -> None:
        h = _A5Harness()
        root1 = h.new_signer()
        worker = h.new_signer()
        sealer = h.new_signer()
        h.finalize_profile()
        end_w = h.add_endorsement(
            root1,
            worker,
            kinds=["provenance.r5e.io/v2/Observation"],
            stream="urn:stream:end-w",
        )
        h.add_endorsement(
            root1,
            sealer,
            kinds=[EPOCH_SEAL_KIND],
            stream="urn:stream:end-s",
        )
        r1 = h.add_observation(
            worker, stream="urn:stream:work", captured_at="2026-11-10T02:00:00Z"
        )
        r2 = h.add_observation(
            worker, stream="urn:stream:work", captured_at="2026-11-10T02:01:00Z"
        )
        r3 = h.add_observation(
            worker, stream="urn:stream:work", captured_at="2026-11-10T02:02:00Z"
        )
        rev = h.add_revocation(
            root1,
            end_w,
            stream="urn:stream:rev",
            captured_at="2026-11-10T05:00:00Z",
        )
        # s_full seals 1..3 (no predecessor finding -> replaced by overlap)
        s_full = h.add_epoch_seal(
            sealer, "urn:stream:work", [r1, r2, r3], first_seq=1, captured_at="2026-11-10T03:00:00Z"
        )
        # s_one seals 1..1 (no predecessor finding -> replaced by overlap)
        s_one = h.add_epoch_seal(
            sealer, "urn:stream:work", [r1], first_seq=1, captured_at="2026-11-10T03:01:00Z"
        )
        # s_adj seals 2..3 with previousSeal=s_one (predecessor check WAS `ok` -> replaced by overlap with s_full!)
        s_adj = h.add_epoch_seal(
            sealer,
            "urn:stream:work",
            [r2, r3],
            first_seq=2,
            previous_seal=s_one,
            captured_at="2026-11-10T03:02:00Z",
        )
        # s_missing_pred seals 2..2 WITHOUT previousSeal (predecessor failure stands over overlap!)
        s_missing_pred = h.add_epoch_seal(
            sealer, "urn:stream:work", [r2], first_seq=2, captured_at="2026-11-10T03:03:00Z"
        )

        rep = verify_provenance_bundle(h.fx.bundle(), trusted_roots=[root1.keyid])
        sc_findings = [f for f in rep["findings"] if f["check"] == "seal_chain"]
        # Exactly ONE seal_chain finding per seal!
        self.assertEqual(len(sc_findings), 4)
        sc_by_subj = {f["subject"]: f for f in sc_findings}

        # s_missing_pred keeps `seal_predecessor_missing` (predecessor failure stands)
        self.assertEqual(sc_by_subj[s_missing_pred]["code"], "seal_predecessor_missing")
        self.assertIsNone(sc_by_subj[s_missing_pred]["about"])

        # s_full overlaps s_one, s_adj, and s_missing_pred -> about = lowest ref in byte order!
        expected_lowest_for_full = min(
            [s_one, s_adj, s_missing_pred], key=lambda r: r.encode("utf-8")
        )
        self.assertEqual(sc_by_subj[s_full]["code"], "seal_ranges_overlap")
        self.assertEqual(sc_by_subj[s_full]["about"], expected_lowest_for_full)

        # s_one overlaps only s_full
        self.assertEqual(sc_by_subj[s_one]["code"], "seal_ranges_overlap")
        self.assertEqual(sc_by_subj[s_one]["about"], s_full)

        # s_adj had `ok` on predecessor check, replaced by `seal_ranges_overlap` (overlaps s_full & s_missing_pred)
        expected_lowest_for_adj = min([s_full, s_missing_pred], key=lambda r: r.encode("utf-8"))
        self.assertEqual(sc_by_subj[s_adj]["code"], "seal_ranges_overlap")
        self.assertEqual(sc_by_subj[s_adj]["about"], expected_lowest_for_adj)

        # Every seal on urn:stream:work failed seal_chain, so NONE fixes r1/r2/r3 in time before rev!
        for r_ref in (r1, r2, r3):
            auth_f = next(
                f for f in rep["findings"] if f["check"] == "authority" and f["subject"] == r_ref
            )
            self.assertEqual(auth_f["result"], "incomplete")
            self.assertEqual(auth_f["code"], "time_rests_on_the_signer")
            self.assertEqual(auth_f["about"], rev)


class R5eApiBlock0ProfileTests(unittest.TestCase):
    GENESIS_BUNDLE = (
        Path(__file__).resolve().parent.parent / "genesis" / "r5e-api" / "block-0-r5e-api.json"
    )
    EXPECTED_REPORT_SHA256 = "c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed"
    ROOT_KEY_ID = (
        "key:ed25519:sha256:aeb2f4f7d81d87ce8e9f437fa5bada43d41d7cf5badcceffdf37403ddfee53fc"
    )

    def _run_cli(self, argv: list[str]) -> tuple[int, bytes, str]:
        out_buf = io.BytesIO()
        err_buf = io.StringIO()

        class _StdOut:
            buffer = out_buf

        with (
            patch("sys.stdout", _StdOut()),
            patch("sys.stderr", err_buf),
        ):
            code = cli_main(argv)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_default_trust_remains_empty_on_block0(self) -> None:
        code, out_bytes, err = self._run_cli([str(self.GENESIS_BUNDLE)])
        self.assertEqual(err, "")
        self.assertEqual(code, 3)
        rep = json.loads(out_bytes.decode("utf-8"))
        self.assertEqual(rep["summary"]["failed"], 0)
        self.assertGreater(rep["summary"]["incomplete"], 0)
        pub_findings = [f for f in rep["findings"] if f["check"] == "publication"]
        self.assertTrue(
            any(f.get("code") == "publisher_not_trusted" for f in pub_findings),
            "default trust must not trust r5e.io publisher without --profile r5e-api",
        )

    def test_opt_in_profile_r5e_api_verifies_block0_canonical_report(self) -> None:
        for flag_args in (["--profile", "r5e-api"], ["--profile=r5e-api"]):
            with self.subTest(flag_args=flag_args):
                code, out_bytes, err = self._run_cli([str(self.GENESIS_BUNDLE), *flag_args])
                self.assertEqual(err, "")
                self.assertEqual(code, 0)
                self.assertEqual(
                    hashlib.sha256(out_bytes).hexdigest(),
                    self.EXPECTED_REPORT_SHA256,
                )
                rep = json.loads(out_bytes.decode("utf-8"))
                self.assertEqual(rep["summary"], {"failed": 0, "incomplete": 0, "ok": 122})

    def test_opt_in_profile_r5e_api_with_explicit_root_overrides_chain(self) -> None:
        code, out_bytes, err = self._run_cli(
            [str(self.GENESIS_BUNDLE), "--profile", "r5e-api", "--root", self.ROOT_KEY_ID]
        )
        self.assertEqual(err, "")
        self.assertEqual(code, 0)
        self.assertEqual(hashlib.sha256(out_bytes).hexdigest(), self.EXPECTED_REPORT_SHA256)
        rep = json.loads(out_bytes.decode("utf-8"))
        self.assertEqual(rep["summary"], {"failed": 0, "incomplete": 0, "ok": 122})

    def test_unknown_or_duplicate_profile_fails_closed(self) -> None:
        code_bad, _, err_bad = self._run_cli([str(self.GENESIS_BUNDLE), "--profile", "unknown"])
        self.assertEqual(code_bad, 2)
        self.assertIn("unknown --profile", err_bad)

        code_dup, _, err_dup = self._run_cli(
            [str(self.GENESIS_BUNDLE), "--profile", "r5e-api", "--profile", "r5e-api"]
        )
        self.assertEqual(code_dup, 2)
        self.assertIn("more than once", err_dup)


if __name__ == "__main__":
    unittest.main()
