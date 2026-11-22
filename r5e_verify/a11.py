"""Amendment A11 offline verification rules (V1–V11) and finding classification."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .provenance import (
    BASIS_KIND,
    BASIS_OVERLAY_KIND,
    BYTES_REF_RE,
    CHAIN_STARTED_KIND,
    CHECKPOINT_KIND,
    DEFINITION_PUBLISHED_KIND,
    DEPLOYMENT_KIND,
    ENDORSEMENT_KIND,
    EPOCH_SEAL_KIND,
    ERASURE_ANSWER_KIND,
    PROVENANCE_REPORT_FORMAT,
    RELEASE_RECEIPT_KIND,
    RELEASE_REQUEST_KIND,
    RETENTION_HOLD_KIND,
    REVOCATION_KIND,
    ROOT_CHANGE_APPROVAL_KIND,
    ROOTS_CHANGED_KIND,
    SALTED_BYTES_REF_RE,
    SUCCESSION_KIND,
    Instant,
    _is_utc_rfc3339,
    _load_base_definitions,
    _load_bundled_schemas,
    _validate_bundle_shape,
    bytes_ref,
    canonical_json_bytes,
    compute_key_id,
    decode_base64,
    decode_strict_base64,
    parse_canonical_json,
    parse_rfc3339_instant,
    verify_provenance_bundle_baseline,
    verify_record_envelope,
    verify_signature,
)

DISCLOSURE_KIND = "provenance.r5e.io/v2/Disclosure"
SESSION_CLOSED_KIND = "provenance.r5e.io/v2/SessionClosed"
SESSION_OPENED_KIND = "provenance.r5e.io/v2/SessionOpened"

CATEGORY_CRYPTOGRAPHIC_PROOF = "cryptographic_proof"
CATEGORY_MECHANICAL_CHECK = "mechanical_check"
CATEGORY_INSTITUTIONAL_ASSERTION = "institutional_assertion"
CATEGORY_UNAVAILABLE_EVIDENCE = "unavailable_evidence"

VALID_CATEGORIES: frozenset[str] = frozenset(
    {
        CATEGORY_CRYPTOGRAPHIC_PROOF,
        CATEGORY_MECHANICAL_CHECK,
        CATEGORY_INSTITUTIONAL_ASSERTION,
        CATEGORY_UNAVAILABLE_EVIDENCE,
    }
)

_EXCLUDED_GOVERNANCE_KINDS: frozenset[str] = frozenset(
    {
        DEFINITION_PUBLISHED_KIND,
        DEPLOYMENT_KIND,
        CHAIN_STARTED_KIND,
        ROOTS_CHANGED_KIND,
        ROOT_CHANGE_APPROVAL_KIND,
        ENDORSEMENT_KIND,
        SUCCESSION_KIND,
        REVOCATION_KIND,
        CHECKPOINT_KIND,
        EPOCH_SEAL_KIND,
        BASIS_KIND,
        BASIS_OVERLAY_KIND,
        RELEASE_REQUEST_KIND,
        RELEASE_RECEIPT_KIND,
        ERASURE_ANSWER_KIND,
    }
)

_UNAVAILABLE_CODES: frozenset[str] = frozenset(
    {
        "unavailable_evidence",
        "not_carried",
        "content_not_carried",
        "publication_not_carried",
        "manifest_not_carried",
        "missing_key",
        "definition_not_available",
        "profile_not_available",
        "chain_not_carried",
        "basis_ref_missing",
        "until_event_unverified",
        "release_target_missing",
        "witness_request_missing",
        "erasure_copy_confirmation_pending",
        "salted_content_omitted",
    }
)

_INSTITUTIONAL_CODES: frozenset[str] = frozenset(
    {
        "profile_not_trusted",
        "basis_person_signed_by_device_session",
        "hardware_attestation_unverified",
    }
)

_CRYPTO_CODES: frozenset[str] = frozenset(
    {
        "approval_signature_invalid",
        "witness_receipt_hash_mismatch",
        "witness_unpinned",
        "witness_request_wrong_kind",
        "succession_recovery_threshold_not_met",
        "succession_recovery_rule_unknown",
        "succession_institution_only_rejected",
        "succession_signer_mismatch",
        "erasure_proof_invalid_or_missing_l2",
        "erasure_unknown_copy_id",
        "erasure_institution_claim_at_l2",
        "salted_content_digest_mismatch",
        "checkpoint_fork_or_stale",
    }
)

_CRYPTO_CHECKS: frozenset[str] = frozenset(
    {
        "identity",
        "signature",
        "content_hash",
        "epoch",
        "merkle",
        "membership",
        "salted_content_ref",
        "witness_receipt_binding",
        "succession_recovery",
        "erasure_l2_proof",
    }
)


def classify_finding(finding: dict[str, Any]) -> str:
    """Classify a baseline or A11 verifier finding into one of the four A11 categories."""
    existing = finding.get("category")
    if isinstance(existing, str) and existing in VALID_CATEGORIES:
        return existing

    code = finding.get("code")
    check = finding.get("check")
    result = finding.get("result")

    if code in _INSTITUTIONAL_CODES:
        return CATEGORY_INSTITUTIONAL_ASSERTION
    if code in _UNAVAILABLE_CODES:
        return CATEGORY_UNAVAILABLE_EVIDENCE
    if result == "incomplete" and check in (
        "content",
        "publication",
        "epoch",
        "signature",
        "body",
        "schema",
        "authority",
        "start",
        "merkle",
        "membership",
        "profile",
        "profile_bounds",
        "retention",
    ):
        return CATEGORY_UNAVAILABLE_EVIDENCE
    if code in _CRYPTO_CODES:
        return CATEGORY_CRYPTOGRAPHIC_PROOF
    if check in _CRYPTO_CHECKS:
        return CATEGORY_CRYPTOGRAPHIC_PROOF
    if check == "content":
        return CATEGORY_CRYPTOGRAPHIC_PROOF
    return CATEGORY_MECHANICAL_CHECK


def _a11_finding(
    layer: int,
    subject: str,
    check: str,
    result: str,
    code: str,
    category: str,
    about: str | None = None,
) -> dict[str, Any]:
    return {
        "about": about,
        "category": category,
        "check": check,
        "code": code,
        "layer": layer,
        "result": result,
        "subject": subject,
    }


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str, str, int, str]:
    about = finding.get("about")
    return (
        int(finding["layer"]),
        str(finding["subject"]),
        str(finding["check"]),
        str(finding["code"]),
        0 if about is None else 1,
        "" if about is None else str(about),
    )


def _safe_int(value: Any, default: int = 0) -> int:
    return value if type(value) is int else default


def _safe_canonical_json(obj: Any) -> bytes | None:
    try:
        return canonical_json_bytes(obj)
    except (TypeError, ValueError):
        return None


def _decode_strict_b64_allow_empty(value: str) -> bytes:
    if value == "":
        return b""
    return decode_strict_base64(value)


def _zero_instant() -> Instant:
    return (0, "")


def _safe_instant(value: Any) -> Instant | None:
    if type(value) is not str:
        return None
    return parse_rfc3339_instant(value)


@dataclass(frozen=True)
class _ParsedRecord:
    ref: str
    payload_bytes: bytes
    payload: dict[str, Any]
    signers: list[str]
    kind_path: str
    body: dict[str, Any]
    captured_at: Instant | None
    seq: int
    stream: str | None


@dataclass(frozen=True)
class _ContractSnapshot:
    ref: str
    seq: int
    captured_at: Instant | None
    custody_level: int
    witness_keys: frozenset[str]
    overseer_key: str | None
    approver_roles: dict[str, frozenset[str]]
    sealed_service_copies: dict[str, str]
    sealed_copy_order: tuple[str, ...]
    hardware_attestation_roots: frozenset[str]
    deployment_root_keys: frozenset[str]


def _default_contract() -> _ContractSnapshot:
    return _ContractSnapshot(
        ref="",
        seq=0,
        captured_at=None,
        custody_level=1,
        witness_keys=frozenset(),
        overseer_key=None,
        approver_roles={},
        sealed_service_copies={},
        sealed_copy_order=(),
        hardware_attestation_roots=frozenset(),
        deployment_root_keys=frozenset(),
    )


def _collect_salted_refs(node: Any, out: set[str]) -> None:
    if type(node) is str:
        if SALTED_BYTES_REF_RE.match(node):
            out.add(node)
    elif isinstance(node, list):
        for item in node:
            _collect_salted_refs(item, out)
    elif isinstance(node, dict):
        for val in node.values():
            _collect_salted_refs(val, out)


def _collect_bare_bytes_refs(node: Any, out: set[str]) -> None:
    if type(node) is str:
        if BYTES_REF_RE.match(node):
            out.add(node)
    elif isinstance(node, list):
        for item in node:
            _collect_bare_bytes_refs(item, out)
    elif isinstance(node, dict):
        for val in node.values():
            _collect_bare_bytes_refs(val, out)


def _basis_names_person(body: dict[str, Any]) -> bool:
    """Structural person-naming predicate per A11 §1.1 (zero URI-prefix heuristics)."""
    subjects = body.get("subjects")
    if isinstance(subjects, list) and len(subjects) > 0:
        return True
    rep = body.get("representative")
    return type(rep) is str and len(rep) > 0


def _verify_embedded_sig(
    keys_by_id: dict[str, tuple[str, bytes]],
    key_id: Any,
    msg: bytes,
    sig_b64: Any,
) -> bool:
    """Verify an embedded A11 signature with constant-time key-ID binding."""
    if type(key_id) is not str or type(sig_b64) is not str:
        return False
    key_entry = keys_by_id.get(key_id)
    if key_entry is None:
        return False
    alg, key_bytes = key_entry
    derived_id = compute_key_id(alg, key_bytes)
    if derived_id is None or not hmac.compare_digest(derived_id, key_id):
        return False
    try:
        sig_bytes = decode_strict_base64(sig_b64)
    except ValueError:
        return False
    return verify_signature(alg, key_bytes, sig_bytes, msg)


def _extract_contract_history(records: list[_ParsedRecord]) -> list[_ContractSnapshot]:
    """Build start-stream-ordered historical contract snapshots per A11 §7.3."""
    contract_recs = [
        r for r in records if r.kind_path in (DEPLOYMENT_KIND, ROOTS_CHANGED_KIND)
    ]
    contract_recs.sort(key=lambda r: (r.seq, r.ref))

    custody_level = 1
    witness_keys: frozenset[str] = frozenset()
    overseer_key: str | None = None
    approver_roles: dict[str, frozenset[str]] = {}
    sealed_service_copies: dict[str, str] = {}
    sealed_copy_order: tuple[str, ...] = ()
    explicit_hw_roots: frozenset[str] | None = None
    deployment_root_keys: set[str] = set()

    snapshots: list[_ContractSnapshot] = []
    for rec in contract_recs:
        body = rec.body
        roots = body.get("roots")
        if isinstance(roots, list):
            for entry in roots:
                if isinstance(entry, dict) and type(entry.get("key")) is str:
                    deployment_root_keys.add(entry["key"])
        if type(body.get("custodyLevel")) is int:
            custody_level = body["custodyLevel"]
        if isinstance(body.get("witnessKeys"), list):
            witness_keys = frozenset(k for k in body["witnessKeys"] if type(k) is str)
        if type(body.get("overseerKey")) is str:
            overseer_key = body["overseerKey"]
        if isinstance(body.get("approverRoles"), list):
            roles_map: dict[str, frozenset[str]] = {}
            for entry in body["approverRoles"]:
                if isinstance(entry, dict) and type(entry.get("role")) is str:
                    ks = entry.get("keys")
                    if isinstance(ks, list):
                        roles_map[entry["role"]] = frozenset(
                            k for k in ks if type(k) is str
                        )
            approver_roles = roles_map
        if isinstance(body.get("sealedServiceCopies"), list):
            copy_map: dict[str, str] = {}
            copy_order: list[str] = []
            for entry in body["sealedServiceCopies"]:
                if (
                    isinstance(entry, dict)
                    and type(entry.get("copyId")) is str
                    and len(entry["copyId"]) > 0
                    and type(entry.get("keyId")) is str
                ):
                    cid = entry["copyId"]
                    if cid not in copy_map:
                        copy_order.append(cid)
                    copy_map[cid] = entry["keyId"]
            sealed_service_copies = copy_map
            sealed_copy_order = tuple(copy_order)
        if isinstance(body.get("hardwareAttestationRoots"), list):
            explicit_hw_roots = frozenset(
                k for k in body["hardwareAttestationRoots"] if type(k) is str
            )

        hw_roots = (
            explicit_hw_roots
            if explicit_hw_roots is not None
            else frozenset(deployment_root_keys)
        )
        snapshots.append(
            _ContractSnapshot(
                ref=rec.ref,
                seq=rec.seq,
                captured_at=rec.captured_at,
                custody_level=custody_level,
                witness_keys=witness_keys,
                overseer_key=overseer_key,
                approver_roles=dict(approver_roles),
                sealed_service_copies=dict(sealed_service_copies),
                sealed_copy_order=sealed_copy_order,
                hardware_attestation_roots=hw_roots,
                deployment_root_keys=frozenset(deployment_root_keys),
            )
        )

    return snapshots


def _resolve_contract(
    snapshots: list[_ContractSnapshot],
    *,
    contract_version: str | None = None,
    at_record: _ParsedRecord | None = None,
) -> _ContractSnapshot:
    if not snapshots:
        return _default_contract()
    if type(contract_version) is str and contract_version:
        for snap in snapshots:
            if snap.ref == contract_version:
                return snap
    if at_record is not None and at_record.captured_at is not None:
        applicable = [
            s
            for s in snapshots
            if s.captured_at is not None and s.captured_at <= at_record.captured_at
        ]
        if applicable:
            return applicable[-1]
    return snapshots[-1]


def _find_ground_and_power(
    basis_body: dict[str, Any],
    ground_id: Any,
    power_name: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    grounds = basis_body.get("grounds")
    if not isinstance(grounds, list):
        return None, None
    for ground in grounds:
        if isinstance(ground, dict) and ground.get("groundId") == ground_id:
            powers = ground.get("powers")
            if isinstance(powers, list):
                for p in powers:
                    if isinstance(p, dict) and p.get("power") == power_name:
                        return ground, p
            return ground, None
    return None, None


def _find_any_power(basis_body: dict[str, Any], power_name: str) -> dict[str, Any] | None:
    grounds = basis_body.get("grounds")
    if not isinstance(grounds, list):
        return None
    for ground in grounds:
        if not isinstance(ground, dict):
            continue
        powers = ground.get("powers")
        if not isinstance(powers, list):
            continue
        for p in powers:
            if isinstance(p, dict) and p.get("power") == power_name:
                return p
    return None


def _is_endorsement_active(
    end_rec: _ParsedRecord,
    at_time: Instant | None,
    revocations_by_target: dict[str, list[_ParsedRecord]],
) -> bool:
    """Check whether an Endorsement is in-window and non-revoked at `at_time`."""
    if at_time is not None:
        nb = _safe_instant(end_rec.body.get("notBefore"))
        na = _safe_instant(end_rec.body.get("notAfter"))
        if nb is not None and at_time < nb:
            return False
        if na is not None and at_time > na:
            return False
    for rev in revocations_by_target.get(end_rec.ref, ()):
        if at_time is None or rev.captured_at is None or rev.captured_at <= at_time:
            return False
    return True


def _latest_active_endorsement(
    endorsements_by_key: dict[str, list[_ParsedRecord]],
    key_id: str,
    at_time: Instant | None,
    revocations_by_target: dict[str, list[_ParsedRecord]],
) -> _ParsedRecord | None:
    candidates = [
        e
        for e in endorsements_by_key.get(key_id, ())
        if _is_endorsement_active(e, at_time, revocations_by_target)
    ]
    return candidates[-1] if candidates else None


def _verify_hardware_attestation(
    att_ref: Any,
    signer_key: str,
    contract: _ContractSnapshot,
    blobs_by_ref: dict[str, bytes],
    salted_plaintexts: dict[str, bytes],
    keys_by_id: dict[str, tuple[str, bytes]],
) -> bool:
    """Verify cryptographic hardware attestation per A11 §7.4."""
    if type(att_ref) is not str:
        return False
    raw = blobs_by_ref.get(att_ref)
    if raw is None:
        raw = salted_plaintexts.get(att_ref)
    if raw is None:
        return False
    try:
        obj = parse_canonical_json(raw)
    except ValueError:
        return False
    if not isinstance(obj, dict):
        return False
    if set(obj.keys()) != {"attestedAt", "device", "keyId", "rootKeyId", "signature"}:
        return False
    attested_at = obj["attestedAt"]
    device = obj["device"]
    key_id = obj["keyId"]
    root_key_id = obj["rootKeyId"]
    signature = obj["signature"]
    if (
        not _is_utc_rfc3339(attested_at)
        or type(device) is not str
        or not device
        or type(key_id) is not str
        or type(root_key_id) is not str
        or type(signature) is not str
    ):
        return False
    if not hmac.compare_digest(key_id, signer_key):
        return False
    if root_key_id not in contract.hardware_attestation_roots:
        return False
    unsigned_bytes = _safe_canonical_json(
        {
            "attestedAt": attested_at,
            "device": device,
            "keyId": key_id,
            "rootKeyId": root_key_id,
        }
    )
    if unsigned_bytes is None:
        return False
    msg = b"r5e-hw-attestation-v1\x00" + unsigned_bytes
    return _verify_embedded_sig(keys_by_id, root_key_id, msg, signature)


def _evaluate_successions_v7(
    records: list[_ParsedRecord],
    by_ref: dict[str, _ParsedRecord],
    base_def_index_refs: set[str],
    keys_by_id: dict[str, tuple[str, bytes]],
    snapshots: list[_ContractSnapshot],
    endorsements_by_key: dict[str, list[_ParsedRecord]],
    revocations_by_target: dict[str, list[_ParsedRecord]],
) -> tuple[list[dict[str, Any]], set[str]]:
    """Evaluate V7 (succession_recovery) and return (findings, excluded_succession_refs)."""
    # Collect institutional keys that alone can never satisfy recoveryRule.threshold
    institutional_keys: set[str] = set()
    for snap in snapshots:
        institutional_keys.update(snap.deployment_root_keys)
        for role_keys in snap.approver_roles.values():
            institutional_keys.update(role_keys)
    for rec in records:
        if rec.kind_path == ENDORSEMENT_KIND:
            issuer = rec.payload.get("issuer")
            if type(issuer) is str:
                institutional_keys.add(issuer)

    # Sort Succession records chronologically so chained recovery rules work deterministically
    succ_records = [r for r in records if r.kind_path == SUCCESSION_KIND]
    succ_records.sort(
        key=lambda r: (
            r.captured_at or _zero_instant(),
            r.seq,
            r.ref,
        )
    )

    findings: list[dict[str, Any]] = []
    excluded_refs: set[str] = set()
    valid_succession_by_ref: dict[str, _ParsedRecord] = {}

    for rec in succ_records:
        schema_ref = rec.payload.get("schemaRef")
        has_recovery_proof = "recoveryProof" in rec.body
        has_recovery_rule = "recoveryRule" in rec.body
        is_a11_succession = (
            has_recovery_proof
            or has_recovery_rule
            or (type(schema_ref) is str and schema_ref not in base_def_index_refs)
        )
        if not is_a11_succession:
            continue

        predecessor = rec.body.get("predecessor")
        successor = rec.body.get("successor")

        if not has_recovery_proof:
            # Standard-form A11 Succession: must be signed by [predecessor, successor] in order
            if (
                type(predecessor) is not str
                or type(successor) is not str
                or rec.signers != [predecessor, successor]
            ):
                excluded_refs.add(rec.ref)
                findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "succession_recovery",
                        "failed",
                        "succession_signer_mismatch",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                    )
                )
            else:
                valid_succession_by_ref[rec.ref] = rec
                findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "succession_recovery",
                        "ok",
                        "ok",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                    )
                )
            continue

        # Recovery-form Succession
        recovery_proof = rec.body.get("recoveryProof")
        if (
            type(predecessor) is not str
            or type(successor) is not str
            or rec.signers != [successor]
        ):
            excluded_refs.add(rec.ref)
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_signer_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
            continue

        if not isinstance(recovery_proof, dict):
            excluded_refs.add(rec.ref)
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_recovery_rule_unknown",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
            continue

        rule_ref = recovery_proof.get("recoveryRuleRef")
        rule_rec = by_ref.get(rule_ref) if type(rule_ref) is str else None

        # Pin active recoveryRule: predecessor's earliest valid Endorsement or prior valid Succession
        recovery_rule: dict[str, Any] | None = None
        if rule_rec is not None:
            if rule_rec.kind_path == ENDORSEMENT_KIND:
                if (
                    rule_rec.body.get("subject") == predecessor
                    and _is_endorsement_active(rule_rec, rec.captured_at, revocations_by_target)
                    and isinstance(rule_rec.body.get("recoveryRule"), dict)
                ):
                    # Must be predecessor's earliest valid Endorsement carrying recoveryRule
                    pred_ends = [
                        e
                        for e in endorsements_by_key.get(predecessor, ())
                        if isinstance(e.body.get("recoveryRule"), dict)
                        and _is_endorsement_active(e, rec.captured_at, revocations_by_target)
                    ]
                    if pred_ends and pred_ends[0].ref == rule_rec.ref:
                        recovery_rule = rule_rec.body["recoveryRule"]
            elif (
                rule_rec.kind_path == SUCCESSION_KIND
                and rule_rec.ref in valid_succession_by_ref
                and rule_rec.body.get("successor") == predecessor
                and isinstance(rule_rec.body.get("recoveryRule"), dict)
            ):
                recovery_rule = rule_rec.body["recoveryRule"]

        if recovery_rule is None:
            excluded_refs.add(rec.ref)
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_recovery_rule_unknown",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    rule_ref if type(rule_ref) is str else None,
                )
            )
            continue

        raw_recovery_keys = recovery_rule.get("recoveryKeys")
        allowed_keys = (
            {k for k in raw_recovery_keys if type(k) is str}
            if isinstance(raw_recovery_keys, list)
            else set()
        )
        raw_threshold = recovery_rule.get("threshold")
        threshold = raw_threshold if type(raw_threshold) is int and raw_threshold >= 1 else 1

        raw_approvals = recovery_proof.get("approvals")
        approvals = raw_approvals if isinstance(raw_approvals, list) else []
        if len(approvals) > 64:
            excluded_refs.add(rec.ref)
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_recovery_threshold_not_met",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
            continue

        succ_bytes = _safe_canonical_json(
            {
                "newKey": successor,
                "oldKey": predecessor,
                "recoveryRuleRef": rule_ref,
            }
        )
        if succ_bytes is None:
            excluded_refs.add(rec.ref)
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_recovery_threshold_not_met",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
            continue

        succ_msg = b"r5e-succession-recovery-v1\x00" + succ_bytes
        valid_recovery_signers: set[str] = set()
        for app in approvals:
            if not isinstance(app, dict):
                continue
            sk = app.get("signerKey")
            if type(sk) is not str or sk not in allowed_keys:
                continue
            if _verify_embedded_sig(keys_by_id, sk, succ_msg, app.get("signature")):
                valid_recovery_signers.add(sk)

        if len(valid_recovery_signers) < threshold:
            excluded_refs.add(rec.ref)
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_recovery_threshold_not_met",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
        elif valid_recovery_signers.issubset(institutional_keys):
            excluded_refs.add(rec.ref)
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_institution_only_rejected",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
        else:
            valid_succession_by_ref[rec.ref] = rec
            findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "ok",
                    "ok",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )

    return findings, excluded_refs


def _parse_bundle_context(
    bundle: dict[str, Any],
) -> tuple[
    dict[str, bytes],
    dict[str, tuple[str, bytes]],
    list[_ParsedRecord],
    dict[str, _ParsedRecord],
]:
    schemas = _load_bundled_schemas()
    signed_schema = schemas["signed-evidence.schema.json"]

    blobs_by_ref: dict[str, bytes] = {}
    for blob_entry in bundle["blobs"]:
        b_ref = blob_entry["ref"]
        try:
            raw_blob = decode_base64(blob_entry["base64"])
        except ValueError:
            continue
        if hmac.compare_digest(bytes_ref(raw_blob), b_ref):
            blobs_by_ref[b_ref] = raw_blob

    keys_by_id: dict[str, tuple[str, bytes]] = {}
    for key_entry in bundle["keys"]:
        kid = key_entry["keyid"]
        alg = key_entry["algorithm"]
        try:
            raw_key = decode_base64(key_entry["bytes"])
        except ValueError:
            continue
        if kid not in keys_by_id:
            keys_by_id[kid] = (alg, raw_key)

    records: list[_ParsedRecord] = []
    by_ref: dict[str, _ParsedRecord] = {}
    for rec_entry in bundle["records"]:
        rec_ref = rec_entry["ref"]
        opened, _ = verify_record_envelope(rec_ref, rec_entry["envelope"], signed_schema)
        if opened is None:
            continue
        payload_bytes, payload, sig_entries = opened
        api_ver = payload.get("apiVersion")
        kind = payload.get("kind")
        body = payload.get("body")
        if type(api_ver) is not str or type(kind) is not str or not isinstance(body, dict):
            continue
        rec = _ParsedRecord(
            ref=rec_ref,
            payload_bytes=payload_bytes,
            payload=payload,
            signers=[kid for kid, _ in sig_entries],
            kind_path=f"{api_ver}/{kind}",
            body=body,
            captured_at=_safe_instant(payload.get("capturedAt")),
            seq=_safe_int(payload.get("seq"), 0),
            stream=payload.get("stream") if type(payload.get("stream")) is str else None,
        )
        records.append(rec)
        by_ref[rec_ref] = rec

    return blobs_by_ref, keys_by_id, records, by_ref


def _extract_target_subjects(
    target: str,
    by_ref: dict[str, _ParsedRecord],
    records_by_session: dict[str, list[_ParsedRecord]],
    basis_by_session: dict[str, list[_ParsedRecord]],
) -> tuple[bool, set[str]]:
    """Resolve subjects for a ReleaseRequest target (`evidence:sha256:...` or `urn:r5e:session:...`)."""
    subjects: set[str] = set()
    if target.startswith("evidence:sha256:"):
        t_rec = by_ref.get(target)
        if t_rec is None:
            return False, subjects
        raw_subjs = t_rec.body.get("subjects")
        if isinstance(raw_subjs, list):
            subjects.update(s for s in raw_subjs if type(s) is str)
        raw_subj = t_rec.body.get("subject")
        if type(raw_subj) is str and raw_subj:
            subjects.add(raw_subj)
        sess = t_rec.payload.get("session")
        if type(sess) is str:
            for b_rec in basis_by_session.get(sess, ()):
                b_subjs = b_rec.body.get("subjects")
                if isinstance(b_subjs, list):
                    subjects.update(s for s in b_subjs if type(s) is str)
        return True, subjects

    if target.startswith("urn:r5e:session:"):
        sess_recs = records_by_session.get(target, [])
        sess_bases = basis_by_session.get(target, [])
        if not sess_recs and not sess_bases:
            return False, subjects
        for r in sess_recs:
            raw_subjs = r.body.get("subjects")
            if isinstance(raw_subjs, list):
                subjects.update(s for s in raw_subjs if type(s) is str)
            raw_subj = r.body.get("subject")
            if type(raw_subj) is str and raw_subj:
                subjects.add(raw_subj)
            # Check contextRefs pointing to Basis records (on body or payload)
            for ctx in (r.body.get("contextRefs"), r.payload.get("contextRefs")):
                if isinstance(ctx, list):
                    for cref in ctx:
                        if type(cref) is str:
                            c_rec = by_ref.get(cref)
                            if c_rec is not None and c_rec.kind_path == BASIS_KIND:
                                c_subjs = c_rec.body.get("subjects")
                                if isinstance(c_subjs, list):
                                    subjects.update(s for s in c_subjs if type(s) is str)
        for b_rec in sess_bases:
            b_subjs = b_rec.body.get("subjects")
            if isinstance(b_subjs, list):
                subjects.update(s for s in b_subjs if type(s) is str)
        return True, subjects

    return False, subjects


def verify_a11_rules(
    bundle: Any,
    *,
    baseline_findings: Sequence[dict[str, Any]],
    trusted_checkpoints: Sequence[dict[str, Any]] = (),
    _precomputed_v7: tuple[list[dict[str, Any]], set[str]] | None = None,
) -> list[dict[str, Any]]:
    """Run Amendment A11 offline verifier rules (V1–V11) on a parsed bundle."""
    schemas = _load_bundled_schemas()
    if not _validate_bundle_shape(bundle, schemas["export.schema.json"], allow_a11=True):
        return []

    _, base_def_index_refs = _load_base_definitions()
    blobs_by_ref, keys_by_id, records, by_ref = _parse_bundle_context(bundle)
    snapshots = _extract_contract_history(records)

    # Index baseline results per record
    body_ok_refs: set[str] = set()
    body_failed_refs: set[str] = set()
    sig_ok_counts: dict[str, int] = {}
    sig_failed_refs: set[str] = set()
    for f in baseline_findings:
        subj = f.get("subject")
        if type(subj) is not str:
            continue
        chk = f.get("check")
        res = f.get("result")
        if chk == "body":
            if res == "ok":
                body_ok_refs.add(subj)
            elif res == "failed":
                body_failed_refs.add(subj)
        elif chk == "signature":
            if res == "ok":
                sig_ok_counts[subj] = sig_ok_counts.get(subj, 0) + 1
            else:
                sig_failed_refs.add(subj)

    def _record_all_sigs_ok(rec: _ParsedRecord) -> bool:
        if rec.ref in sig_failed_refs:
            return False
        return sig_ok_counts.get(rec.ref, 0) == len(rec.signers) and len(rec.signers) > 0

    # Index Revocations by target ref
    revocations_by_target: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        if rec.kind_path == REVOCATION_KIND and _record_all_sigs_ok(rec):
            tgt = rec.body.get("target")
            if type(tgt) is str:
                revocations_by_target.setdefault(tgt, []).append(rec)

    # Index Endorsements by subject key (sorted deterministically by capturedAt, seq, ref)
    endorsements_by_key: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        if rec.kind_path == ENDORSEMENT_KIND and _record_all_sigs_ok(rec):
            subj = rec.body.get("subject")
            if type(subj) is str:
                endorsements_by_key.setdefault(subj, []).append(rec)
    for elist in endorsements_by_key.values():
        elist.sort(key=lambda r: (r.captured_at or _zero_instant(), r.seq, r.ref))

    # Index sessions & Basis records per session for target resolution
    records_by_session: dict[str, list[_ParsedRecord]] = {}
    basis_by_session: dict[str, list[_ParsedRecord]] = {}
    session_closed_by_session: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        sess = rec.payload.get("session")
        if type(sess) is str:
            records_by_session.setdefault(sess, []).append(rec)
            if rec.kind_path == BASIS_KIND:
                basis_by_session.setdefault(sess, []).append(rec)
            elif rec.kind_path == SESSION_CLOSED_KIND:
                session_closed_by_session.setdefault(sess, []).append(rec)
        if rec.kind_path in (SESSION_OPENED_KIND, SESSION_CLOSED_KIND):
            bsess = rec.body.get("session")
            if type(bsess) is str and bsess != sess:
                records_by_session.setdefault(bsess, []).append(rec)
                if rec.kind_path == SESSION_CLOSED_KIND:
                    session_closed_by_session.setdefault(bsess, []).append(rec)

    # Index BasisOverlays by basisRef
    overlays_by_basis: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        if rec.kind_path == BASIS_OVERLAY_KIND and rec.ref not in body_failed_refs:
            bref = rec.body.get("basisRef")
            if type(bref) is str:
                overlays_by_basis.setdefault(bref, []).append(rec)
    for olist in overlays_by_basis.values():
        olist.sort(
            key=lambda r: (
                _safe_instant(r.body.get("effectiveAt")) or _zero_instant(),
                r.seq,
                r.ref,
            )
        )

    a11_findings: list[dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # V9: salted_content_ref (Layer 1) — pre-verify and cache every entry once
    # -------------------------------------------------------------------------
    salted_content_raw = bundle.get("saltedContent")
    salted_map: dict[str, Any] = (
        salted_content_raw if isinstance(salted_content_raw, dict) else {}
    )
    salted_verified: dict[str, bool] = {}
    salted_plaintexts: dict[str, bytes] = {}
    for s_ref, entry in salted_map.items():
        if type(s_ref) is not str:
            continue
        ok = False
        if (
            isinstance(entry, dict)
            and type(entry.get("salt")) is str
            and type(entry.get("bytes")) is str
        ):
            try:
                salt_bytes = decode_strict_base64(entry["salt"])
                raw_bytes = _decode_strict_b64_allow_empty(entry["bytes"])
                if len(salt_bytes) == 32:
                    digest = hashlib.sha256(
                        b"r5e-salted-content-v1\x00" + salt_bytes + raw_bytes
                    ).hexdigest()
                    if hmac.compare_digest(f"bytes:sha256+salt:{digest}", s_ref):
                        ok = True
                        salted_plaintexts[s_ref] = raw_bytes
            except ValueError:
                ok = False
        salted_verified[s_ref] = ok

    referenced_salted_refs: set[str] = set()
    for rec in records:
        salted_refs: set[str] = set()
        _collect_salted_refs(rec.body, salted_refs)
        for s_ref in sorted(salted_refs):
            referenced_salted_refs.add(s_ref)
            if s_ref not in salted_verified:
                a11_findings.append(
                    _a11_finding(
                        1,
                        rec.ref,
                        "salted_content_ref",
                        "incomplete",
                        "salted_content_omitted",
                        CATEGORY_UNAVAILABLE_EVIDENCE,
                        s_ref,
                    )
                )
            elif salted_verified[s_ref]:
                a11_findings.append(
                    _a11_finding(
                        1,
                        rec.ref,
                        "salted_content_ref",
                        "ok",
                        "ok",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        s_ref,
                    )
                )
            else:
                a11_findings.append(
                    _a11_finding(
                        1,
                        rec.ref,
                        "salted_content_ref",
                        "failed",
                        "salted_content_digest_mismatch",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        s_ref,
                    )
                )

    for s_ref in sorted(salted_verified):
        if s_ref not in referenced_salted_refs and not salted_verified[s_ref]:
            a11_findings.append(
                _a11_finding(
                    1,
                    s_ref,
                    "salted_content_ref",
                    "failed",
                    "salted_content_digest_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    s_ref,
                )
            )

    # -------------------------------------------------------------------------
    # V11: definition_coexistence (Layer 1)
    # -------------------------------------------------------------------------
    published_defs_by_kind: dict[str, set[str]] = {}
    for rec in records:
        if rec.kind_path == DEFINITION_PUBLISHED_KIND:
            defs = rec.body.get("definitions")
            if isinstance(defs, list):
                for item in defs:
                    if (
                        isinstance(item, dict)
                        and type(item.get("kind")) is str
                        and type(item.get("definition")) is str
                    ):
                        published_defs_by_kind.setdefault(item["kind"], set()).add(
                            item["definition"]
                        )
    for rec in records:
        schema_ref = rec.payload.get("schemaRef")
        if type(schema_ref) is not str:
            continue
        kind_versions = published_defs_by_kind.get(rec.kind_path, set())
        if (
            len(kind_versions) > 1
            and schema_ref in base_def_index_refs
            and rec.ref in body_ok_refs
        ):
            a11_findings.append(
                _a11_finding(
                    1,
                    rec.ref,
                    "definition_coexistence",
                    "ok",
                    "ok",
                    CATEGORY_MECHANICAL_CHECK,
                    schema_ref,
                )
            )

    # -------------------------------------------------------------------------
    # V1: basis_signatures (Layer 2)
    # -------------------------------------------------------------------------
    failed_basis_refs: set[str] = set()
    for rec in records:
        if rec.kind_path != BASIS_KIND:
            continue
        all_sigs_ok = _record_all_sigs_ok(rec)
        unique_signers = list(dict.fromkeys(rec.signers))

        if _basis_names_person(rec.body):
            if len(unique_signers) > 2:
                failed_basis_refs.add(rec.ref)
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "failed",
                        "basis_unexpected_signature_count",
                        CATEGORY_MECHANICAL_CHECK,
                    )
                )
                continue
            if len(unique_signers) < 2 or not all_sigs_ok:
                failed_basis_refs.add(rec.ref)
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "failed",
                        "basis_missing_counter_signature",
                        CATEGORY_MECHANICAL_CHECK,
                    )
                )
                continue

            institution = rec.body.get("institution")
            raw_subjects = rec.body.get("subjects")
            person_targets: set[str] = (
                {s for s in raw_subjects if type(s) is str}
                if isinstance(raw_subjects, list)
                else set()
            )
            rep = rec.body.get("representative")
            if type(rep) is str and rep:
                person_targets.add(rep)

            # Match one institutional signer and one distinct person/representative signer
            inst_signers: set[str] = set()
            person_signers: dict[str, str] = {}
            for signer in unique_signers:
                end_rec = _latest_active_endorsement(
                    endorsements_by_key, signer, rec.captured_at, revocations_by_target
                )
                if end_rec is None:
                    continue
                acts_for = end_rec.body.get("actsFor")
                signer_kind = end_rec.body.get("signerKind")
                if type(institution) is str and acts_for == institution:
                    inst_signers.add(signer)
                if (
                    type(acts_for) is str
                    and acts_for in person_targets
                    and signer_kind in ("personal", "device_session")
                ):
                    person_signers[signer] = signer_kind

            matched_kind: str | None = None
            for p_signer, p_kind in person_signers.items():
                if any(i_signer != p_signer for i_signer in inst_signers):
                    matched_kind = p_kind
                    if p_kind == "personal":
                        break

            if matched_kind == "personal":
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "ok",
                        "ok",
                        CATEGORY_MECHANICAL_CHECK,
                    )
                )
            elif matched_kind == "device_session":
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "ok",
                        "basis_person_signed_by_device_session",
                        CATEGORY_INSTITUTIONAL_ASSERTION,
                    )
                )
            else:
                failed_basis_refs.add(rec.ref)
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "failed",
                        "basis_invalid_signer_binding",
                        CATEGORY_MECHANICAL_CHECK,
                    )
                )
        else:
            if len(unique_signers) == 1 and all_sigs_ok:
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "ok",
                        "ok",
                        CATEGORY_MECHANICAL_CHECK,
                    )
                )
            elif len(unique_signers) > 1:
                failed_basis_refs.add(rec.ref)
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "failed",
                        "basis_unexpected_signature_count",
                        CATEGORY_MECHANICAL_CHECK,
                    )
                )
            else:
                failed_basis_refs.add(rec.ref)
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "basis_signatures",
                        "failed",
                        "basis_missing_counter_signature",
                        CATEGORY_MECHANICAL_CHECK,
                    )
                )

    # -------------------------------------------------------------------------
    # V5: witness_receipt_binding (Layer 3) — also build verified logIndex map for V3
    # -------------------------------------------------------------------------
    witness_receipts_raw = bundle.get("witnessReceipts")
    witness_receipts: dict[str, Any] = (
        witness_receipts_raw if isinstance(witness_receipts_raw, dict) else {}
    )
    verified_witness_log_index: dict[str, int] = {}

    # Reject any ReleaseRequest embedding witnessReceiptRef
    for rec in records:
        if rec.kind_path == RELEASE_REQUEST_KIND and "witnessReceiptRef" in rec.body:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "witness_receipt_binding",
                    "failed",
                    "witness_receipt_hash_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )

    # Map witnessReceiptRef -> ReleaseReceipt record(s) citing it
    receipt_recs_by_wref: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        if rec.kind_path == RELEASE_RECEIPT_KIND:
            w_ref = rec.body.get("witnessReceiptRef")
            if type(w_ref) is str:
                receipt_recs_by_wref.setdefault(w_ref, []).append(rec)

    def _verify_witness_receipt(
        w_ref: str,
        subject: str,
        expected_req_ref: str | None,
        at_rec: _ParsedRecord | None,
    ) -> None:
        receipt = witness_receipts.get(w_ref)
        if not isinstance(receipt, dict):
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "failed",
                    "witness_receipt_hash_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    w_ref,
                )
            )
            return

        # (1) Map key equals bytes:sha256(canonical(receipt))
        canon_receipt = _safe_canonical_json(receipt)
        if canon_receipt is None or not hmac.compare_digest(bytes_ref(canon_receipt), w_ref):
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "failed",
                    "witness_receipt_hash_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    w_ref,
                )
            )
            return

        # Resolve applicable contract (use ReleaseRequest contractVersion if available)
        req_ref = receipt.get("requestRef")
        req_rec = by_ref.get(req_ref) if type(req_ref) is str else None
        contract_ver = (
            req_rec.body.get("contractVersion")
            if req_rec is not None and type(req_rec.body.get("contractVersion")) is str
            else None
        )
        contract = _resolve_contract(
            snapshots, contract_version=contract_ver, at_record=at_rec or req_rec
        )

        # (2) witnessKey in active contract witnessKeys
        w_key = receipt.get("witnessKey")
        if type(w_key) is not str or w_key not in contract.witness_keys:
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "failed",
                    "witness_unpinned",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    w_key if type(w_key) is str else w_ref,
                )
            )
            return

        # (3) Constant-time key-ID binding + valid signature
        unsigned_bytes = _safe_canonical_json(
            {
                "logIndex": receipt.get("logIndex"),
                "loggedAt": receipt.get("loggedAt"),
                "requestHash": receipt.get("requestHash"),
                "requestRef": req_ref,
                "witnessKey": w_key,
            }
        )
        if unsigned_bytes is None or not _verify_embedded_sig(
            keys_by_id,
            w_key,
            b"r5e-witness-receipt-v1\x00" + unsigned_bytes,
            receipt.get("signature"),
        ):
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "failed",
                    "witness_receipt_hash_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    w_ref,
                )
            )
            return

        # (4) requestRef resolves to carried ReleaseRequest (or BasisOverlay)
        if type(req_ref) is not str or req_rec is None:
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "incomplete",
                    "witness_request_missing",
                    CATEGORY_UNAVAILABLE_EVIDENCE,
                    req_ref if type(req_ref) is str else w_ref,
                )
            )
            return
        if req_rec.kind_path not in (RELEASE_REQUEST_KIND, BASIS_OVERLAY_KIND):
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "failed",
                    "witness_request_wrong_kind",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    req_ref,
                )
            )
            return
        if expected_req_ref is not None and not hmac.compare_digest(req_ref, expected_req_ref):
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "failed",
                    "witness_receipt_hash_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    w_ref,
                )
            )
            return

        # (5) requestHash matches sha256(req_rec.payload_bytes)
        expected_hash = "sha256:" + hashlib.sha256(req_rec.payload_bytes).hexdigest()
        actual_hash = receipt.get("requestHash")
        if type(actual_hash) is not str or not hmac.compare_digest(actual_hash, expected_hash):
            a11_findings.append(
                _a11_finding(
                    3,
                    subject,
                    "witness_receipt_binding",
                    "failed",
                    "witness_receipt_hash_mismatch",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    w_ref,
                )
            )
            return

        log_idx = receipt.get("logIndex")
        if type(log_idx) is int:
            verified_witness_log_index[req_ref] = log_idx

        a11_findings.append(
            _a11_finding(
                3,
                subject,
                "witness_receipt_binding",
                "ok",
                "ok",
                CATEGORY_CRYPTOGRAPHIC_PROOF,
                w_ref,
            )
        )

    checked_wrefs: set[str] = set()
    for w_ref, rrecs in receipt_recs_by_wref.items():
        checked_wrefs.add(w_ref)
        for rrec in rrecs:
            exp_req = rrec.body.get("requestRef")
            _verify_witness_receipt(
                w_ref,
                rrec.ref,
                exp_req if type(exp_req) is str else None,
                rrec,
            )
    for w_ref in sorted(witness_receipts):
        if w_ref not in checked_wrefs:
            _verify_witness_receipt(w_ref, w_ref, None, None)

    # -------------------------------------------------------------------------
    # V2 (basis_declared_power) & V3 (basis_overlay_order) — independent passes
    # -------------------------------------------------------------------------
    # Pre-check BasisOverlay signer authority for withdrawal overlays
    authorized_withdrawal_refs: set[str] = set()
    for rec in records:
        if rec.kind_path != BASIS_OVERLAY_KIND or rec.ref in body_failed_refs:
            continue
        if rec.body.get("overlayType") != "withdrawal":
            continue
        bref = rec.body.get("basisRef")
        basis_rec = by_ref.get(bref) if type(bref) is str else None
        if basis_rec is None or basis_rec.kind_path != BASIS_KIND:
            continue
        allowed_entities: set[str] = set()
        inst = basis_rec.body.get("institution")
        if type(inst) is str:
            allowed_entities.add(inst)
        subjs = basis_rec.body.get("subjects")
        if isinstance(subjs, list):
            allowed_entities.update(s for s in subjs if type(s) is str)
        rep = basis_rec.body.get("representative")
        if type(rep) is str and rep:
            allowed_entities.add(rep)
        signer_ok = False
        for signer in rec.signers:
            end_rec = _latest_active_endorsement(
                endorsements_by_key, signer, rec.captured_at, revocations_by_target
            )
            if end_rec is not None and end_rec.body.get("actsFor") in allowed_entities:
                signer_ok = True
                break
        if signer_ok:
            authorized_withdrawal_refs.add(rec.ref)
        else:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_overlay_order",
                    "failed",
                    "overlay_signer_unauthorized",
                    CATEGORY_MECHANICAL_CHECK,
                    bref if type(bref) is str else None,
                )
            )

    def _resolve_act_basis_info(
        rec: _ParsedRecord,
    ) -> tuple[str | None, str | None, str, list[str], str | None]:
        """Return (basis_ref, ground_id, power_name, targets, request_ref_for_l2_order)."""
        if rec.kind_path == RELEASE_REQUEST_KIND:
            bref = rec.body.get("basisRef")
            gid = rec.body.get("groundId")
            raw_power = rec.body.get("power")
            power_name = raw_power if type(raw_power) is str else "disclose"
            raw_targets = rec.body.get("targets")
            targets = [t for t in raw_targets if type(t) is str] if isinstance(raw_targets, list) else []
            return (
                bref if type(bref) is str else None,
                gid if type(gid) is str else None,
                power_name,
                targets,
                rec.ref,
            )
        if rec.kind_path == DISCLOSURE_KIND:
            rel_req_ref = rec.body.get("releaseRequestRef")
            if type(rel_req_ref) is str:
                req_rec = by_ref.get(rel_req_ref)
                if req_rec is not None and req_rec.kind_path == RELEASE_REQUEST_KIND:
                    bref = req_rec.body.get("basisRef")
                    gid = req_rec.body.get("groundId")
                    raw_power = req_rec.body.get("power")
                    power_name = raw_power if type(raw_power) is str else "disclose"
                    raw_targets = req_rec.body.get("targets")
                    targets = (
                        [t for t in raw_targets if type(t) is str]
                        if isinstance(raw_targets, list)
                        else []
                    )
                    return (
                        bref if type(bref) is str else None,
                        gid if type(gid) is str else None,
                        power_name,
                        targets,
                        req_rec.ref,
                    )
            bref = rec.body.get("basisRef")
            if type(bref) is str:
                return bref, None, "disclose", [], None
            return None, None, "disclose", [], None
        if rec.kind_path == RETENTION_HOLD_KIND:
            bref = rec.body.get("basisRef")
            if type(bref) is str:
                raw_targets = rec.body.get("targets")
                targets = (
                    [t for t in raw_targets if type(t) is str]
                    if isinstance(raw_targets, list)
                    else []
                )
                return bref, None, "hold", targets, None
            return None, None, "hold", [], None
        return None, None, "", [], None

    for rec in records:
        if rec.kind_path not in (RELEASE_REQUEST_KIND, DISCLOSURE_KIND, RETENTION_HOLD_KIND):
            continue
        if rec.ref in body_failed_refs:
            continue

        basis_ref, ground_id, power_name, targets, l2_req_ref = _resolve_act_basis_info(rec)
        if basis_ref is None:
            continue

        target = by_ref.get(basis_ref)
        if target is None:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_declared_power",
                    "incomplete",
                    "basis_ref_missing",
                    CATEGORY_UNAVAILABLE_EVIDENCE,
                    basis_ref,
                )
            )
            continue

        if (
            target.kind_path == BASIS_OVERLAY_KIND
            and target.body.get("overlayType") == "amendment_proposal"
        ):
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_declared_power",
                    "failed",
                    "proposal_authorises_nothing",
                    CATEGORY_MECHANICAL_CHECK,
                    basis_ref,
                )
            )
            continue

        if target.kind_path != BASIS_KIND:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_declared_power",
                    "failed",
                    "basis_ref_wrong_kind",
                    CATEGORY_MECHANICAL_CHECK,
                    basis_ref,
                )
            )
            continue

        if basis_ref in failed_basis_refs:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_declared_power",
                    "failed",
                    "basis_invalid",
                    CATEGORY_MECHANICAL_CHECK,
                    basis_ref,
                )
            )
            continue

        # --- V2 pass ---
        cited_power_obj: dict[str, Any] | None = None
        v2_emitted = False

        if rec.kind_path == RETENTION_HOLD_KIND:
            if type(rec.body.get("reviewAt")) is not str or not rec.body["reviewAt"]:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "basis_declared_power",
                        "failed",
                        "retention_hold_missing_review_at",
                        CATEGORY_MECHANICAL_CHECK,
                        basis_ref,
                    )
                )
                v2_emitted = True
            else:
                cited_power_obj = _find_any_power(target.body, "hold")
                if cited_power_obj is None:
                    a11_findings.append(
                        _a11_finding(
                            3,
                            rec.ref,
                            "basis_declared_power",
                            "failed",
                            "act_cites_declared_or_absent_power",
                            CATEGORY_MECHANICAL_CHECK,
                            "hold",
                        )
                    )
                    v2_emitted = True
        else:
            declared_terms = target.body.get("declaredTerms")
            if (
                ground_id is not None
                and isinstance(declared_terms, list)
                and any(
                    isinstance(t, dict) and t.get("termId") == ground_id
                    for t in declared_terms
                )
            ):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "basis_declared_power",
                        "failed",
                        "act_cites_declared_or_absent_power",
                        CATEGORY_MECHANICAL_CHECK,
                        ground_id,
                    )
                )
                v2_emitted = True
            else:
                if ground_id is not None:
                    ground_obj, power_obj = _find_ground_and_power(
                        target.body, ground_id, power_name
                    )
                    if ground_obj is None:
                        a11_findings.append(
                            _a11_finding(
                                3,
                                rec.ref,
                                "basis_declared_power",
                                "failed",
                                "act_cites_declared_or_absent_power",
                                CATEGORY_MECHANICAL_CHECK,
                                ground_id,
                            )
                        )
                        v2_emitted = True
                    elif power_obj is None:
                        a11_findings.append(
                            _a11_finding(
                                3,
                                rec.ref,
                                "basis_declared_power",
                                "failed",
                                "act_cites_declared_or_absent_power",
                                CATEGORY_MECHANICAL_CHECK,
                                power_name,
                            )
                        )
                        v2_emitted = True
                    else:
                        cited_power_obj = power_obj
                else:
                    cited_power_obj = _find_any_power(target.body, power_name)
                    if cited_power_obj is None:
                        a11_findings.append(
                            _a11_finding(
                                3,
                                rec.ref,
                                "basis_declared_power",
                                "failed",
                                "act_cites_declared_or_absent_power",
                                CATEGORY_MECHANICAL_CHECK,
                                power_name,
                            )
                        )
                        v2_emitted = True

        # Check Basis.subjects covers every subject of every resolved target
        if not v2_emitted:
            basis_subjects = {
                s for s in (target.body.get("subjects") or []) if type(s) is str
            }
            target_subjects: set[str] = set()
            for tgt in targets:
                _, t_subjs = _extract_target_subjects(
                    tgt, by_ref, records_by_session, basis_by_session
                )
                target_subjects.update(t_subjs)
            uncovered = sorted(target_subjects - basis_subjects)
            if uncovered:
                for subj in uncovered:
                    a11_findings.append(
                        _a11_finding(
                            3,
                            rec.ref,
                            "basis_declared_power",
                            "failed",
                            "basis_subjects_do_not_cover_targets",
                            CATEGORY_MECHANICAL_CHECK,
                            subj,
                        )
                    )
                v2_emitted = True

        if not v2_emitted:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_declared_power",
                    "ok",
                    "ok",
                    CATEGORY_MECHANICAL_CHECK,
                    basis_ref,
                )
            )

        # --- V3 pass (independent of V2!) ---
        act_ts = rec.captured_at
        act_stream = rec.stream
        act_seq = rec.seq
        act_log_idx = (
            verified_witness_log_index.get(l2_req_ref)
            if l2_req_ref is not None
            else None
        )
        withdrawn_by: str | None = None

        for ov in overlays_by_basis.get(basis_ref, ()):
            if ov.ref not in authorized_withdrawal_refs:
                continue
            ov_log_idx = verified_witness_log_index.get(ov.ref)
            if ov_log_idx is not None and act_log_idx is not None:
                if ov_log_idx < act_log_idx:
                    withdrawn_by = ov.ref
                    break
                continue

            ov_eff = _safe_instant(ov.body.get("effectiveAt"))
            if ov.stream is not None and ov.stream == act_stream:
                if ov.seq < act_seq:
                    withdrawn_by = ov.ref
                    break
            elif ov_eff is not None and act_ts is not None and ov_eff <= act_ts:
                withdrawn_by = ov.ref
                break

        if withdrawn_by is not None:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_overlay_order",
                    "failed",
                    "basis_power_withdrawn_or_expired",
                    CATEGORY_MECHANICAL_CHECK,
                    withdrawn_by,
                )
            )
            continue

        # Check duration.until and duration.untilEvent
        v3_done = False
        if cited_power_obj is not None:
            dur = cited_power_obj.get("duration")
            if isinstance(dur, dict):
                until_val = dur.get("until")
                if type(until_val) is str:
                    until_ts = _safe_instant(until_val)
                    expired = False
                    if until_ts is not None:
                        if act_ts is not None and act_ts > until_ts:
                            expired = True
                        if rec.kind_path == RELEASE_REQUEST_KIND:
                            tw = rec.body.get("timeWindow")
                            if isinstance(tw, dict):
                                na_ts = _safe_instant(tw.get("notAfter"))
                                if na_ts is not None and na_ts > until_ts:
                                    expired = True
                    if expired:
                        a11_findings.append(
                            _a11_finding(
                                3,
                                rec.ref,
                                "basis_overlay_order",
                                "failed",
                                "basis_power_withdrawn_or_expired",
                                CATEGORY_MECHANICAL_CHECK,
                                basis_ref,
                            )
                        )
                        v3_done = True

                until_event = dur.get("untilEvent")
                if not v3_done and type(until_event) is str and until_event:
                    triggered_ref: str | None = None
                    if until_event == "session_closed":
                        candidate_sessions: set[str] = set()
                        for tgt in targets:
                            if tgt.startswith("urn:r5e:session:"):
                                candidate_sessions.add(tgt)
                            elif tgt in by_ref:
                                ts = by_ref[tgt].payload.get("session")
                                if type(ts) is str:
                                    candidate_sessions.add(ts)
                        if not candidate_sessions and rec.payload.get("session"):
                            rs = rec.payload.get("session")
                            if type(rs) is str:
                                candidate_sessions.add(rs)
                        for cs in sorted(candidate_sessions):
                            for sc_rec in session_closed_by_session.get(cs, ()):
                                if (
                                    sc_rec.captured_at is None
                                    or act_ts is None
                                    or sc_rec.captured_at <= act_ts
                                ):
                                    triggered_ref = sc_rec.ref
                                    break
                            if triggered_ref is not None:
                                break
                    if triggered_ref is not None:
                        a11_findings.append(
                            _a11_finding(
                                3,
                                rec.ref,
                                "basis_overlay_order",
                                "failed",
                                "basis_power_withdrawn_or_expired",
                                CATEGORY_MECHANICAL_CHECK,
                                triggered_ref,
                            )
                        )
                        v3_done = True
                    else:
                        a11_findings.append(
                            _a11_finding(
                                3,
                                rec.ref,
                                "basis_overlay_order",
                                "incomplete",
                                "until_event_unverified",
                                CATEGORY_UNAVAILABLE_EVIDENCE,
                                until_event,
                            )
                        )
                        v3_done = True

        if not v3_done:
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_overlay_order",
                    "ok",
                    "ok",
                    CATEGORY_MECHANICAL_CHECK,
                    basis_ref,
                )
            )

    # -------------------------------------------------------------------------
    # V4: release_request_approvals (Layer 2)
    # -------------------------------------------------------------------------
    for rec in records:
        if rec.kind_path != RELEASE_REQUEST_KIND:
            continue
        if rec.ref in body_failed_refs:
            continue

        body = rec.body
        basis_ref = body.get("basisRef")
        request_id = body.get("requestId")
        contract_version = body.get("contractVersion")
        recipient_key = body.get("recipientKey")
        ground_id = body.get("groundId")
        raw_power = body.get("power")
        power_name = raw_power if type(raw_power) is str else "disclose"

        basis_rec = by_ref.get(basis_ref) if type(basis_ref) is str else None
        if (
            basis_rec is None
            or basis_rec.kind_path != BASIS_KIND
            or basis_ref in failed_basis_refs
        ):
            # V2 already reported missing/wrong-kind/invalid Basis; never emit V4 ok
            continue

        _, cited_v4_power = _find_ground_and_power(basis_rec.body, ground_id, power_name)
        if cited_v4_power is None:
            # V2 already rejected absent power / declared term; no approvalRule to verify
            continue

        contract = _resolve_contract(
            snapshots,
            contract_version=contract_version if type(contract_version) is str else None,
            at_record=rec,
        )

        v4_failed = False
        v4_incomplete = False

        # Resolve targets and verify exact subject union
        raw_targets = body.get("targets")
        targets = [t for t in raw_targets if type(t) is str] if isinstance(raw_targets, list) else []
        expected_subjects: set[str] = {
            s for s in (basis_rec.body.get("subjects") or []) if type(s) is str
        }
        for tgt in targets:
            resolved, t_subjs = _extract_target_subjects(
                tgt, by_ref, records_by_session, basis_by_session
            )
            if not resolved:
                v4_incomplete = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "incomplete",
                        "release_target_missing",
                        CATEGORY_UNAVAILABLE_EVIDENCE,
                        tgt,
                    )
                )
            else:
                expected_subjects.update(t_subjs)

        raw_req_subjs = body.get("subjects")
        req_subjects = (
            {s for s in raw_req_subjs if type(s) is str}
            if isinstance(raw_req_subjs, list)
            else set()
        )
        if not v4_incomplete:
            diff_subjects = sorted(expected_subjects ^ req_subjects)
            for diff_subj in diff_subjects:
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "release_subjects_incomplete",
                        CATEGORY_MECHANICAL_CHECK,
                        diff_subj,
                    )
                )

        # Verify approvals
        raw_approvals = body.get("approvals")
        approvals = raw_approvals if isinstance(raw_approvals, list) else []
        approval_payload = _safe_canonical_json(
            {
                "basisFingerprint": basis_ref,
                "contractVersion": contract_version,
                "recipientKey": recipient_key,
                "requestId": request_id,
            }
        )
        if approval_payload is None or len(approvals) > 64:
            v4_failed = True
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "release_request_approvals",
                    "failed",
                    "approval_signature_invalid",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
            continue

        approval_msg = b"r5e-release-approval-v1\x00" + approval_payload
        valid_approvals: list[tuple[str, str, bool]] = []
        seen_key_role: set[tuple[str, str]] = set()

        for app in approvals:
            if not isinstance(app, dict):
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "approval_signature_invalid",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                    )
                )
                continue
            signer_key = app.get("signerKey")
            role = app.get("role")
            sig_b64 = app.get("signature")
            if type(signer_key) is not str or type(role) is not str:
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "approval_signature_invalid",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        signer_key if type(signer_key) is str else None,
                    )
                )
                continue

            if not _verify_embedded_sig(keys_by_id, signer_key, approval_msg, sig_b64):
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "approval_signature_invalid",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        signer_key,
                    )
                )
                continue

            end_rec = _latest_active_endorsement(
                endorsements_by_key, signer_key, rec.captured_at, revocations_by_target
            )
            if end_rec is None:
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "approval_endorsement_inactive",
                        CATEGORY_MECHANICAL_CHECK,
                        signer_key,
                    )
                )
                continue

            if end_rec.body.get("keyStorage") != "hardware":
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "approval_key_not_hardware",
                        CATEGORY_MECHANICAL_CHECK,
                        signer_key,
                    )
                )
                continue

            # Fail closed if approverRoles omits role or signer_key
            role_keys = contract.approver_roles.get(role)
            if role_keys is None or signer_key not in role_keys:
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "approval_role_unlisted",
                        CATEGORY_MECHANICAL_CHECK,
                        role,
                    )
                )
                continue

            attested = _verify_hardware_attestation(
                end_rec.body.get("hardwareAttestationRef"),
                signer_key,
                contract,
                blobs_by_ref,
                salted_plaintexts,
                keys_by_id,
            )
            if (signer_key, role) not in seen_key_role:
                seen_key_role.add((signer_key, role))
                valid_approvals.append((signer_key, role, attested))

        # Check approvalRule threshold
        _, power_obj = _find_ground_and_power(basis_rec.body, ground_id, power_name)
        qualifying_approvals = valid_approvals
        if power_obj is not None:
            rule = power_obj.get("approvalRule")
            if isinstance(rule, dict):
                raw_roles = rule.get("roles")
                allowed_roles = (
                    {r for r in raw_roles if type(r) is str}
                    if isinstance(raw_roles, list)
                    else set()
                )
                raw_thr = rule.get("threshold")
                threshold = raw_thr if type(raw_thr) is int and raw_thr >= 1 else 1
                qualifying_approvals = [
                    (sk, r, att) for sk, r, att in valid_approvals if r in allowed_roles
                ]
                distinct_qualifying_keys = {sk for sk, _, _ in qualifying_approvals}
                if not v4_failed and len(distinct_qualifying_keys) < threshold:
                    v4_failed = True
                    a11_findings.append(
                        _a11_finding(
                            2,
                            rec.ref,
                            "release_request_approvals",
                            "failed",
                            "approval_threshold_not_met",
                            CATEGORY_MECHANICAL_CHECK,
                            basis_ref,
                        )
                    )

        if not v4_failed and not v4_incomplete:
            if not qualifying_approvals:
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "approval_threshold_not_met",
                        CATEGORY_MECHANICAL_CHECK,
                        basis_ref,
                    )
                )
            elif all(att for _, _, att in qualifying_approvals):
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "ok",
                        "ok",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        qualifying_approvals[0][0],
                    )
                )
            else:
                unattested_key = next(
                    sk for sk, _, att in qualifying_approvals if not att
                )
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "incomplete",
                        "hardware_attestation_unverified",
                        CATEGORY_INSTITUTIONAL_ASSERTION,
                        unattested_key,
                    )
                )

    # -------------------------------------------------------------------------
    # V6: release_receipt_fingerprint (Layer 2) — non-short-circuiting
    # -------------------------------------------------------------------------
    for rec in records:
        if rec.kind_path != RELEASE_RECEIPT_KIND:
            continue
        body = rec.body
        outcome = body.get("outcome")
        fp = body.get("releasedFingerprint")
        w_ref = body.get("witnessReceiptRef")
        req_ref = body.get("requestRef")
        req_rec = by_ref.get(req_ref) if type(req_ref) is str else None
        req_contract_ver = (
            req_rec.body.get("contractVersion")
            if req_rec is not None and type(req_rec.body.get("contractVersion")) is str
            else None
        )
        rec_contract = _resolve_contract(
            snapshots, contract_version=req_contract_ver, at_record=rec
        )

        v6_failed = False
        if outcome in ("released", "delivered") and type(fp) is not str:
            v6_failed = True
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "release_receipt_fingerprint",
                    "failed",
                    "released_fingerprint_missing",
                    CATEGORY_MECHANICAL_CHECK,
                )
            )
        if outcome in ("denied", "failed") and type(fp) is str:
            v6_failed = True
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "release_receipt_fingerprint",
                    "failed",
                    "released_fingerprint_unexpected",
                    CATEGORY_MECHANICAL_CHECK,
                    fp,
                )
            )
        if rec_contract.custody_level == 2 and type(w_ref) is not str:
            v6_failed = True
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "release_receipt_fingerprint",
                    "failed",
                    "witness_receipt_missing_l2",
                    CATEGORY_MECHANICAL_CHECK,
                )
            )
        if not v6_failed:
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "release_receipt_fingerprint",
                    "ok",
                    "ok",
                    CATEGORY_MECHANICAL_CHECK,
                    fp if type(fp) is str else None,
                )
            )

    # -------------------------------------------------------------------------
    # V7: succession_recovery (Layer 2)
    # -------------------------------------------------------------------------
    if _precomputed_v7 is not None:
        v7_findings, _ = _precomputed_v7
    else:
        v7_findings, _ = _evaluate_successions_v7(
            records,
            by_ref,
            base_def_index_refs,
            keys_by_id,
            snapshots,
            endorsements_by_key,
            revocations_by_target,
        )
    a11_findings.extend(v7_findings)

    # -------------------------------------------------------------------------
    # V8: erasure_l2_proof (Layer 3)
    # -------------------------------------------------------------------------
    for rec in records:
        if rec.kind_path != ERASURE_ANSWER_KIND or rec.ref in body_failed_refs:
            continue
        rec_contract = _resolve_contract(snapshots, at_record=rec)
        sessions = rec.body.get("sessions")
        if not isinstance(sessions, list):
            continue
        for sess in sessions:
            if not isinstance(sess, dict):
                continue
            if sess.get("governedState") != "destroyed":
                continue
            session_uri = sess.get("session")
            session_about = session_uri if type(session_uri) is str else None
            ev_support = sess.get("evidentialSupport")

            if ev_support == "institution_claim":
                if rec_contract.custody_level == 2:
                    a11_findings.append(
                        _a11_finding(
                            3,
                            rec.ref,
                            "erasure_l2_proof",
                            "failed",
                            "erasure_institution_claim_at_l2",
                            CATEGORY_CRYPTOGRAPHIC_PROOF,
                            session_about,
                        )
                    )
                else:
                    a11_findings.append(
                        _a11_finding(
                            3,
                            rec.ref,
                            "erasure_l2_proof",
                            "ok",
                            "ok",
                            CATEGORY_INSTITUTIONAL_ASSERTION,
                            session_about,
                        )
                    )
                continue

            if ev_support != "sealed_key_service_proof":
                continue

            if not rec_contract.sealed_service_copies:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_proof_invalid_or_missing_l2",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        session_about,
                    )
                )
                continue

            raw_confirmed = sess.get("confirmedCopies")
            confirmed_copies = (
                [c for c in raw_confirmed if type(c) is str]
                if isinstance(raw_confirmed, list)
                else []
            )
            unknown_copies = [
                c for c in confirmed_copies if c not in rec_contract.sealed_service_copies
            ]
            if unknown_copies:
                for cid in unknown_copies:
                    a11_findings.append(
                        _a11_finding(
                            3,
                            rec.ref,
                            "erasure_l2_proof",
                            "failed",
                            "erasure_unknown_copy_id",
                            CATEGORY_CRYPTOGRAPHIC_PROOF,
                            cid,
                        )
                    )
                continue

            proof_ref = sess.get("proofRef")
            proof_raw: bytes | None = None
            if type(proof_ref) is str:
                proof_raw = blobs_by_ref.get(proof_ref)
                if proof_raw is None:
                    proof_raw = salted_plaintexts.get(proof_ref)

            if proof_raw is None:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_proof_invalid_or_missing_l2",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        session_about,
                    )
                )
                continue

            try:
                proof_obj = parse_canonical_json(proof_raw)
            except ValueError:
                proof_obj = None

            if (
                not isinstance(proof_obj, dict)
                or proof_obj.get("session") != session_uri
                or type(proof_obj.get("destroyedAt")) is not str
                or not isinstance(proof_obj.get("copyConfirmations"), list)
            ):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_proof_invalid_or_missing_l2",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        session_about,
                    )
                )
                continue

            # Index copyConfirmations and reject duplicate copyId
            conf_by_copy: dict[str, dict[str, Any]] = {}
            dup_copy: str | None = None
            for conf in proof_obj["copyConfirmations"]:
                if not isinstance(conf, dict) or type(conf.get("copyId")) is not str:
                    continue
                cid = conf["copyId"]
                if cid in conf_by_copy:
                    dup_copy = cid
                    break
                conf_by_copy[cid] = conf

            if dup_copy is not None:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_proof_invalid_or_missing_l2",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        dup_copy,
                    )
                )
                continue

            if not confirmed_copies:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_proof_invalid_or_missing_l2",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        session_about,
                    )
                )
                continue

            destroyed_at = proof_obj["destroyedAt"]
            bad_copy: str | None = None
            for cid in confirmed_copies:
                conf = conf_by_copy.get(cid)
                expected_key_id = rec_contract.sealed_service_copies[cid]
                if conf is None:
                    bad_copy = cid
                    break
                conf_key_id = conf.get("keyId")
                if type(conf_key_id) is not str or not hmac.compare_digest(
                    conf_key_id, expected_key_id
                ):
                    bad_copy = cid
                    break
                c_bytes = _safe_canonical_json(
                    {
                        "copyId": cid,
                        "destroyedAt": destroyed_at,
                        "session": session_uri,
                    }
                )
                if c_bytes is None or not _verify_embedded_sig(
                    keys_by_id,
                    expected_key_id,
                    b"r5e-erasure-proof-v1\x00" + c_bytes,
                    conf.get("signature"),
                ):
                    bad_copy = cid
                    break

            if bad_copy is not None:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_proof_invalid_or_missing_l2",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        bad_copy,
                    )
                )
                continue

            confirmed_set = set(confirmed_copies)
            pending_copies = [
                c for c in rec_contract.sealed_copy_order if c not in confirmed_set
            ]
            if pending_copies:
                for cid in pending_copies:
                    a11_findings.append(
                        _a11_finding(
                            3,
                            rec.ref,
                            "erasure_l2_proof",
                            "incomplete",
                            "erasure_copy_confirmation_pending",
                            CATEGORY_UNAVAILABLE_EVIDENCE,
                            cid,
                        )
                    )
                continue

            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "erasure_l2_proof",
                    "ok",
                    "ok",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    session_about,
                )
            )

    # -------------------------------------------------------------------------
    # V10: checkpoint_and_unlock_log (Layer 3)
    # -------------------------------------------------------------------------
    # 10a. Checkpoints monotonicity over bundle.checkpoints, duplicate-seq forks, and pins
    ckpts_by_seq: dict[int, list[str]] = {}
    for rec in records:
        if rec.kind_path != CHECKPOINT_KIND:
            continue
        seq_val = rec.payload.get("seq")
        if type(seq_val) is int:
            ckpts_by_seq.setdefault(seq_val, []).append(rec.ref)

    prev_ckpt_seq: int | None = None
    bundle_ckpts = bundle.get("checkpoints")
    if isinstance(bundle_ckpts, list):
        for ckpt_ref in bundle_ckpts:
            if type(ckpt_ref) is not str:
                continue
            ckpt_rec = by_ref.get(ckpt_ref)
            if ckpt_rec is None or ckpt_rec.kind_path != CHECKPOINT_KIND:
                continue
            seq_val = ckpt_rec.payload.get("seq")
            if type(seq_val) is not int:
                continue
            if prev_ckpt_seq is not None and seq_val <= prev_ckpt_seq:
                a11_findings.append(
                    _a11_finding(
                        3,
                        ckpt_rec.ref,
                        "checkpoint_and_unlock_log",
                        "failed",
                        "checkpoint_fork_or_stale",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        f"seq:{seq_val}",
                    )
                )
            prev_ckpt_seq = seq_val

    all_pins: list[tuple[int, str]] = []
    seen_pins: set[tuple[int, str]] = set()
    for pin_src in (trusted_checkpoints, bundle.get("pinnedCheckpoints") or ()):
        if not isinstance(pin_src, Sequence):
            continue
        for pin in pin_src:
            if not isinstance(pin, dict):
                continue
            p_seq = pin.get("seq")
            p_ref = pin.get("ref")
            if type(p_seq) is int and type(p_ref) is str:
                key = (p_seq, p_ref)
                if key not in seen_pins:
                    seen_pins.add(key)
                    all_pins.append(key)

    for pin_seq, pin_ref in all_pins:
        actual_refs = ckpts_by_seq.get(pin_seq, [])
        if not actual_refs:
            a11_findings.append(
                _a11_finding(
                    3,
                    "bundle",
                    "checkpoint_and_unlock_log",
                    "failed",
                    "checkpoint_fork_or_stale",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    pin_ref,
                )
            )
        else:
            mismatched = [r for r in actual_refs if not hmac.compare_digest(r, pin_ref)]
            if mismatched:
                a11_findings.append(
                    _a11_finding(
                        3,
                        mismatched[0],
                        "checkpoint_and_unlock_log",
                        "failed",
                        "checkpoint_fork_or_stale",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        pin_ref,
                    )
                )

    # Build index of valid releases covering sessions / targets / content refs
    released_targets_by_ref: dict[str, set[str]] = {}
    all_released_targets: set[str] = set()
    for rec in records:
        if rec.kind_path == RELEASE_RECEIPT_KIND and rec.body.get("outcome") in (
            "released",
            "delivered",
        ):
            req_ref = rec.body.get("requestRef")
            req_rec = by_ref.get(req_ref) if type(req_ref) is str else None
            if req_rec is not None and req_rec.kind_path == RELEASE_REQUEST_KIND:
                raw_t = req_rec.body.get("targets")
                tset = {t for t in raw_t if type(t) is str} if isinstance(raw_t, list) else set()
                released_targets_by_ref[rec.ref] = tset
                all_released_targets.update(tset)
        elif rec.kind_path == DISCLOSURE_KIND and rec.body.get("outcome") in (
            "provided",
            "partial",
        ):
            tset = set()
            raw_prov = rec.body.get("providedRefs")
            if isinstance(raw_prov, list):
                tset.update(x for x in raw_prov if type(x) is str)
            scope = rec.body.get("scope")
            if isinstance(scope, dict):
                s_sess = scope.get("session")
                if type(s_sess) is str:
                    tset.add(s_sess)
                s_recs = scope.get("records")
                if isinstance(s_recs, list):
                    tset.update(x for x in s_recs if type(x) is str)
            raw_excl = rec.body.get("excluding")
            if isinstance(raw_excl, list):
                tset.difference_update(x for x in raw_excl if type(x) is str)
            released_targets_by_ref[rec.ref] = tset
            all_released_targets.update(tset)

    # 10b. Level 1 unlock log
    unlock_log = bundle.get("unlockLog")
    if isinstance(unlock_log, list):
        for entry in unlock_log:
            if not isinstance(entry, dict):
                continue
            raw_entry_id = entry.get("entryId")
            entry_id = raw_entry_id if type(raw_entry_id) is str and raw_entry_id else "unlock"
            session = entry.get("session")
            rel_ref = entry.get("releaseRef")
            covered = (
                type(session) is str
                and len(session) > 0
                and type(rel_ref) is str
                and rel_ref in released_targets_by_ref
                and session in released_targets_by_ref[rel_ref]
            )
            if not covered:
                a11_findings.append(
                    _a11_finding(
                        3,
                        entry_id,
                        "checkpoint_and_unlock_log",
                        "failed",
                        "unlock_without_release_record",
                        CATEGORY_MECHANICAL_CHECK,
                        session if type(session) is str else None,
                    )
                )

    # 10c. Unrecorded session plaintext in bundle (both bare blobs and saltedContent)
    for rec in records:
        if rec.kind_path in _EXCLUDED_GOVERNANCE_KINDS:
            continue
        session = rec.payload.get("session")
        if type(session) is not str:
            continue
        cited_refs: set[str] = set()
        _collect_bare_bytes_refs(rec.body, cited_refs)
        _collect_salted_refs(rec.body, cited_refs)
        for c_ref in sorted(cited_refs):
            carried = c_ref in blobs_by_ref or c_ref in salted_plaintexts
            if not carried:
                continue
            if (
                session not in all_released_targets
                and rec.ref not in all_released_targets
                and c_ref not in all_released_targets
            ):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "checkpoint_and_unlock_log",
                        "failed",
                        "unrecorded_plaintext_in_bundle",
                        CATEGORY_MECHANICAL_CHECK,
                        c_ref,
                    )
                )

    a11_findings.sort(key=_finding_sort_key)
    return a11_findings


def verify_provenance_bundle_a11(
    bundle: Any,
    *,
    trusted_profiles: Sequence[str] = (),
    trusted_publishers: Sequence[str] = (),
    trusted_roots: Sequence[str] | None = None,
    trusted_chain: str | None = None,
    min_start_seq: int | None = None,
    installed_definitions: dict[str, bytes] | None = None,
    trusted_checkpoints: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Verify a Provenance v2 bundle with Amendment A11 rules (V1–V11) and complete finding classification."""
    schemas = _load_bundled_schemas()
    precomputed_v7: tuple[list[dict[str, Any]], set[str]] | None = None
    excluded_successions: set[str] = set()

    if _validate_bundle_shape(bundle, schemas["export.schema.json"], allow_a11=True):
        _, base_def_index_refs = _load_base_definitions()
        _, keys_by_id, records, by_ref = _parse_bundle_context(bundle)
        snapshots = _extract_contract_history(records)
        revocations_by_target: dict[str, list[_ParsedRecord]] = {}
        endorsements_by_key: dict[str, list[_ParsedRecord]] = {}
        for rec in records:
            if rec.kind_path == REVOCATION_KIND:
                tgt = rec.body.get("target")
                if type(tgt) is str:
                    revocations_by_target.setdefault(tgt, []).append(rec)
            elif rec.kind_path == ENDORSEMENT_KIND:
                subj = rec.body.get("subject")
                if type(subj) is str:
                    endorsements_by_key.setdefault(subj, []).append(rec)
        for elist in endorsements_by_key.values():
            elist.sort(key=lambda r: (r.captured_at or _zero_instant(), r.seq, r.ref))
        precomputed_v7 = _evaluate_successions_v7(
            records,
            by_ref,
            base_def_index_refs,
            keys_by_id,
            snapshots,
            endorsements_by_key,
            revocations_by_target,
        )
        excluded_successions = precomputed_v7[1]

    baseline = verify_provenance_bundle_baseline(
        bundle,
        trusted_profiles=trusted_profiles,
        trusted_publishers=trusted_publishers,
        trusted_roots=trusted_roots,
        trusted_chain=trusted_chain,
        min_start_seq=min_start_seq,
        installed_definitions=installed_definitions,
        allow_a11=True,
        excluded_succession_refs=excluded_successions,
    )
    raw_baseline_findings: list[dict[str, Any]] = baseline["findings"]
    classified_baseline_findings: list[dict[str, Any]] = []
    for bf in raw_baseline_findings:
        enriched = dict(bf)
        enriched["category"] = classify_finding(bf)
        classified_baseline_findings.append(enriched)

    a11_findings = verify_a11_rules(
        bundle,
        baseline_findings=raw_baseline_findings,
        trusted_checkpoints=trusted_checkpoints,
        _precomputed_v7=precomputed_v7,
    )

    all_findings = classified_baseline_findings + a11_findings
    total_ok = sum(1 for f in all_findings if f["result"] == "ok")
    total_failed = sum(1 for f in all_findings if f["result"] == "failed")
    total_incomplete = sum(1 for f in all_findings if f["result"] == "incomplete")
    total_summary = {
        "failed": total_failed,
        "incomplete": total_incomplete,
        "ok": total_ok,
        "total": len(all_findings),
    }

    categories = {
        CATEGORY_CRYPTOGRAPHIC_PROOF: 0,
        CATEGORY_INSTITUTIONAL_ASSERTION: 0,
        CATEGORY_MECHANICAL_CHECK: 0,
        CATEGORY_UNAVAILABLE_EVIDENCE: 0,
    }
    for f in all_findings:
        cat = f["category"]
        if cat in categories:
            categories[cat] += 1

    if total_failed > 0:
        verdict = "failed"
    elif total_incomplete > 0:
        verdict = "incomplete"
    else:
        verdict = "ok"

    return {
        "a11Findings": a11_findings,
        "amendment": "A11",
        "baseline": {
            "findings": classified_baseline_findings,
            "summary": baseline["summary"],
        },
        "categories": categories,
        "format": PROVENANCE_REPORT_FORMAT,
        "summary": total_summary,
        "verdict": verdict,
    }
