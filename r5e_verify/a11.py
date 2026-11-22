"""Amendment A11 offline verification rules (V1–V11) and finding classification."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .provenance import (
    BASIS_KIND,
    BASIS_OVERLAY_KIND,
    BYTES_REF_RE,
    CHECKPOINT_KIND,
    DEFINITION_PUBLISHED_KIND,
    DEPLOYMENT_KIND,
    ENDORSEMENT_KIND,
    ERASURE_ANSWER_KIND,
    PROVENANCE_REPORT_FORMAT,
    RELEASE_RECEIPT_KIND,
    RELEASE_REQUEST_KIND,
    RETENTION_HOLD_KIND,
    ROOTS_CHANGED_KIND,
    SALTED_BYTES_REF_RE,
    SUCCESSION_KIND,
    _load_base_definitions,
    _load_bundled_schemas,
    _validate_bundle_shape,
    bytes_ref,
    canonical_json_bytes,
    decode_base64,
    decode_strict_base64,
    parse_canonical_json,
    parse_rfc3339_instant_ns,
    verify_provenance_bundle,
    verify_record_envelope,
    verify_signature,
)

DISCLOSURE_KIND = "provenance.r5e.io/v2/Disclosure"

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

_PERSON_URI_MARKERS = (":person:", ":subject:", ":user:", ":human:")

_NON_SESSION_PLAINTEXT_KINDS: frozenset[str] = frozenset(
    {
        BASIS_KIND,
        BASIS_OVERLAY_KIND,
        RELEASE_REQUEST_KIND,
        RELEASE_RECEIPT_KIND,
        ERASURE_ANSWER_KIND,
        DISCLOSURE_KIND,
        ENDORSEMENT_KIND,
        SUCCESSION_KIND,
        DEPLOYMENT_KIND,
        ROOTS_CHANGED_KIND,
        DEFINITION_PUBLISHED_KIND,
        CHECKPOINT_KIND,
        RETENTION_HOLD_KIND,
    }
)

_CRYPTO_CODES: frozenset[str] = frozenset(
    {
        "approval_signature_invalid",
        "witness_receipt_hash_mismatch",
        "witness_unpinned",
        "succession_recovery_threshold_not_met",
        "succession_recovery_rule_unknown",
        "erasure_proof_invalid_or_missing_l2",
        "erasure_unknown_copy_id",
        "erasure_copy_confirmation_pending",
        "salted_content_digest_mismatch",
        "checkpoint_fork_or_stale",
    }
)

_UNAVAILABLE_CODES: frozenset[str] = frozenset(
    {
        "unavailable_evidence",
        "not_carried",
        "missing_key",
        "definition_not_available",
        "profile_not_available",
    }
)

_CRYPTO_CHECKS: frozenset[str] = frozenset(
    {
        "witness_receipt_binding",
        "succession_recovery",
        "salted_content_ref",
        "signature",
        "content_hash",
    }
)


def classify_finding(finding: dict[str, Any]) -> str:
    """Classify a verifier finding into one of the four A11 finding categories."""
    existing = finding.get("category")
    if isinstance(existing, str) and existing in VALID_CATEGORIES:
        return existing

    code = finding.get("code")
    check = finding.get("check")
    result = finding.get("result")

    if code in _UNAVAILABLE_CODES:
        return CATEGORY_UNAVAILABLE_EVIDENCE
    if code in _CRYPTO_CODES:
        return CATEGORY_CRYPTOGRAPHIC_PROOF
    if check in _CRYPTO_CHECKS:
        if result == "incomplete" and code in _UNAVAILABLE_CODES:
            return CATEGORY_UNAVAILABLE_EVIDENCE
        return CATEGORY_CRYPTOGRAPHIC_PROOF
    if check == "erasure_l2_proof":
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


@dataclass(frozen=True)
class _ParsedRecord:
    ref: str
    payload_bytes: bytes
    payload: dict[str, Any]
    signers: list[str]
    kind_path: str
    body: dict[str, Any]


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


def _is_person_uri(uri: Any) -> bool:
    if type(uri) is not str:
        return False
    return any(marker in uri for marker in _PERSON_URI_MARKERS)


def _basis_names_person(body: dict[str, Any]) -> bool:
    subjects = body.get("subjects")
    if isinstance(subjects, list) and len(subjects) > 0:
        return True
    rep = body.get("representative")
    if type(rep) is str and len(rep) > 0:
        return True
    return _is_person_uri(body.get("actor"))


def _verify_embedded_sig(
    keys_by_id: dict[str, tuple[str, bytes]],
    key_id: Any,
    msg: bytes,
    sig_b64: Any,
) -> bool:
    if type(key_id) is not str or type(sig_b64) is not str:
        return False
    key_entry = keys_by_id.get(key_id)
    if key_entry is None:
        return False
    try:
        sig_bytes = decode_strict_base64(sig_b64)
    except ValueError:
        return False
    alg, key_bytes = key_entry
    return verify_signature(alg, key_bytes, sig_bytes, msg)


def _extract_contract_state(records: list[_ParsedRecord]) -> dict[str, Any]:
    """Extract latest A11 deployment contract fields from Deployment / RootsChanged records."""
    contract_recs = [
        r for r in records if r.kind_path in (DEPLOYMENT_KIND, ROOTS_CHANGED_KIND)
    ]
    contract_recs.sort(
        key=lambda r: (
            int(r.payload.get("seq", 0)),
            parse_rfc3339_instant_ns(r.payload.get("capturedAt")) or 0,
            r.ref,
        )
    )
    custody_level = 1
    witness_keys: set[str] = set()
    overseer_key: str | None = None
    approver_roles: dict[str, set[str]] = {}
    sealed_service_copies: list[str] = []

    for rec in contract_recs:
        body = rec.body
        if type(body.get("custodyLevel")) is int:
            custody_level = body["custodyLevel"]
        if isinstance(body.get("witnessKeys"), list):
            witness_keys = {k for k in body["witnessKeys"] if type(k) is str}
        if type(body.get("overseerKey")) is str:
            overseer_key = body["overseerKey"]
        if isinstance(body.get("approverRoles"), list):
            roles_map: dict[str, set[str]] = {}
            for entry in body["approverRoles"]:
                if isinstance(entry, dict) and type(entry.get("role")) is str:
                    ks = entry.get("keys")
                    if isinstance(ks, list):
                        roles_map[entry["role"]] = {k for k in ks if type(k) is str}
            approver_roles = roles_map
        if isinstance(body.get("sealedServiceCopies"), list):
            sealed_service_copies = [
                c for c in body["sealedServiceCopies"] if type(c) is str
            ]

    return {
        "custody_level": custody_level,
        "witness_keys": witness_keys,
        "overseer_key": overseer_key,
        "approver_roles": approver_roles,
        "sealed_service_copies": sealed_service_copies,
    }


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


def verify_a11_rules(
    bundle: Any,
    *,
    baseline_findings: Sequence[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Run Amendment A11 offline verifier rules (V1–V11) on a parsed bundle."""
    schemas = _load_bundled_schemas()
    if not _validate_bundle_shape(bundle, schemas["export.schema.json"]):
        return []

    _, base_def_index_refs = _load_base_definitions()
    signed_schema = schemas["signed-evidence.schema.json"]

    # Decode blobs and keys
    blobs_by_ref: dict[str, bytes] = {}
    for blob_entry in bundle["blobs"]:
        b_ref = blob_entry["ref"]
        try:
            raw_blob = decode_base64(blob_entry["base64"])
        except ValueError:
            continue
        if bytes_ref(raw_blob) == b_ref:
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

    # Open records
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
        )
        records.append(rec)
        by_ref[rec_ref] = rec

    contract = _extract_contract_state(records)
    custody_level: int = contract["custody_level"]
    witness_keys: set[str] = contract["witness_keys"]
    approver_roles: dict[str, set[str]] = contract["approver_roles"]
    sealed_service_copies: list[str] = contract["sealed_service_copies"]

    # Index endorsements by subject key (latest wins)
    endorsements_by_key: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        if rec.kind_path == ENDORSEMENT_KIND:
            subj = rec.body.get("subject")
            if type(subj) is str:
                endorsements_by_key.setdefault(subj, []).append(rec)
    for elist in endorsements_by_key.values():
        elist.sort(
            key=lambda r: (
                parse_rfc3339_instant_ns(r.payload.get("capturedAt")) or 0,
                int(r.payload.get("seq", 0)),
                r.ref,
            )
        )

    # Index BasisOverlays by basisRef
    overlays_by_basis: dict[str, list[_ParsedRecord]] = {}
    for rec in records:
        if rec.kind_path == BASIS_OVERLAY_KIND:
            bref = rec.body.get("basisRef")
            if type(bref) is str:
                overlays_by_basis.setdefault(bref, []).append(rec)
    for olist in overlays_by_basis.values():
        olist.sort(
            key=lambda r: (
                parse_rfc3339_instant_ns(r.body.get("effectiveAt")) or 0,
                int(r.payload.get("seq", 0)),
                r.ref,
            )
        )

    # Index body_ok from baseline findings if provided
    body_ok_refs: set[str] = set()
    if baseline_findings is not None:
        for f in baseline_findings:
            if f.get("check") == "body" and f.get("result") == "ok":
                subj = f.get("subject")
                if type(subj) is str:
                    body_ok_refs.add(subj)

    a11_findings: list[dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # V9: salted_content_ref (Layer 1)
    # -------------------------------------------------------------------------
    salted_content = bundle.get("saltedContent")
    salted_map: dict[str, Any] = salted_content if isinstance(salted_content, dict) else {}
    for rec in records:
        salted_refs: set[str] = set()
        _collect_salted_refs(rec.body, salted_refs)
        for s_ref in sorted(salted_refs):
            if s_ref not in salted_map:
                a11_findings.append(
                    _a11_finding(
                        1,
                        rec.ref,
                        "salted_content_ref",
                        "incomplete",
                        "unavailable_evidence",
                        CATEGORY_UNAVAILABLE_EVIDENCE,
                        s_ref,
                    )
                )
                continue
            entry = salted_map[s_ref]
            verified = False
            if isinstance(entry, dict) and type(entry.get("salt")) is str and type(entry.get("bytes")) is str:
                try:
                    salt_bytes = decode_strict_base64(entry["salt"])
                    raw_bytes = decode_strict_base64(entry["bytes"])
                    if len(salt_bytes) == 32:
                        digest = hashlib.sha256(
                            b"r5e-salted-content-v1\x00" + salt_bytes + raw_bytes
                        ).hexdigest()
                        verified = f"bytes:sha256+salt:{digest}" == s_ref
                except ValueError:
                    verified = False
            if verified:
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
            and (baseline_findings is None or rec.ref in body_ok_refs)
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
    for rec in records:
        if rec.kind_path != BASIS_KIND:
            continue
        if _basis_names_person(rec.body):
            if len(set(rec.signers)) < 2:
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
            else:
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
        else:
            if len(set(rec.signers)) >= 1:
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

    # -------------------------------------------------------------------------
    # V2 & V3: basis_declared_power & basis_overlay_order (Layer 3)
    # -------------------------------------------------------------------------
    for rec in records:
        if rec.kind_path not in (RELEASE_REQUEST_KIND, DISCLOSURE_KIND, RETENTION_HOLD_KIND):
            continue
        basis_ref = rec.body.get("basisRef")
        if type(basis_ref) is not str:
            continue
        target = by_ref.get(basis_ref)
        if target is None:
            continue

        # V2: amendment_proposal authorises nothing
        if target.kind_path == BASIS_OVERLAY_KIND and target.body.get("overlayType") == "amendment_proposal":
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
            continue

        # V2: declaredTerms / absent power on ReleaseRequest
        cited_power_obj: dict[str, Any] | None = None
        if rec.kind_path == RELEASE_REQUEST_KIND:
            ground_id = rec.body.get("groundId")
            raw_power = rec.body.get("power")
            power_name = raw_power if isinstance(raw_power, str) else "disclose"
            declared_terms = target.body.get("declaredTerms")
            if isinstance(declared_terms, list) and any(
                isinstance(t, dict) and t.get("termId") == ground_id for t in declared_terms
            ):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "basis_declared_power",
                        "failed",
                        "act_cites_declared_or_absent_power",
                        CATEGORY_MECHANICAL_CHECK,
                        str(ground_id),
                    )
                )
                continue
            ground_obj, power_obj = _find_ground_and_power(target.body, ground_id, power_name)
            if ground_obj is None:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "basis_declared_power",
                        "failed",
                        "act_cites_declared_or_absent_power",
                        CATEGORY_MECHANICAL_CHECK,
                        str(ground_id),
                    )
                )
                continue
            if power_obj is None:
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
                continue
            cited_power_obj = power_obj
            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "basis_declared_power",
                    "ok",
                    "ok",
                    CATEGORY_MECHANICAL_CHECK,
                    str(ground_id),
                )
            )

        # V3: basis_overlay_order (withdrawal / duration expiration)
        act_ts = parse_rfc3339_instant_ns(rec.payload.get("capturedAt"))
        act_stream = rec.payload.get("stream")
        act_seq = int(rec.payload.get("seq", 0))
        withdrawn_by: str | None = None

        for ov in overlays_by_basis.get(basis_ref, ()):
            if ov.body.get("overlayType") != "withdrawal":
                continue
            ov_eff = parse_rfc3339_instant_ns(ov.body.get("effectiveAt"))
            ov_stream = ov.payload.get("stream")
            ov_seq = int(ov.payload.get("seq", 0))
            if ov_stream == act_stream:
                if ov_seq < act_seq and (ov_eff is None or act_ts is None or ov_eff <= act_ts):
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

        expired = False
        if cited_power_obj is not None:
            dur = cited_power_obj.get("duration")
            if isinstance(dur, dict) and type(dur.get("until")) is str and act_ts is not None:
                until_ts = parse_rfc3339_instant_ns(dur["until"])
                if until_ts is not None and act_ts > until_ts:
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
            continue

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
        body = rec.body
        basis_ref = body.get("basisRef")
        request_id = body.get("requestId")
        contract_version = body.get("contractVersion")
        recipient_key = body.get("recipientKey")
        ground_id = body.get("groundId")
        raw_power = body.get("power")
        power_name = raw_power if isinstance(raw_power, str) else "disclose"
        raw_approvals = body.get("approvals")
        approvals: list[Any] = raw_approvals if isinstance(raw_approvals, list) else []

        basis_rec = by_ref.get(basis_ref) if type(basis_ref) is str else None
        if basis_rec is not None and basis_rec.kind_path != BASIS_KIND:
            basis_rec = None

        v4_failed = False

        # Check subjects completeness against Basis subjects
        if basis_rec is not None:
            expected_subjects = {
                s for s in basis_rec.body.get("subjects", []) if type(s) is str
            }
            req_subjects = {
                s for s in body.get("subjects", []) if type(s) is str
            }
            missing_subjects = sorted(expected_subjects - req_subjects)
            for missing_subj in missing_subjects:
                v4_failed = True
                a11_findings.append(
                    _a11_finding(
                        2,
                        rec.ref,
                        "release_request_approvals",
                        "failed",
                        "release_subjects_incomplete",
                        CATEGORY_MECHANICAL_CHECK,
                        missing_subj,
                    )
                )

        # Verify each approval signature and hardware key storage
        approval_msg = b"r5e-release-approval-v1\x00" + canonical_json_bytes(
            {
                "basisFingerprint": basis_ref,
                "contractVersion": contract_version,
                "recipientKey": recipient_key,
                "requestId": request_id,
            }
        )
        valid_approvers: list[tuple[str, str, bool]] = []
        seen_approver_keys: set[str] = set()
        for app in approvals:
            if not isinstance(app, dict):
                continue
            signer_key = app.get("signerKey")
            role = app.get("role")
            sig_b64 = app.get("signature")
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
                        signer_key if type(signer_key) is str else None,
                    )
                )
                continue

            assert type(signer_key) is str
            end_list = endorsements_by_key.get(signer_key, [])
            end_body = end_list[-1].body if end_list else {}
            if end_body.get("keyStorage") != "hardware":
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

            att_ref = end_body.get("hardwareAttestationRef")
            attested = type(att_ref) is str and att_ref in blobs_by_ref
            if signer_key not in seen_approver_keys and type(role) is str:
                seen_approver_keys.add(signer_key)
                valid_approvers.append((signer_key, role, attested))

        # Check approvalRule threshold when cited ground/power exists on Basis
        if not v4_failed and basis_rec is not None:
            _, power_obj = _find_ground_and_power(basis_rec.body, ground_id, power_name)
            if power_obj is not None:
                rule = power_obj.get("approvalRule")
                if isinstance(rule, dict):
                    allowed_roles = {
                        r for r in rule.get("roles", []) if type(r) is str
                    }
                    threshold = int(rule.get("threshold", 1))
                    qualifying = [
                        (sk, role, att)
                        for sk, role, att in valid_approvers
                        if role in allowed_roles
                        and (
                            role not in approver_roles
                            or sk in approver_roles[role]
                        )
                    ]
                    if len(qualifying) < threshold:
                        v4_failed = True
                        a11_findings.append(
                            _a11_finding(
                                2,
                                rec.ref,
                                "release_request_approvals",
                                "failed",
                                "approval_threshold_not_met",
                                CATEGORY_MECHANICAL_CHECK,
                                str(ground_id),
                            )
                        )

        if not v4_failed:
            all_attested = bool(valid_approvers) and all(att for _, _, att in valid_approvers)
            cat = (
                CATEGORY_CRYPTOGRAPHIC_PROOF
                if all_attested
                else CATEGORY_INSTITUTIONAL_ASSERTION
            )
            about_key = valid_approvers[0][0] if valid_approvers else None
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "release_request_approvals",
                    "ok",
                    "ok",
                    cat,
                    about_key,
                )
            )

    # -------------------------------------------------------------------------
    # V5 & V6: witness_receipt_binding (L3) & release_receipt_fingerprint (L2)
    # -------------------------------------------------------------------------
    witness_receipts_raw = bundle.get("witnessReceipts")
    witness_receipts: dict[str, Any] = (
        witness_receipts_raw if isinstance(witness_receipts_raw, dict) else {}
    )

    for rec in records:
        if rec.kind_path != RELEASE_RECEIPT_KIND:
            continue
        body = rec.body
        outcome = body.get("outcome")
        fp = body.get("releasedFingerprint")
        w_ref = body.get("witnessReceiptRef")
        req_ref = body.get("requestRef")

        # V6: release_receipt_fingerprint
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
        if custody_level == 2 and type(w_ref) is not str:
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

        # V5: witness_receipt_binding
        if type(w_ref) is str:
            receipt = witness_receipts.get(w_ref)
            if not isinstance(receipt, dict):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "witness_receipt_binding",
                        "failed",
                        "witness_receipt_hash_mismatch",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        w_ref,
                    )
                )
                continue

            w_key = receipt.get("witnessKey")
            if type(w_key) is not str or w_key not in witness_keys:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "witness_receipt_binding",
                        "failed",
                        "witness_unpinned",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        w_key if type(w_key) is str else w_ref,
                    )
                )
                continue

            # Verify map key matches canonical receipt hash
            if bytes_ref(canonical_json_bytes(receipt)) != w_ref:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "witness_receipt_binding",
                        "failed",
                        "witness_receipt_hash_mismatch",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        w_ref,
                    )
                )
                continue

            req_rec = by_ref.get(req_ref) if type(req_ref) is str else None
            expected_req_hash = (
                "sha256:" + hashlib.sha256(req_rec.payload_bytes).hexdigest()
                if req_rec is not None
                else None
            )
            if (
                req_rec is None
                or receipt.get("requestRef") != req_ref
                or receipt.get("requestHash") != expected_req_hash
            ):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "witness_receipt_binding",
                        "failed",
                        "witness_receipt_hash_mismatch",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        w_ref,
                    )
                )
                continue

            unsigned = {
                "logIndex": receipt.get("logIndex"),
                "loggedAt": receipt.get("loggedAt"),
                "requestHash": receipt.get("requestHash"),
                "requestRef": receipt.get("requestRef"),
                "witnessKey": w_key,
            }
            w_msg = b"r5e-witness-receipt-v1\x00" + canonical_json_bytes(unsigned)
            if not _verify_embedded_sig(keys_by_id, w_key, w_msg, receipt.get("signature")):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "witness_receipt_binding",
                        "failed",
                        "witness_receipt_hash_mismatch",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        w_ref,
                    )
                )
                continue

            a11_findings.append(
                _a11_finding(
                    3,
                    rec.ref,
                    "witness_receipt_binding",
                    "ok",
                    "ok",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                    w_ref,
                )
            )

    # -------------------------------------------------------------------------
    # V7: succession_recovery (Layer 2)
    # -------------------------------------------------------------------------
    for rec in records:
        if rec.kind_path != SUCCESSION_KIND:
            continue
        recovery_proof = rec.body.get("recoveryProof")
        if not isinstance(recovery_proof, dict):
            continue

        rule_ref = recovery_proof.get("recoveryRuleRef")
        rule_rec = by_ref.get(rule_ref) if type(rule_ref) is str else None
        recovery_rule = (
            rule_rec.body.get("recoveryRule")
            if rule_rec is not None and isinstance(rule_rec.body.get("recoveryRule"), dict)
            else None
        )
        if recovery_rule is None:
            a11_findings.append(
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

        allowed_keys = {
            k for k in recovery_rule.get("recoveryKeys", []) if type(k) is str
        }
        threshold = int(recovery_rule.get("threshold", 1))
        succ_msg = b"r5e-succession-recovery-v1\x00" + canonical_json_bytes(
            {
                "newKey": rec.body.get("successor"),
                "oldKey": rec.body.get("predecessor"),
                "recoveryRuleRef": rule_ref,
            }
        )
        valid_recovery_signers: set[str] = set()
        for app in recovery_proof.get("approvals", []):
            if not isinstance(app, dict):
                continue
            sk = app.get("signerKey")
            if type(sk) is not str or sk not in allowed_keys:
                continue
            if _verify_embedded_sig(keys_by_id, sk, succ_msg, app.get("signature")):
                valid_recovery_signers.add(sk)

        if len(valid_recovery_signers) < threshold:
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "failed",
                    "succession_recovery_threshold_not_met",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )
        else:
            a11_findings.append(
                _a11_finding(
                    2,
                    rec.ref,
                    "succession_recovery",
                    "ok",
                    "ok",
                    CATEGORY_CRYPTOGRAPHIC_PROOF,
                )
            )

    # -------------------------------------------------------------------------
    # V8: erasure_l2_proof (Layer 3)
    # -------------------------------------------------------------------------
    sealed_copy_set = set(sealed_service_copies)
    for rec in records:
        if rec.kind_path != ERASURE_ANSWER_KIND:
            continue
        sessions = rec.body.get("sessions")
        if not isinstance(sessions, list):
            continue
        for sess in sessions:
            if not isinstance(sess, dict):
                continue
            if sess.get("governedState") != "destroyed":
                continue
            session_uri = sess.get("session")
            ev_support = sess.get("evidentialSupport")
            if ev_support == "institution_claim":
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "ok",
                        "ok",
                        CATEGORY_INSTITUTIONAL_ASSERTION,
                        session_uri if type(session_uri) is str else None,
                    )
                )
                continue
            if ev_support != "sealed_key_service_proof":
                continue

            confirmed_copies = [
                c for c in sess.get("confirmedCopies", []) if type(c) is str
            ]
            unknown_copies = [c for c in confirmed_copies if c not in sealed_copy_set]
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
            proof_raw = blobs_by_ref.get(proof_ref) if type(proof_ref) is str else None
            proof_ok = False
            if proof_raw is not None:
                try:
                    proof_obj = parse_canonical_json(proof_raw)
                except ValueError:
                    proof_obj = None
                if (
                    isinstance(proof_obj, dict)
                    and proof_obj.get("session") == session_uri
                    and type(proof_obj.get("destroyedAt")) is str
                    and isinstance(proof_obj.get("copyConfirmations"), list)
                ):
                    destroyed_at = proof_obj["destroyedAt"]
                    conf_by_copy: dict[str, dict[str, Any]] = {}
                    for conf in proof_obj["copyConfirmations"]:
                        if isinstance(conf, dict) and type(conf.get("copyId")) is str:
                            conf_by_copy[conf["copyId"]] = conf
                    proof_ok = True
                    for cid in confirmed_copies:
                        conf = conf_by_copy.get(cid)
                        if conf is None:
                            proof_ok = False
                            break
                        c_msg = b"r5e-erasure-proof-v1\x00" + canonical_json_bytes(
                            {
                                "copyId": cid,
                                "destroyedAt": destroyed_at,
                                "session": session_uri,
                            }
                        )
                        if not _verify_embedded_sig(
                            keys_by_id,
                            conf.get("keyId"),
                            c_msg,
                            conf.get("signature"),
                        ):
                            proof_ok = False
                            break

            if not proof_ok:
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "erasure_l2_proof",
                        "failed",
                        "erasure_proof_invalid_or_missing_l2",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        session_uri if type(session_uri) is str else None,
                    )
                )
                continue

            confirmed_set = set(confirmed_copies)
            pending_copies = [c for c in sealed_service_copies if c not in confirmed_set]
            if pending_copies:
                for cid in pending_copies:
                    a11_findings.append(
                        _a11_finding(
                            3,
                            rec.ref,
                            "erasure_l2_proof",
                            "incomplete",
                            "erasure_copy_confirmation_pending",
                            CATEGORY_CRYPTOGRAPHIC_PROOF,
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
                    session_uri if type(session_uri) is str else None,
                )
            )

    # -------------------------------------------------------------------------
    # V10: checkpoint_and_unlock_log (Layer 3)
    # -------------------------------------------------------------------------
    # 10a. Pinned checkpoints
    ckpt_by_seq: dict[int, str] = {}
    for rec in records:
        if rec.kind_path == CHECKPOINT_KIND:
            seq_val = rec.payload.get("seq")
            if type(seq_val) is int:
                ckpt_by_seq[seq_val] = rec.ref

    pinned_ckpts = bundle.get("pinnedCheckpoints")
    if isinstance(pinned_ckpts, list):
        for pin in pinned_ckpts:
            if not isinstance(pin, dict):
                continue
            pin_seq = pin.get("seq")
            pin_ref = pin.get("ref")
            if type(pin_seq) is not int or type(pin_ref) is not str:
                continue
            actual_ref = ckpt_by_seq.get(pin_seq)
            if actual_ref is None:
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
            elif actual_ref != pin_ref:
                a11_findings.append(
                    _a11_finding(
                        3,
                        actual_ref,
                        "checkpoint_and_unlock_log",
                        "failed",
                        "checkpoint_fork_or_stale",
                        CATEGORY_CRYPTOGRAPHIC_PROOF,
                        pin_ref,
                    )
                )

    # Build index of valid releases covering sessions / targets
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
                tset = {
                    t for t in req_rec.body.get("targets", []) if type(t) is str
                }
                released_targets_by_ref[rec.ref] = tset
                all_released_targets.update(tset)
        elif rec.kind_path == DISCLOSURE_KIND:
            tset: set[str] = set()
            sess = rec.payload.get("session")
            if type(sess) is str:
                tset.add(sess)
            for key in ("targets", "contentRefs", "records"):
                val = rec.body.get(key)
                if isinstance(val, list):
                    tset.update(x for x in val if type(x) is str)
            released_targets_by_ref[rec.ref] = tset
            all_released_targets.update(tset)

    # 10b. Level 1 unlock log
    unlock_log = bundle.get("unlockLog")
    if isinstance(unlock_log, list):
        for entry in unlock_log:
            if not isinstance(entry, dict):
                continue
            raw_entry_id = entry.get("entryId")
            entry_id = raw_entry_id if isinstance(raw_entry_id, str) else "unlock"
            session = entry.get("session")
            rel_ref = entry.get("releaseRef")
            covered = (
                type(rel_ref) is str
                and rel_ref in released_targets_by_ref
                and (type(session) is not str or session in released_targets_by_ref[rel_ref])
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

    # 10c. Unrecorded session plaintext in bundle
    for rec in records:
        session = rec.payload.get("session")
        if type(session) is not str:
            continue
        if rec.kind_path in _NON_SESSION_PLAINTEXT_KINDS:
            continue
        cited_bare: set[str] = set()
        _collect_bare_bytes_refs(rec.body, cited_bare)
        for b_ref in sorted(cited_bare):
            if b_ref not in blobs_by_ref:
                continue
            if (
                session not in all_released_targets
                and rec.ref not in all_released_targets
                and b_ref not in all_released_targets
            ):
                a11_findings.append(
                    _a11_finding(
                        3,
                        rec.ref,
                        "checkpoint_and_unlock_log",
                        "failed",
                        "unrecorded_plaintext_in_bundle",
                        CATEGORY_MECHANICAL_CHECK,
                        b_ref,
                    )
                )

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
) -> dict[str, Any]:
    """Verify a Provenance v2 bundle with Amendment A11 rules (V1–V11) and finding classification."""
    baseline = verify_provenance_bundle(
        bundle,
        trusted_profiles=trusted_profiles,
        trusted_publishers=trusted_publishers,
        trusted_roots=trusted_roots,
        trusted_chain=trusted_chain,
        min_start_seq=min_start_seq,
        installed_definitions=installed_definitions,
    )
    baseline_findings: list[dict[str, Any]] = baseline["findings"]
    a11_findings = verify_a11_rules(bundle, baseline_findings=baseline_findings)

    baseline_clean = not any(f["result"] == "failed" for f in baseline_findings)

    all_results = [f["result"] for f in baseline_findings] + [
        f["result"] for f in a11_findings
    ]
    if "failed" in all_results:
        verdict = "failed"
    elif "incomplete" in all_results:
        verdict = "incomplete"
    else:
        verdict = "ok"

    return {
        "amendment": "A11",
        "baselineClean": baseline_clean,
        "a11Findings": a11_findings,
        "findings": baseline_findings,
        "format": PROVENANCE_REPORT_FORMAT,
        "summary": baseline["summary"],
        "verdict": verdict,
    }
