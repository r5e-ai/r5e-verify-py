"""Independent offline Provenance v2 bundle verifier (VERIFY-V2.md §§1–10)."""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

PROVENANCE_EXPORT_FORMAT = "r5e.provenance-export/v2"
PROVENANCE_REPORT_FORMAT = "r5e.provenance-verify-report/v2"
PROVENANCE_EPOCH_FORMAT = "r5e.provenance-epoch/v2"
KIND_DEFINITION_FORMAT = "r5e.kind-definition/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.r5e.provenance-evidence+json;v=2"
DEFINITION_PUBLISHED_KIND = "provenance.r5e.io/v2/DefinitionPublished"
EPOCH_SEAL_KIND = "provenance.r5e.io/v2/EpochSeal"
CHECKPOINT_KIND = "provenance.r5e.io/v2/Checkpoint"
PRINCIPAL_KIND = "provenance.r5e.io/v2/Principal"
SUCCESSION_KIND = "provenance.r5e.io/v2/Succession"
ENDORSEMENT_KIND = "provenance.r5e.io/v2/Endorsement"
BADGE_KIND = "provenance.r5e.io/v2/Badge"
REVOCATION_KIND = "provenance.r5e.io/v2/Revocation"
CHAIN_STARTED_KIND = "provenance.r5e.io/v2/ChainStarted"
DEPLOYMENT_KIND = "provenance.r5e.io/v2/Deployment"
ROOTS_CHANGED_KIND = "provenance.r5e.io/v2/RootsChanged"
ROOT_CHANGE_APPROVAL_KIND = "provenance.r5e.io/v2/RootChangeApproval"
RETENTION_HOLD_KIND = "provenance.r5e.io/v2/RetentionHold"
RETENTION_HOLD_RELEASE_KIND = "provenance.r5e.io/v2/RetentionHoldRelease"
PAYLOAD_DISPOSITION_KIND = "provenance.r5e.io/v2/PayloadDisposition"

START_STREAM_KINDS: frozenset[str] = frozenset({
    CHAIN_STARTED_KIND,
    DEPLOYMENT_KIND,
    ROOTS_CHANGED_KIND,
})
A5_EXEMPT_KINDS: frozenset[str] = frozenset({
    PRINCIPAL_KIND,
    SUCCESSION_KIND,
    DEFINITION_PUBLISHED_KIND,
    CHAIN_STARTED_KIND,
    DEPLOYMENT_KIND,
    ROOTS_CHANGED_KIND,
    ROOT_CHANGE_APPROVAL_KIND,
})
NO_CONTENT_SCOPE_KINDS: frozenset[str] = frozenset({
    EPOCH_SEAL_KIND,
    CHECKPOINT_KIND,
    RETENTION_HOLD_KIND,
    RETENTION_HOLD_RELEASE_KIND,
    PAYLOAD_DISPOSITION_KIND,
})
RETENTION_ACT_KINDS: frozenset[str] = frozenset({
    RETENTION_HOLD_KIND,
    RETENTION_HOLD_RELEASE_KIND,
    PAYLOAD_DISPOSITION_KIND,
})

MAX_SAFE_INT = (1 << 53) - 1

ED25519_P = (1 << 255) - 19
ED25519_D = (-121665 * pow(121666, -1, ED25519_P)) % ED25519_P
ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
ED25519_SMALL_ORDER = {
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
}

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P384_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
)

BYTES_REF_RE = re.compile(r"\Abytes:sha256:[0-9a-f]{64}\Z")
SALTED_BYTES_REF_RE = re.compile(r"\Abytes:sha256\+salt:[0-9a-f]{64}\Z")
EVENT_REF_RE = re.compile(r"\Aevent:sha256:[0-9a-f]{64}\Z")
EVIDENCE_REF_RE = re.compile(r"\Aevidence:sha256:[0-9a-f]{64}\Z")
SHA256_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

BASIS_KIND = "provenance.r5e.io/v2/Basis"
BASIS_OVERLAY_KIND = "provenance.r5e.io/v2/BasisOverlay"
RELEASE_REQUEST_KIND = "provenance.r5e.io/v2/ReleaseRequest"
RELEASE_RECEIPT_KIND = "provenance.r5e.io/v2/ReleaseReceipt"
ERASURE_ANSWER_KIND = "provenance.r5e.io/v2/ErasureAnswer"

A11_BUNDLE_FIELD_TYPES: dict[str, type] = {
    "saltedContent": dict,
    "witnessReceipts": dict,
    "unlockLog": list,
    "pinnedCheckpoints": list,
}
CANDIDATE_START_STREAM_RE = re.compile(r"\Aurn:r5e:stream:[^:]+:start\Z")
VALID_START_STREAM_RE = re.compile(r"\Aurn:r5e:stream:[a-z0-9][a-z0-9-]*:start\Z")
DEPLOYMENT_STREAM_RE = re.compile(r"\Aurn:r5e:stream:([a-z0-9][a-z0-9-]*):.+\Z")
RETENTION_STREAM_RE = re.compile(r"\Aurn:r5e:stream:[a-z0-9][a-z0-9-]*:retention\Z")
RFC3339_RE = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)

_DATA_DIR = Path(__file__).resolve().parent / "provenance_data"
_NEG_ZERO = object()


class ProvenanceInputError(ValueError):
    """Raised when CLI/file inputs cannot be read or parsed as JSON."""


def json_eq(a: Any, b: Any) -> bool:
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(json_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(json_eq(x, y) for x, y in zip(a, b, strict=True))
    return a == b


# ---------------------------------------------------------------------------
# §2.1 Canonical JSON
# ---------------------------------------------------------------------------

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _reject_constant(token: str) -> Any:
    raise ValueError(f"invalid JSON constant: {token}")


def _reject_float(token: str) -> Any:
    raise ValueError(f"floating-point or exponent number not permitted: {token}")


def _check_utf8_no_surrogates(v: Any) -> None:
    if isinstance(v, str):
        v.encode("utf-8")
    elif isinstance(v, list):
        for item in v:
            _check_utf8_no_surrogates(item)
    elif isinstance(v, dict):
        for k, val in v.items():
            k.encode("utf-8")
            _check_utf8_no_surrogates(val)


def load_strict_json(data: bytes | str) -> Any:
    """Parse JSON enforcing §2.1 value limits, no -0/floats/exponents, no duplicate keys, BMP keys."""
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    if not isinstance(text, str):
        raise TypeError("JSON input must be bytes or str")

    def parse_int(s: str) -> int:
        if s.startswith("-0"):
            raise ValueError("negative zero is not permitted")
        n = int(s)
        if n < -MAX_SAFE_INT or n > MAX_SAFE_INT:
            raise ValueError("integer outside safe range")
        return n

    def parse_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            k.encode("utf-8")
            if any(ord(c) > 0xFFFF for c in k):
                raise ValueError("object key contains code point above U+FFFF")
            if k in out:
                raise ValueError(f"duplicate object key: {k}")
            out[k] = v
        return out

    try:
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=parse_int,
            object_pairs_hook=parse_pairs,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting too deep") from exc
    _check_utf8_no_surrogates(value)
    return value


def load_bundle_json(data: bytes | str) -> Any:
    """Parse outer bundle JSON (allowing pretty-printing; flagging -0/floats for schema rejection)."""
    try:
        text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    except UnicodeDecodeError as exc:
        raise ProvenanceInputError("bundle is not valid UTF-8") from exc
    if not isinstance(text, str):
        raise ProvenanceInputError("bundle input must be bytes or str")

    def parse_int(s: str) -> Any:
        if s.startswith("-0"):
            return _NEG_ZERO
        return int(s)

    def parse_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            k.encode("utf-8")
            if k in out:
                raise ValueError(f"duplicate object key: {k}")
            out[k] = v
        return out

    try:
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            parse_float=float,
            parse_int=parse_int,
            object_pairs_hook=parse_pairs,
        )
        _check_utf8_no_surrogates(value)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProvenanceInputError(f"cannot parse JSON input: {exc}") from exc
    return value


def _encode_jcs_string(s: str) -> bytes:
    parts: list[str] = ['"']
    for ch in s:
        code = ord(ch)
        esc = _SHORT_ESCAPES.get(code)
        if esc is not None:
            parts.append(esc)
        elif code < 0x20:
            parts.append(f"\\u{code:04x}")
        else:
            parts.append(ch)
    parts.append('"')
    try:
        return "".join(parts).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("unpaired surrogate in string") from exc


def canonical_json_bytes(v: Any) -> bytes:
    """Encode a value to §2.1 Canonical JSON (restricted RFC 8785 JCS)."""
    if v is None:
        return b"null"
    if v is True:
        return b"true"
    if v is False:
        return b"false"
    if type(v) is int:
        if v < -MAX_SAFE_INT or v > MAX_SAFE_INT:
            raise ValueError("integer outside safe range")
        return str(v).encode("ascii")
    if type(v) is str:
        return _encode_jcs_string(v)
    if isinstance(v, list):
        return b"[" + b",".join(canonical_json_bytes(x) for x in v) + b"]"
    if isinstance(v, dict):
        items: list[tuple[bytes, bytes, Any]] = []
        for k, val in v.items():
            if type(k) is not str:
                raise ValueError("object key must be string")
            if any(ord(c) > 0xFFFF for c in k):
                raise ValueError("object key contains code point above U+FFFF")
            kb = _encode_jcs_string(k)
            items.append((k.encode("utf-8"), kb, val))
        items.sort(key=lambda entry: entry[0])
        return b"{" + b",".join(kb + b":" + canonical_json_bytes(val) for _, kb, val in items) + b"}"
    raise ValueError(f"unsupported value for canonical JSON: {type(v).__name__}")


def parse_canonical_json(raw: bytes) -> Any:
    """Verify raw bytes are exact §2.1 canonical JSON and return parsed value."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("canonical JSON input must be bytes")
    raw_bytes = bytes(raw)
    parsed = load_strict_json(raw_bytes)
    if canonical_json_bytes(parsed) != raw_bytes:
        raise ValueError("bytes are not canonical JSON")
    return parsed


# ---------------------------------------------------------------------------
# §2.2–§2.6 References, Key IDs, Signatures, PAE, Base64, Merkle, Timestamps
# ---------------------------------------------------------------------------

def bytes_ref(raw: bytes) -> str:
    return "bytes:sha256:" + hashlib.sha256(raw).hexdigest()


def evidence_ref(canonical_payload: bytes) -> str:
    return "evidence:sha256:" + hashlib.sha256(canonical_payload).hexdigest()


def _uvarint(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative uvarint")
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def is_admissible_public_key(alg: str, pub: bytes) -> bool:
    """Check §2.3 public key admissibility before consulting external verification."""
    if not isinstance(alg, str) or not isinstance(pub, (bytes, bytearray)):
        return False
    pub_bytes = bytes(pub)
    if alg == "ed25519":
        if len(pub_bytes) != 32:
            return False
        masked = pub_bytes[:31] + bytes([pub_bytes[31] & 0x7F])
        y = int.from_bytes(masked, "little")
        if y >= ED25519_P or masked in ED25519_SMALL_ORDER:
            return False
        y2 = (y * y) % ED25519_P
        u = (y2 - 1) % ED25519_P
        v = (ED25519_D * y2 + 1) % ED25519_P
        x2 = (u * pow(v, -1, ED25519_P)) % ED25519_P
        return x2 == 0 or pow(x2, (ED25519_P - 1) // 2, ED25519_P) == 1
    if alg == "es256":
        if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
            return False
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
            return True
        except ValueError:
            return False
    if alg == "es384":
        if len(pub_bytes) != 97 or pub_bytes[0] != 0x04:
            return False
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pub_bytes)
            return True
        except ValueError:
            return False
    return False


def compute_key_id(alg: str, pub: bytes) -> str | None:
    if not is_admissible_public_key(alg, pub):
        return None
    alg_bytes = alg.encode("ascii")
    digest_hex = hashlib.sha256(_uvarint(len(alg_bytes)) + alg_bytes + bytes(pub)).hexdigest()
    return f"key:{alg}:sha256:{digest_hex}"


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt)).encode("ascii")
        + b" "
        + pt
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def verify_signature(alg: str, pub: bytes, sig: bytes, message: bytes) -> bool:
    if not is_admissible_public_key(alg, pub):
        return False
    pub_bytes = bytes(pub)
    sig_bytes = bytes(sig)
    if alg == "ed25519":
        if len(sig_bytes) != 64:
            return False
        if int.from_bytes(sig_bytes[32:], "little") >= ED25519_L:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, message)
            return True
        except (ValueError, InvalidSignature):
            return False
    if alg == "es256":
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        if not (1 <= r < P256_N and 1 <= s <= P256_N // 2):
            return False
        der = encode_dss_signature(r, s)
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes).verify(
                der, message, ec.ECDSA(hashes.SHA256())
            )
            return True
        except (ValueError, InvalidSignature):
            return False
    if alg == "es384":
        if len(sig_bytes) != 96:
            return False
        r = int.from_bytes(sig_bytes[:48], "big")
        s = int.from_bytes(sig_bytes[48:], "big")
        if not (1 <= r < P384_N and 1 <= s <= P384_N // 2):
            return False
        der = encode_dss_signature(r, s)
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), pub_bytes).verify(
                der, message, ec.ECDSA(hashes.SHA384())
            )
            return True
        except (ValueError, InvalidSignature):
            return False
    return False


def decode_base64(s: Any) -> bytes:
    """Decode standard padded base64 with zero unused pad bits (§2.5)."""
    if not isinstance(s, str) or len(s) % 4 != 0:
        raise ValueError("invalid base64")
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception as exc:
        raise ValueError("invalid base64") from exc
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("invalid base64")
    return raw


def decode_strict_base64(s: Any) -> bytes:
    """Decode strict base64 (§2.5): canonical standard padded base64 of >= 1 byte."""
    raw = decode_base64(s)
    if not raw:
        raise ValueError("empty strict base64")
    return raw


def _merkle_tree_hash(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1 << ((n - 1).bit_length() - 1)
    return hashlib.sha256(
        b"\x01" + _merkle_tree_hash(leaves[:k]) + _merkle_tree_hash(leaves[k:])
    ).digest()


def merkle_root_for_events(event_refs: list[str]) -> str:
    if not event_refs:
        raise ValueError("epoch manifest events cannot be empty")
    leaves: list[bytes] = []
    for ref in event_refs:
        if not isinstance(ref, str) or not EVIDENCE_REF_RE.match(ref):
            raise ValueError(f"invalid evidence reference: {ref}")
        leaves.append(bytes.fromhex(ref[len("evidence:sha256:") :]))
    return "sha256:" + _merkle_tree_hash(leaves).hex()


def verify_merkle_inclusion(
    record_ref: str,
    index: int,
    tree_size: int,
    siblings: list[str],
    expected_root: Any,
) -> bool:
    """Verify an RFC 9162 §2.1.3.2 inclusion proof, requiring every sibling to be used."""
    if (
        type(index) is not int
        or type(tree_size) is not int
        or tree_size < 1
        or index < 0
        or index >= tree_size
        or not isinstance(record_ref, str)
        or not EVIDENCE_REF_RE.match(record_ref)
        or not isinstance(expected_root, str)
        or not SHA256_DIGEST_RE.match(expected_root)
        or not isinstance(siblings, list)
    ):
        return False

    sib_digests: list[bytes] = []
    for s in siblings:
        if not isinstance(s, str) or not SHA256_DIGEST_RE.match(s):
            return False
        sib_digests.append(bytes.fromhex(s[len("sha256:") :]))

    leaf = bytes.fromhex(record_ref[len("evidence:sha256:") :])
    fn = index
    sn = tree_size - 1
    r = hashlib.sha256(b"\x00" + leaf).digest()
    for p in sib_digests:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            while (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return False
    return ("sha256:" + r.hex()) == expected_root


def parse_rfc3339_instant(value: Any) -> tuple[int, str] | None:
    """Parse RFC 3339 date-time (uppercase T and Z) to (utc_seconds, normalized_frac) or None."""
    if not isinstance(value, str):
        return None
    m = RFC3339_RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    try:
        if y == 0:
            ordinal = datetime.date(400, mo, d).toordinal() - 146097
        else:
            ordinal = datetime.date(y, mo, d).toordinal()
    except ValueError:
        return None
    if h > 23 or mi > 59 or s > 59:
        return None
    tz = m.group(8)
    offset_seconds = 0
    if tz != "Z":
        oh = int(tz[1:3])
        om = int(tz[4:6])
        if oh > 23 or om > 59:
            return None
        sign = 1 if tz[0] == "+" else -1
        offset_seconds = sign * (oh * 3600 + om * 60)
    utc_seconds = ((ordinal * 24 + h) * 3600 + mi * 60 + s) - offset_seconds
    frac = (m.group(7) or "").rstrip("0")
    return (utc_seconds, frac)


def parse_rfc3339_instant_ns(value: Any) -> int | None:
    """Parse RFC 3339 date-time to exact arbitrary-precision UTC nanoseconds, or None."""
    parsed = parse_rfc3339_instant(value)
    if parsed is None:
        return None
    utc_seconds, frac = parsed
    ns_part = int(frac.ljust(9, "0")[:9]) if frac else 0
    return utc_seconds * 1_000_000_000 + ns_part


def translate_regex_anchors(pattern: str) -> str:
    """Rewrite unescaped ^ and $ outside character classes to \\A and \\Z."""
    out: list[str] = []
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if not in_class:
            if ch == "[":
                in_class = True
                out.append("[")
                i += 1
                if i < n and pattern[i] == "^":
                    out.append("^")
                    i += 1
                if i < n and pattern[i] == "]":
                    out.append("]")
                    i += 1
            elif ch == "^":
                out.append(r"\A")
                i += 1
            elif ch == "$":
                out.append(r"\Z")
                i += 1
            else:
                out.append(ch)
                i += 1
        else:
            if ch == "]":
                in_class = False
            out.append(ch)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# §2.7 Fixed Wire JSON Schema 2020-12 Subset Validator
# ---------------------------------------------------------------------------

def _resolve_json_pointer(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported non-local $ref: {ref}")
    cur: Any = root
    for raw_token in ref[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or token not in cur:
            raise ValueError(f"unresolved $ref: {ref}")
        cur = cur[token]
    if not isinstance(cur, dict):
        raise TypeError(f"$ref target is not a schema object: {ref}")
    return cur


def _matches_wire_type(v: Any, t: str) -> bool:
    if t == "null":
        return v is None
    if t == "boolean":
        return type(v) is bool
    if t == "integer":
        return type(v) is int and -MAX_SAFE_INT <= v <= MAX_SAFE_INT
    if t == "string":
        return type(v) is str
    if t == "array":
        return isinstance(v, list)
    if t == "object":
        return isinstance(v, dict)
    return False


def validate_wire_schema(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any] | None = None,
) -> bool:
    """Validate `value` against one of the §2.7 JSON Schema 2020-12 wire schemas."""
    if root is None:
        root = schema
    if value is _NEG_ZERO:
        return False

    if "$ref" in schema:
        target = _resolve_json_pointer(root, schema["$ref"])
        if not validate_wire_schema(value, target, root):
            return False

    if "type" in schema:
        decl = schema["type"]
        types = [decl] if isinstance(decl, str) else decl
        if not any(_matches_wire_type(value, t) for t in types):
            return False

    if "const" in schema and not json_eq(value, schema["const"]):
        return False

    if "enum" in schema and not any(json_eq(value, item) for item in schema["enum"]):
        return False

    if type(value) is str:
        if "minLength" in schema and len(value) < schema["minLength"]:
            return False
        if "pattern" in schema:
            compiled = re.compile(translate_regex_anchors(schema["pattern"]))
            if compiled.search(value) is None:
                return False
        if schema.get("format") == "date-time" and parse_rfc3339_instant(value) is None:
            return False

    if type(value) is int and "minimum" in schema and value < schema["minimum"]:
        return False

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        if schema.get("uniqueItems") is True:
            for idx, item in enumerate(value):
                if any(json_eq(item, prev) for prev in value[:idx]):
                    return False
        if "items" in schema:
            item_schema = schema["items"]
            if not all(validate_wire_schema(item, item_schema, root) for item in value):
                return False

    if isinstance(value, dict):
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            return False
        if "required" in schema and not all(req in value for req in schema["required"]):
            return False
        if "propertyNames" in schema:
            prop_name_schema = schema["propertyNames"]
            if not all(validate_wire_schema(k, prop_name_schema, root) for k in value):
                return False
        props = schema.get("properties", {})
        for k, subschema in props.items():
            if k in value and not validate_wire_schema(value[k], subschema, root):
                return False
        if "additionalProperties" in schema:
            ap = schema["additionalProperties"]
            for k, val in value.items():
                if k not in props:
                    if ap is False:
                        return False
                    if isinstance(ap, dict) and not validate_wire_schema(val, ap, root):
                        return False

    if "allOf" in schema and not all(
        validate_wire_schema(value, s, root) for s in schema["allOf"]
    ):
        return False

    if "anyOf" in schema and not any(
        validate_wire_schema(value, s, root) for s in schema["anyOf"]
    ):
        return False

    if "oneOf" in schema:
        matches = sum(1 for s in schema["oneOf"] if validate_wire_schema(value, s, root))
        if matches != 1:
            return False

    if "if" in schema:
        if validate_wire_schema(value, schema["if"], root):
            if "then" in schema and not validate_wire_schema(value, schema["then"], root):
                return False
        elif "else" in schema and not validate_wire_schema(value, schema["else"], root):
            return False

    return True


# ---------------------------------------------------------------------------
# §2.8 Definition Document & Body Schema Validator
# ---------------------------------------------------------------------------

_DEF_NODE_KEYS = {
    "type",
    "enum",
    "pattern",
    "minimum",
    "maximum",
    "items",
    "unique",
    "properties",
    "additionalProperties",
    "values",
    "keys",
    "maxEntries",
    "maxLength",
    "required",
    "nonEmpty",
    "ordered",
    "exactlyOne",
    "atMostOne",
    "requires",
    "matchesSigner",
    "keyBytes",
    "derives",
    "ref",
    "description",
}
_DEF_TYPES = {"string", "integer", "boolean", "object", "array", "ref"}


@dataclass(frozen=True)
class ParsedDefinition:
    kind: str
    signatures: int
    schema: dict[str, Any]


def _node_types(node: dict[str, Any]) -> list[str] | None:
    if "type" not in node:
        return ["object"]
    decl = node["type"]
    if type(decl) is str:
        return [decl] if decl in _DEF_TYPES else None
    if isinstance(decl, list) and decl and all(type(x) is str and x in _DEF_TYPES for x in decl):
        return decl
    return None


def _is_valid_ref_spec(spec: Any) -> bool:
    if not isinstance(spec, dict):
        return False
    if "crossChain" in spec and spec["crossChain"] is not True:
        return False
    base_keys = set(spec.keys()) - {"crossChain"}
    if len(base_keys) != 1:
        return False
    if "bytes" in base_keys:
        return spec["bytes"] is True
    if "evidence" in base_keys:
        return spec["evidence"] is True
    if "event" in base_keys:
        return spec["event"] is not False and spec["event"] is not None
    if "anyOf" in base_keys:
        alts = spec["anyOf"]
        return isinstance(alts, list) and len(alts) > 0 and all(_is_valid_ref_spec(a) for a in alts)
    return False


def _is_valid_key_bytes_node(node: Any) -> bool:
    if not isinstance(node, dict) or node.get("keyBytes") is not True:
        return False
    if _node_types(node) != ["object"]:
        return False
    props = node.get("properties")
    req = node.get("required")
    if not isinstance(props, dict) or not isinstance(req, list):
        return False
    return (
        "algorithm" in props
        and "bytes" in props
        and "algorithm" in req
        and "bytes" in req
    )


def _validate_def_schema_node(
    node: Any,
    doc_signatures: int,
    parent_object_node: dict[str, Any] | None = None,
) -> bool:
    if not isinstance(node, dict):
        return False
    if not set(node.keys()).issubset(_DEF_NODE_KEYS):
        return False

    types = _node_types(node)
    if types is None:
        return False

    if "enum" in node and not isinstance(node["enum"], list):
        return False

    if "pattern" in node:
        pat = node["pattern"]
        if type(pat) is not str:
            return False
        try:
            re.compile(translate_regex_anchors(pat).encode("utf-8"))
        except re.error:
            return False

    if "minimum" in node and type(node["minimum"]) is not int:
        return False
    if "maximum" in node and type(node["maximum"]) is not int:
        return False

    if "unique" in node and (types != ["array"] or node["unique"] is not True):
        return False

    if "keys" in node:
        kpat = node["keys"]
        if types != ["object"] or type(kpat) is not str:
            return False
        try:
            re.compile(translate_regex_anchors(kpat).encode("utf-8"))
        except re.error:
            return False

    if "maxEntries" in node:
        me = node["maxEntries"]
        if types != ["object"] or type(me) is not int or me < 1 or me > MAX_SAFE_INT:
            return False

    if "maxLength" in node:
        ml = node["maxLength"]
        if "string" not in types or type(ml) is not int or ml < 1 or ml > MAX_SAFE_INT:
            return False

    if "additionalProperties" in node and type(node["additionalProperties"]) is not bool:
        return False

    if "required" in node:
        req = node["required"]
        if not isinstance(req, list) or not all(type(x) is str for x in req):
            return False

    if "nonEmpty" in node:
        ne = node["nonEmpty"]
        if not isinstance(ne, list) or not all(type(x) is str for x in ne):
            return False

    if "ordered" in node:
        ord_pairs = node["ordered"]
        if not isinstance(ord_pairs, list) or not all(
            isinstance(pair, list) and len(pair) == 2 and type(pair[0]) is str and type(pair[1]) is str
            for pair in ord_pairs
        ):
            return False

    for group_key in ("exactlyOne", "atMostOne"):
        if group_key in node:
            groups = node[group_key]
            if not isinstance(groups, list) or not all(
                isinstance(g, list) and all(type(x) is str for x in g) for g in groups
            ):
                return False

    if "requires" in node:
        reqs = node["requires"]
        if not isinstance(reqs, list):
            return False
        for rule in reqs:
            if not isinstance(rule, dict) or set(rule.keys()) != {"when", "then"}:
                return False
            when = rule["when"]
            then = rule["then"]
            if (
                not isinstance(when, dict)
                or set(when.keys()) != {"field", "equals"}
                or type(when["field"]) is not str
                or not isinstance(then, list)
                or not all(type(x) is str for x in then)
            ):
                return False

    if "matchesSigner" in node:
        ms = node["matchesSigner"]
        if types != ["string"] or type(ms) is not int or ms < 1 or ms > 16 or ms > doc_signatures:
            return False

    if "keyBytes" in node and not _is_valid_key_bytes_node(node):
        return False

    if "derives" in node:
        der = node["derives"]
        if (
            types != ["string"]
            or not isinstance(der, dict)
            or set(der.keys()) != {"keyIdOf"}
            or type(der["keyIdOf"]) is not str
            or parent_object_node is None
        ):
            return False
        sibling_name = der["keyIdOf"]
        parent_props = parent_object_node.get("properties")
        parent_req = parent_object_node.get("required")
        if (
            not isinstance(parent_props, dict)
            or not isinstance(parent_req, list)
            or sibling_name not in parent_props
            or sibling_name not in parent_req
            or not _is_valid_key_bytes_node(parent_props[sibling_name])
        ):
            return False

    if "ref" in node and ("ref" not in types or not _is_valid_ref_spec(node["ref"])):
        return False

    if "items" in node and not _validate_def_schema_node(node["items"], doc_signatures, None):
        return False

    if "properties" in node:
        props = node["properties"]
        if not isinstance(props, dict) or not all(type(k) is str for k in props):
            return False
        for prop_node in props.values():
            if not _validate_def_schema_node(prop_node, doc_signatures, node):
                return False

    return not (
        "values" in node and not _validate_def_schema_node(node["values"], doc_signatures, None)
    )


def parse_definition_document(raw_bytes: bytes) -> ParsedDefinition | None:
    """Parse and validate a §2.8 definition document; return None if unavailable/faulty."""
    try:
        doc = parse_canonical_json(raw_bytes)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    if doc.get("format") != KIND_DEFINITION_FORMAT:
        return None
    kind = doc.get("kind")
    if type(kind) is not str:
        return None
    schema = doc.get("schema")
    if not isinstance(schema, dict):
        return None

    if "signatures" in doc:
        sigs = doc["signatures"]
        if type(sigs) is not int or sigs < 1 or sigs > 16:
            return None
    else:
        sigs = 1

    if not _validate_def_schema_node(schema, sigs, None):
        return None

    if sigs >= 2:
        if _node_types(schema) != ["object"]:
            return None
        top_props = schema.get("properties")
        top_req = schema.get("required")
        if not isinstance(top_props, dict) or not isinstance(top_req, list):
            return None
        req_set = set(top_req)
        for pos in range(2, sigs + 1):
            bound = any(
                prop_name in req_set
                and isinstance(prop_node, dict)
                and _node_types(prop_node) == ["string"]
                and prop_node.get("matchesSigner") == pos
                for prop_name, prop_node in top_props.items()
            )
            if not bound:
                return None

    return ParsedDefinition(kind=kind, signatures=sigs, schema=schema)


def _match_ref_spec(value: str, spec: dict[str, Any], *, allow_cross_chain: bool = True) -> bool:
    if value.startswith("chain:"):
        if not allow_cross_chain:
            return False
        if spec.get("crossChain") is True:
            rest = value[len("chain:") :]
            if "/" not in rest:
                return False
            chain_name, inner_ref = rest.split("/", 1)
            if EVIDENCE_REF_RE.match(chain_name) is None:
                return False
            return _match_ref_spec(inner_ref, spec, allow_cross_chain=False)
        if "anyOf" in spec:
            return any(
                _match_ref_spec(value, alt, allow_cross_chain=True) for alt in spec["anyOf"]
            )
        return False
    if "bytes" in spec:
        return BYTES_REF_RE.match(value) is not None
    if "evidence" in spec:
        return EVIDENCE_REF_RE.match(value) is not None
    if "event" in spec:
        return EVENT_REF_RE.match(value) is not None
    if "anyOf" in spec:
        return any(
            _match_ref_spec(value, alt, allow_cross_chain=allow_cross_chain)
            for alt in spec["anyOf"]
        )
    return False


def _matches_def_type(value: Any, t: str) -> bool:
    if t in ("string", "ref"):
        return type(value) is str
    if t == "integer":
        return type(value) is int and -MAX_SAFE_INT <= value <= MAX_SAFE_INT
    if t == "boolean":
        return type(value) is bool
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    return False


def validate_body_against_schema(
    value: Any,
    node: dict[str, Any],
    signers: list[str],
    parent_obj: dict[str, Any] | None = None,
) -> bool:
    """Validate `value` against a pre-validated §2.8/§2.9 schema node."""
    types = _node_types(node)
    if types is None or not any(_matches_def_type(value, t) for t in types):
        return False

    if "enum" in node and not any(json_eq(value, item) for item in node["enum"]):
        return False

    if type(value) is str:
        if "maxLength" in node and len(value.encode("utf-8")) > node["maxLength"]:
            return False
        if "pattern" in node:
            pat = node["pattern"]
            regex = re.compile(translate_regex_anchors(pat).encode("utf-8"))
            if regex.search(value.encode("utf-8")) is None:
                return False
            if pat == TIMESTAMP_PATTERN and parse_rfc3339_instant(value) is None:
                return False
        if "matchesSigner" in node:
            pos = node["matchesSigner"]
            if pos < 1 or pos > len(signers) or value != signers[pos - 1]:
                return False
        if "derives" in node:
            if parent_obj is None:
                return False
            sibling = parent_obj.get(node["derives"]["keyIdOf"])
            if not isinstance(sibling, dict):
                return False
            alg = sibling.get("algorithm")
            b64_key = sibling.get("bytes")
            if type(alg) is not str or type(b64_key) is not str:
                return False
            try:
                raw_key = decode_strict_base64(b64_key)
            except ValueError:
                return False
            derived_kid = compute_key_id(alg, raw_key)
            if derived_kid is None or value != derived_kid:
                return False
        if "ref" in node and not _match_ref_spec(value, node["ref"]):
            return False

    if type(value) is int:
        if "minimum" in node and value < node["minimum"]:
            return False
        if "maximum" in node and value > node["maximum"]:
            return False

    if isinstance(value, list):
        if node.get("unique") is True:
            for idx, item in enumerate(value):
                if any(json_eq(item, prev) for prev in value[:idx]):
                    return False
        if "items" in node and not all(
            validate_body_against_schema(item, node["items"], signers, None) for item in value
        ):
            return False

    if isinstance(value, dict):
        if "maxEntries" in node and len(value) > node["maxEntries"]:
            return False
        if "keys" in node:
            key_regex = re.compile(translate_regex_anchors(node["keys"]).encode("utf-8"))
            if not all(key_regex.search(k.encode("utf-8")) is not None for k in value):
                return False
        props = node.get("properties", {})
        if "required" in node and not all(req in value for req in node["required"]):
            return False
        if node.get("additionalProperties") is False and not all(k in props for k in value):
            return False
        for k, subnode in props.items():
            if k in value and not validate_body_against_schema(value[k], subnode, signers, value):
                return False
        if "values" in node:
            val_node = node["values"]
            for k, val in value.items():
                if k not in props and not validate_body_against_schema(val, val_node, signers, None):
                    return False
        if "nonEmpty" in node:
            for name in node["nonEmpty"]:
                if name in value and (value[name] == "" or value[name] == [] or value[name] == {}):
                    return False
        if "ordered" in node:
            for first_name, second_name in node["ordered"]:
                if first_name in value and second_name in value:
                    a, b = value[first_name], value[second_name]
                    if type(a) is int and type(b) is int:
                        if a > b:
                            return False
                    elif type(a) is str and type(b) is str:
                        ia = parse_rfc3339_instant(a)
                        ib = parse_rfc3339_instant(b)
                        if ia is None or ib is None or ia > ib:
                            return False
                    else:
                        return False
        if "exactlyOne" in node:
            for group in node["exactlyOne"]:
                if sum(1 for name in group if name in value) != 1:
                    return False
        if "atMostOne" in node:
            for group in node["atMostOne"]:
                if sum(1 for name in group if name in value) > 1:
                    return False
        if "requires" in node:
            for rule in node["requires"]:
                field = rule["when"]["field"]
                eq_val = rule["when"]["equals"]
                if (
                    field in value
                    and json_eq(value[field], eq_val)
                    and not all(req_name in value for req_name in rule["then"])
                ):
                    return False
        if node.get("keyBytes") is True:
            alg = value.get("algorithm")
            b64_key = value.get("bytes")
            if type(alg) is not str or type(b64_key) is not str:
                return False
            try:
                raw_key = decode_strict_base64(b64_key)
            except ValueError:
                return False
            if not is_admissible_public_key(alg, raw_key):
                return False

    return True


# ---------------------------------------------------------------------------
# Bundled Wire Schemas & Base Definitions Loader
# ---------------------------------------------------------------------------

_cached_schemas: dict[str, dict[str, Any]] | None = None
_cached_base_defs: tuple[dict[str, bytes], set[str]] | None = None


def _load_bundled_schemas() -> dict[str, dict[str, Any]]:
    global _cached_schemas
    if _cached_schemas is None:
        schemas_dir = _DATA_DIR / "schemas"
        loaded: dict[str, dict[str, Any]] = {}
        for name in (
            "export.schema.json",
            "signed-evidence.schema.json",
            "evidence-envelope.schema.json",
            "capture-profile.schema.json",
            "epoch-manifest.schema.json",
        ):
            loaded[name] = json.loads((schemas_dir / name).read_bytes().decode("utf-8"))
        _cached_schemas = loaded
    return _cached_schemas


def _load_base_definitions() -> tuple[dict[str, bytes], set[str]]:
    global _cached_base_defs
    if _cached_base_defs is None:
        defs_dir = _DATA_DIR / "definitions"
        index = json.loads((defs_dir / "index.json").read_bytes().decode("utf-8"))
        by_ref: dict[str, bytes] = {}
        index_refs: set[str] = set()
        for kind_path, ref in index.items():
            index_refs.add(ref)
            doc_path = defs_dir / f"{kind_path}.json"
            raw = doc_path.read_bytes()
            if bytes_ref(raw) == ref:
                by_ref[ref] = raw
        _cached_base_defs = (by_ref, index_refs)
    return _cached_base_defs


def load_definitions_dir(directory: str | Path) -> dict[str, bytes]:
    """Load reader-installed definitions from a directory, keyed by bytes:sha256:<hex>."""
    root = Path(directory)
    if not root.is_dir():
        raise ProvenanceInputError(f"no definitions directory at {directory}")
    out: dict[str, bytes] = {}
    try:
        for path in sorted(root.rglob("*.json")):
            if path.is_file():
                raw = path.read_bytes()
                out[bytes_ref(raw)] = raw
    except OSError as exc:
        raise ProvenanceInputError(f"cannot read definitions directory {directory}: {exc}") from exc
    return out


# ---------------------------------------------------------------------------
# §§3–9 Bundle Verification & Report Generation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OpenedRecord:
    ref: str
    payload: dict[str, Any]
    signers: list[str]
    all_signatures_ok: bool
    any_signature_failed: bool = False

    @property
    def kind_path(self) -> str | None:
        api_version = self.payload.get("apiVersion")
        kind = self.payload.get("kind")
        if type(api_version) is str and type(kind) is str:
            return f"{api_version}/{kind}"
        return None


def _finding(
    layer: int,
    subject: str,
    check: str,
    result: str,
    code: str,
    about: str | None = None,
) -> dict[str, Any]:
    return {
        "layer": layer,
        "subject": subject,
        "check": check,
        "result": result,
        "code": code,
        "about": about,
    }


def _build_report(
    findings: list[dict[str, Any]],
    start_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            f["layer"],
            f["subject"].encode("utf-8"),
            f["check"].encode("utf-8"),
            f["code"].encode("utf-8"),
            (f["about"] or "").encode("utf-8"),
        ),
    )
    summary = {"ok": 0, "failed": 0, "incomplete": 0}
    for f in sorted_findings:
        summary[f["result"]] += 1
    report: dict[str, Any] = {
        "format": PROVENANCE_REPORT_FORMAT,
        "summary": summary,
        "findings": sorted_findings,
    }
    if start_info is not None:
        report["start"] = start_info
    return report


def _parse_trusted_publishers(
    entries: Sequence[str],
) -> dict[str, set[str] | None]:
    """Parse trusted publisher entries (`<key_id>` or `<key_id>=<domain>[,<domain>...]`, A9 §4).

    Maps each `key_id` to `None` (believed about all domains) or a `set[str]` of domains.
    Repeated `key_id` entries union their domains (`None` union anything stays `None`).
    """
    out: dict[str, set[str] | None] = {}
    for entry in entries:
        if type(entry) is not str or not entry:
            raise ProvenanceInputError(f"invalid trusted_publisher entry: {entry!r}")
        key_id, sep, domains_raw = entry.partition("=")
        if not key_id:
            raise ProvenanceInputError(f"invalid trusted_publisher entry: {entry!r}")
        if not sep:
            out[key_id] = None
        else:
            parts = domains_raw.split(",")
            if not parts or any(not d for d in parts):
                raise ProvenanceInputError(f"invalid trusted_publisher domains in {entry!r}")
            if key_id in out and out[key_id] is None:
                continue
            existing = out.get(key_id)
            if existing is None:
                out[key_id] = set(parts)
            else:
                existing.update(parts)
    return out


def _publisher_believed_for_kind(
    publisher_domains: dict[str, set[str] | None],
    pub_key_id: Any,
    kind_path: str | None,
) -> bool:
    """Return True iff `pub_key_id` is believed about `kind_path` under A9 §4 / VERIFY-V2 §6.2a."""
    if type(pub_key_id) is not str or pub_key_id not in publisher_domains or type(kind_path) is not str:
        return False
    domains = publisher_domains[pub_key_id]
    if domains is None:
        return True
    if "/" not in kind_path:
        return False
    group = kind_path.split("/", 1)[0]
    return any(group == d or group.endswith("." + d) for d in domains)


def _is_publication_from_stranger(
    payload: dict[str, Any],
    publisher_domains: dict[str, set[str] | None],
) -> bool:
    """Return True unless `issuer` is trusted and believed about every string kind listed (§6.2a / A9 §4)."""
    issuer = payload.get("issuer")
    if type(issuer) is not str or issuer not in publisher_domains:
        return True
    body = payload.get("body")
    defs = body.get("definitions") if isinstance(body, dict) else None
    if isinstance(defs, list):
        for item in defs:
            if (
                isinstance(item, dict)
                and type(item.get("kind")) is str
                and not _publisher_believed_for_kind(publisher_domains, issuer, item["kind"])
            ):
                return True
    return False


def _validate_reader_options(
    trusted_roots: Sequence[str] | None,
    trusted_chain: str | None,
    min_start_seq: int | None,
    trusted_publishers: Sequence[str] = (),
) -> None:
    if trusted_roots is not None and trusted_chain is not None:
        raise ProvenanceInputError("trusted_roots and trusted_chain are mutually exclusive")
    if trusted_chain is not None and (
        type(trusted_chain) is not str or not EVIDENCE_REF_RE.match(trusted_chain)
    ):
        raise ProvenanceInputError(f"invalid trusted_chain reference: {trusted_chain!r}")
    if min_start_seq is not None and (
        not isinstance(min_start_seq, int)
        or isinstance(min_start_seq, bool)
        or min_start_seq < 2
        or min_start_seq > MAX_SAFE_INT
    ):
        raise ProvenanceInputError(f"min_start_seq must be an integer >= 2, got {min_start_seq!r}")
    _parse_trusted_publishers(trusted_publishers)


def _collect_bytes_refs(node: Any, out: set[str]) -> None:
    if type(node) is str:
        if BYTES_REF_RE.match(node):
            out.add(node)
    elif isinstance(node, list):
        for item in node:
            _collect_bytes_refs(item, out)
    elif isinstance(node, dict):
        for val in node.values():
            _collect_bytes_refs(val, out)


def _collect_record_content_refs(kind_path: str | None, body: Any) -> set[str]:
    """Collect distinct `bytes:sha256:...` refs in `body`, excluding `targets` per A7 §4.4."""
    cited: set[str] = set()
    if kind_path in (RETENTION_HOLD_KIND, PAYLOAD_DISPOSITION_KIND) and isinstance(body, dict):
        for k, val in body.items():
            if k != "targets":
                _collect_bytes_refs(val, cited)
    elif kind_path == RELEASE_RECEIPT_KIND and isinstance(body, dict):
        for k, val in body.items():
            if k not in ("releasedFingerprint", "witnessReceiptRef"):
                _collect_bytes_refs(val, cited)
    else:
        _collect_bytes_refs(body, cited)
    return cited


def _validate_bundle_shape(bundle: Any, export_schema: dict[str, Any]) -> bool:
    """Validate export bundle wire shape, permitting additive optional A11 members."""
    if not isinstance(bundle, dict):
        return False
    has_a11 = False
    for key, expected_type in A11_BUNDLE_FIELD_TYPES.items():
        if key in bundle:
            if not isinstance(bundle[key], expected_type):
                return False
            has_a11 = True
    if not has_a11:
        return validate_wire_schema(bundle, export_schema)
    base_bundle = {k: v for k, v in bundle.items() if k not in A11_BUNDLE_FIELD_TYPES}
    return validate_wire_schema(base_bundle, export_schema)


def _signature_count_matches_definition(
    kind_path: str,
    parsed_def: ParsedDefinition,
    body: dict[str, Any],
    signers: list[str],
) -> bool:
    """Check record signature count against definition, applying A11 §7.3 variable-signature rules."""
    count = len(signers)
    if parsed_def.signatures == 1:
        if kind_path in (BASIS_KIND, BASIS_OVERLAY_KIND):
            return count in (1, 2)
        if kind_path == RELEASE_REQUEST_KIND:
            return count >= 1
        if kind_path == SUCCESSION_KIND:
            if "recoveryProof" in body:
                return count == 1 and signers[0] == body.get("successor")
            return count == 2
    return count == parsed_def.signatures


def verify_record_envelope(
    rec_ref: str,
    env: Any,
    signed_schema: dict[str, Any],
) -> tuple[tuple[bytes, dict[str, Any], list[tuple[str, bytes]]] | None, dict[str, Any]]:
    """Run §5 Layer 1 identity steps on a single record entry."""
    if not isinstance(env, dict) or not validate_wire_schema(env, signed_schema):
        return None, _finding(1, rec_ref, "identity", "failed", "malformed_envelope")

    try:
        payload_bytes = decode_strict_base64(env["payload"])
        sig_entries: list[tuple[str, bytes]] = []
        for s in env["signatures"]:
            sig_entries.append((s["keyid"], decode_strict_base64(s["sig"])))
    except ValueError:
        return None, _finding(1, rec_ref, "identity", "failed", "invalid_base64")

    try:
        payload = parse_canonical_json(payload_bytes)
    except ValueError:
        return None, _finding(1, rec_ref, "identity", "failed", "payload_not_canonical")

    if not isinstance(payload, dict):
        return None, _finding(1, rec_ref, "identity", "failed", "payload_not_an_object")

    signer_1 = sig_entries[0][0]
    if payload.get("issuer") != signer_1:
        return None, _finding(1, rec_ref, "identity", "failed", "issuer_is_not_signer")

    signer_ids = [kid for kid, _ in sig_entries]
    if len(set(signer_ids)) != len(signer_ids):
        return None, _finding(1, rec_ref, "identity", "failed", "duplicate_signer")

    actual_ref = evidence_ref(payload_bytes)
    if actual_ref != rec_ref:
        return None, _finding(
            1, rec_ref, "identity", "failed", "payload_hashes_to_another_reference", actual_ref
        )

    return (payload_bytes, payload, sig_entries), _finding(1, rec_ref, "identity", "ok", "ok")


def verify_provenance_bundle(
    bundle: Any,
    *,
    trusted_profiles: Sequence[str] = (),
    trusted_publishers: Sequence[str] = (),
    trusted_roots: Sequence[str] | None = None,
    trusted_chain: str | None = None,
    min_start_seq: int | None = None,
    installed_definitions: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Verify a parsed Provenance v2 export bundle and return the §9 report object."""
    _validate_reader_options(trusted_roots, trusted_chain, min_start_seq, trusted_publishers)
    schemas = _load_bundled_schemas()
    base_defs_by_ref, base_def_index_refs = _load_base_definitions()
    installed_by_ref = installed_definitions or {}
    trusted_profile_set = set(trusted_profiles)
    publisher_domains = _parse_trusted_publishers(trusted_publishers)

    # §3. The bundle
    if not _validate_bundle_shape(bundle, schemas["export.schema.json"]):
        return _build_report([_finding(1, "bundle", "shape", "failed", "malformed_bundle")])

    seen_record_refs: set[str] = set()
    for rec_entry in bundle["records"]:
        r = rec_entry["ref"]
        if r in seen_record_refs:
            return _build_report([_finding(1, "bundle", "shape", "failed", "malformed_bundle")])
        seen_record_refs.add(r)

    findings: list[dict[str, Any]] = []

    # §4. Blobs and keys
    blobs_by_ref: dict[str, bytes] = {}
    for blob_entry in bundle["blobs"]:
        b_ref = blob_entry["ref"]
        try:
            raw_blob = decode_base64(blob_entry["base64"])
        except ValueError:
            findings.append(_finding(2, b_ref, "content_hash", "failed", "invalid_base64"))
            continue
        if bytes_ref(raw_blob) != b_ref:
            findings.append(
                _finding(2, b_ref, "content_hash", "failed", "bytes_do_not_match_reference")
            )
            continue
        blobs_by_ref[b_ref] = raw_blob

    keys_by_id: dict[str, tuple[str, bytes]] = {}
    for key_entry in bundle["keys"]:
        kid = key_entry["keyid"]
        alg = key_entry["algorithm"]
        try:
            raw_key = decode_base64(key_entry["bytes"])
        except ValueError:
            findings.append(_finding(1, kid, "key", "failed", "conflicting_or_unreadable_key"))
            continue
        if kid in keys_by_id:
            if keys_by_id[kid][1] != raw_key:
                findings.append(_finding(1, kid, "key", "failed", "conflicting_or_unreadable_key"))
            continue
        keys_by_id[kid] = (alg, raw_key)

    # §5. Layer 1: identity & signatures
    opened_records: list[OpenedRecord] = []
    opened_by_ref: dict[str, OpenedRecord] = {}
    signed_schema = schemas["signed-evidence.schema.json"]

    for rec_entry in bundle["records"]:
        rec_ref = rec_entry["ref"]
        env = rec_entry["envelope"]
        opened, id_finding = verify_record_envelope(rec_ref, env, signed_schema)
        findings.append(id_finding)
        if opened is None:
            continue

        payload_bytes, payload, sig_entries = opened
        msg = dsse_pae(env["payloadType"], payload_bytes)
        all_sigs_ok = True
        any_sig_failed = False

        for sig_kid, sig_bytes in sig_entries:
            if sig_kid not in keys_by_id:
                all_sigs_ok = False
                findings.append(
                    _finding(1, rec_ref, "signature", "incomplete", "missing_key", sig_kid)
                )
                continue
            key_alg, key_bytes = keys_by_id[sig_kid]
            if compute_key_id(key_alg, key_bytes) != sig_kid:
                all_sigs_ok = False
                any_sig_failed = True
                findings.append(
                    _finding(1, rec_ref, "signature", "failed", "key_mismatch", sig_kid)
                )
                continue
            if not verify_signature(key_alg, key_bytes, sig_bytes, msg):
                all_sigs_ok = False
                any_sig_failed = True
                findings.append(
                    _finding(1, rec_ref, "signature", "failed", "bad_signature", sig_kid)
                )
                continue
            findings.append(_finding(1, rec_ref, "signature", "ok", "ok", sig_kid))

        rec = OpenedRecord(
            ref=rec_ref,
            payload=payload,
            signers=[kid for kid, _ in sig_entries],
            all_signatures_ok=all_sigs_ok,
            any_signature_failed=any_sig_failed,
        )
        opened_records.append(rec)
        opened_by_ref[rec_ref] = rec

    # Pre-collect §6.2a verified publications
    # Each statement: (pub_ref, issuer, kind_path, def_ref)
    pub_statements_by_kind: dict[str, list[tuple[str, str, str]]] = {}
    for rec in opened_records:
        if rec.kind_path == DEFINITION_PUBLISHED_KIND and rec.all_signatures_ok:
            issuer = rec.payload.get("issuer")
            body = rec.payload.get("body")
            defs = body.get("definitions") if isinstance(body, dict) else None
            if type(issuer) is str and isinstance(defs, list):
                for item in defs:
                    if (
                        isinstance(item, dict)
                        and type(item.get("kind")) is str
                        and type(item.get("definition")) is str
                    ):
                        pub_statements_by_kind.setdefault(item["kind"], []).append(
                            (rec.ref, issuer, item["definition"])
                        )

    # Pre-index omissions by ref (first occurrence wins)
    omissions_by_ref: dict[str, str] = {}
    for om in bundle["omissions"]:
        if om["ref"] not in omissions_by_ref:
            omissions_by_ref[om["ref"]] = om["reason"]

    envelope_schema = schemas["evidence-envelope.schema.json"]
    profile_schema = schemas["capture-profile.schema.json"]
    body_ok_by_ref: dict[str, bool] = {}
    body_result_by_ref: dict[str, str] = {}
    parsed_def_by_ref: dict[str, ParsedDefinition | None] = {}
    valid_profile_by_ref: dict[str, dict[str, Any]] = {}
    profile_bounds_ok_by_ref: dict[str, bool] = {}
    authority_ok_by_ref: dict[str, bool] = {}
    sealer_ok_by_ref: dict[str, bool] = {}

    # §6. Layer 2: Pass 1 — body check (§6.1 & §6.2) for all opened records
    for rec in opened_records:
        payload = rec.payload
        rec_ref = rec.ref
        kind_path = rec.kind_path
        schema_ref = payload.get("schemaRef") if type(payload.get("schemaRef")) is str else None
        body = payload.get("body")
        body_ok_by_ref[rec_ref] = False
        body_result_by_ref[rec_ref] = "failed"
        parsed_def: ParsedDefinition | None = None
        if schema_ref is not None:
            doc_bytes: bytes | None = None
            for source in (base_defs_by_ref, installed_by_ref, blobs_by_ref):
                candidate = source.get(schema_ref)
                if candidate is not None and bytes_ref(candidate) == schema_ref:
                    doc_bytes = candidate
                    break
            if doc_bytes is not None:
                parsed_def = parse_definition_document(doc_bytes)
        parsed_def_by_ref[rec_ref] = parsed_def

        if not validate_wire_schema(payload, envelope_schema):
            findings.append(_finding(2, rec_ref, "body", "failed", "envelope_does_not_match_schema"))
        else:
            causes = payload.get("causes")
            causes_ok = True
            if causes is not None:
                for idx in range(len(causes) - 1):
                    if causes[idx].encode("utf-8") >= causes[idx + 1].encode("utf-8"):
                        causes_ok = False
                        break
            if not causes_ok:
                findings.append(
                    _finding(2, rec_ref, "body", "failed", "causes_not_sorted_and_unique")
                )
            else:
                assert schema_ref is not None and kind_path is not None and isinstance(body, dict)
                if parsed_def is None:
                    body_result_by_ref[rec_ref] = "incomplete"
                    findings.append(
                        _finding(
                            2, rec_ref, "body", "incomplete", "definition_not_available", schema_ref
                        )
                    )
                elif parsed_def.kind != kind_path:
                    findings.append(
                        _finding(2, rec_ref, "body", "failed", "definition_is_for_another_kind")
                    )
                elif not _signature_count_matches_definition(
                    kind_path, parsed_def, body, rec.signers
                ):
                    findings.append(
                        _finding(
                            2,
                            rec_ref,
                            "body",
                            "failed",
                            "signature_count_differs_from_definition",
                        )
                    )
                elif not validate_body_against_schema(body, parsed_def.schema, rec.signers):
                    findings.append(
                        _finding(2, rec_ref, "body", "failed", "body_does_not_match_definition")
                    )
                elif (
                    payload.get("kind") in ("SessionOpened", "SessionClosed")
                    and "session" in payload
                    and "session" in body
                    and not json_eq(payload["session"], body["session"])
                ):
                    findings.append(
                        _finding(2, rec_ref, "body", "failed", "session_differs_from_body")
                    )
                else:
                    body_ok_by_ref[rec_ref] = True
                    body_result_by_ref[rec_ref] = "ok"
                    findings.append(_finding(2, rec_ref, "body", "ok", "ok", kind_path))

    # §6. Layer 2: Pass 2 — publication and profile bounds/authority
    for rec in opened_records:
        payload = rec.payload
        rec_ref = rec.ref
        kind_path = rec.kind_path
        schema_ref = payload.get("schemaRef") if type(payload.get("schemaRef")) is str else None
        profile_ref = payload.get("profileRef") if type(payload.get("profileRef")) is str else None
        body = payload.get("body")
        profile_bounds_ok_by_ref[rec_ref] = False

        # §6.2a & §6.3b / A6 §3 / A9 §4 Publication
        if kind_path == DEFINITION_PUBLISHED_KIND and _is_publication_from_stranger(
            payload, publisher_domains
        ):
            findings.append(
                _finding(
                    2,
                    rec_ref,
                    "publication",
                    "incomplete",
                    "publisher_not_trusted",
                    rec_ref,
                )
            )
        elif kind_path == CHAIN_STARTED_KIND and body_ok_by_ref[rec_ref]:
            findings.append(
                _verify_chain_started_publication(
                    rec=rec,
                    opened_by_ref=opened_by_ref,
                    body_ok_by_ref=body_ok_by_ref,
                    publisher_domains=publisher_domains,
                )
            )
        else:
            stmts = pub_statements_by_kind.get(kind_path, []) if kind_path is not None else []
            trusted_stmts = [
                s for s in stmts if _publisher_believed_for_kind(publisher_domains, s[1], kind_path)
            ]
            untrusted_stmts = [
                s
                for s in stmts
                if not _publisher_believed_for_kind(publisher_domains, s[1], kind_path)
            ]

            matching_trusted = [s for s in trusted_stmts if s[2] == schema_ref]
            if matching_trusted:
                best_ref = min((s[0] for s in matching_trusted), key=lambda r: r.encode("utf-8"))
                findings.append(_finding(2, rec_ref, "publication", "ok", "ok", best_ref))
            elif trusted_stmts:
                first_ref = min((s[0] for s in trusted_stmts), key=lambda r: r.encode("utf-8"))
                findings.append(
                    _finding(
                        2,
                        rec_ref,
                        "publication",
                        "failed",
                        "definition_differs_from_published",
                        first_ref,
                    )
                )
            else:
                matching_untrusted = [s for s in untrusted_stmts if s[2] == schema_ref]
                if matching_untrusted:
                    best_ref = min(
                        (s[0] for s in matching_untrusted), key=lambda r: r.encode("utf-8")
                    )
                    findings.append(
                        _finding(
                            2,
                            rec_ref,
                            "publication",
                            "incomplete",
                            "publisher_not_trusted",
                            best_ref,
                        )
                    )
                else:
                    findings.append(
                        _finding(
                            2,
                            rec_ref,
                            "publication",
                            "incomplete",
                            "publication_not_carried",
                            schema_ref,
                        )
                    )

        # §6.3 Profile bounds and authority
        raw_profile = blobs_by_ref.get(profile_ref) if profile_ref is not None else None
        if raw_profile is None:
            findings.append(
                _finding(
                    2,
                    rec_ref,
                    "profile_bounds",
                    "incomplete",
                    "profile_not_available",
                    profile_ref,
                )
            )
        else:
            assert profile_ref is not None
            profile_obj = valid_profile_by_ref.get(profile_ref)
            if profile_obj is None:
                try:
                    cand = parse_canonical_json(raw_profile)
                    if isinstance(cand, dict) and validate_wire_schema(cand, profile_schema):
                        profile_obj = cand
                        valid_profile_by_ref[profile_ref] = cand
                except ValueError:
                    profile_obj = None

            if profile_obj is None:
                findings.append(
                    _finding(
                        2,
                        rec_ref,
                        "profile_bounds",
                        "failed",
                        "unreadable_profile",
                        profile_ref,
                    )
                )
            else:
                stream = payload.get("stream")
                actor = payload.get("actor")
                issuer = payload.get("issuer")
                bound = any(
                    type(stream) is str
                    and stream.startswith(b["streamPrefix"])
                    and type(actor) is str
                    and any(actor.startswith(ap) for ap in b["actorPrefixes"])
                    and issuer in b["issuerKeys"]
                    for b in profile_obj["authority"]["bindings"]
                )
                if kind_path is None or profile_obj["schemas"].get(kind_path) != schema_ref:
                    findings.append(
                        _finding(
                            2,
                            rec_ref,
                            "profile_bounds",
                            "failed",
                            "kind_not_in_profile",
                            profile_ref,
                        )
                    )
                elif not bound:
                    findings.append(
                        _finding(
                            2,
                            rec_ref,
                            "profile_bounds",
                            "failed",
                            "issuer_not_bound",
                            profile_ref,
                        )
                    )
                elif kind_path in profile_obj["policyRequiredKinds"] and not isinstance(
                    body.get("policy") if isinstance(body, dict) else None, dict
                ):
                    findings.append(
                        _finding(
                            2,
                            rec_ref,
                            "profile_bounds",
                            "failed",
                            "policy_required",
                            profile_ref,
                        )
                    )
                else:
                    profile_bounds_ok_by_ref[rec_ref] = True
                    findings.append(
                        _finding(2, rec_ref, "profile_bounds", "ok", "ok", profile_ref)
                    )

                if trusted_roots is None and trusted_chain is None:
                    if profile_ref in trusted_profile_set:
                        authority_ok_by_ref[rec_ref] = True
                        findings.append(_finding(2, rec_ref, "authority", "ok", "ok", profile_ref))
                    else:
                        authority_ok_by_ref[rec_ref] = False
                        findings.append(
                            _finding(
                                2,
                                rec_ref,
                                "authority",
                                "incomplete",
                                "profile_not_trusted",
                                profile_ref,
                            )
                        )

    # §6.5 Links within a stream
    by_stream: dict[str, dict[int, list[OpenedRecord]]] = {}
    for rec in opened_records:
        stream = rec.payload.get("stream")
        seq = rec.payload.get("seq")
        if type(stream) is str and type(seq) is int and seq >= 1:
            by_stream.setdefault(stream, {}).setdefault(seq, []).append(rec)

    for stream, seq_map in by_stream.items():
        for seq, recs_at_seq in seq_map.items():
            if len(recs_at_seq) >= 2:
                findings.append(
                    _finding(
                        2,
                        stream,
                        "fork",
                        "failed",
                        "two_records_at_one_position",
                        f"seq:{seq}",
                    )
                )
            elif len(recs_at_seq) == 1:
                prior_recs = seq_map.get(seq - 1)
                if prior_recs is not None and len(prior_recs) == 1:
                    curr_rec = recs_at_seq[0]
                    prior_rec = prior_recs[0]
                    if curr_rec.payload.get("previous") == prior_rec.ref:
                        findings.append(
                            _finding(2, curr_rec.ref, "previous", "ok", "ok", prior_rec.ref)
                        )
                    else:
                        findings.append(
                            _finding(
                                2,
                                curr_rec.ref,
                                "previous",
                                "failed",
                                "previous_is_not_the_prior_record",
                                prior_rec.ref,
                            )
                        )

    # §7 & §7a. Layer 3: seals and seal_chain
    manifest_schema = schemas["epoch-manifest.schema.json"]
    seal_refs: list[str] = list(
        dict.fromkeys(list(bundle["seals"]) + [p["seal"] for p in bundle["proofs"]])
    )
    seal_covered_refs: dict[str, set[str]] = {}
    seal_chain_failed_refs: set[str] = set()
    checked_epoch_seals: list[str] = []
    pred_seal_chain_by_ref: dict[str, dict[str, Any] | None] = {}
    seal_ranges_by_ref: dict[str, tuple[str, int, int]] = {}

    for seal_ref in seal_refs:
        seal_rec = opened_by_ref.get(seal_ref)
        if seal_rec is None:
            findings.append(_finding(3, seal_ref, "seal", "incomplete", "seal_record_not_carried"))
            continue
        if seal_rec.kind_path != EPOCH_SEAL_KIND:
            findings.append(_finding(3, seal_ref, "seal", "failed", "not_an_epoch_seal"))
            continue

        seal_payload = seal_rec.payload
        raw_seal_body = seal_payload.get("body")
        seal_body: dict[str, Any] = raw_seal_body if isinstance(raw_seal_body, dict) else {}
        seal_profile_ref = (
            seal_payload.get("profileRef")
            if type(seal_payload.get("profileRef")) is str
            else None
        )
        seal_issuer = (
            seal_payload.get("issuer") if type(seal_payload.get("issuer")) is str else None
        )
        sealed_stream = seal_body.get("stream") if type(seal_body.get("stream")) is str else None

        # Sealer check
        raw_seal_profile = (
            blobs_by_ref.get(seal_profile_ref) if seal_profile_ref is not None else None
        )
        parsed_seal_profile: Any = None
        if raw_seal_profile is not None:
            try:
                parsed_seal_profile = parse_canonical_json(raw_seal_profile)
            except ValueError:
                parsed_seal_profile = None

        if parsed_seal_profile is None:
            findings.append(
                _finding(
                    3, seal_ref, "sealer", "incomplete", "profile_not_available", seal_profile_ref
                )
            )
        else:
            bindings = (
                parsed_seal_profile.get("authority", {}).get("bindings", [])
                if isinstance(parsed_seal_profile, dict)
                and isinstance(parsed_seal_profile.get("authority"), dict)
                else []
            )
            authorized = (
                isinstance(bindings, list)
                and sealed_stream is not None
                and seal_issuer is not None
                and any(
                    isinstance(b, dict)
                    and type(b.get("streamPrefix")) is str
                    and sealed_stream.startswith(b["streamPrefix"])
                    and isinstance(b.get("sealerKeys"), list)
                    and seal_issuer in b["sealerKeys"]
                    for b in bindings
                )
            )
            if authorized:
                sealer_ok_by_ref[seal_ref] = True
                findings.append(_finding(3, seal_ref, "sealer", "ok", "ok", seal_issuer))
            else:
                sealer_ok_by_ref[seal_ref] = False
                findings.append(
                    _finding(3, seal_ref, "sealer", "failed", "unauthorized_seal", seal_issuer)
                )

        # §7a Seal chain predecessor check (A9 §3)
        checked_epoch_seals.append(seal_ref)
        first_seq_sc = seal_body.get("firstSeq")
        last_seq_sc = seal_body.get("lastSeq")
        prev_seal_sc = seal_body.get("previousSeal")
        pred_finding: dict[str, Any] | None = None
        if type(first_seq_sc) is int:
            if first_seq_sc == 1 and prev_seal_sc is not None:
                pred_finding = _finding(
                    3, seal_ref, "seal_chain", "failed", "first_seal_names_a_predecessor"
                )
            elif first_seq_sc > 1 and prev_seal_sc is None:
                pred_finding = _finding(
                    3, seal_ref, "seal_chain", "failed", "seal_predecessor_missing"
                )
            elif first_seq_sc > 1 and type(prev_seal_sc) is str and prev_seal_sc in opened_by_ref:
                pred_seal = opened_by_ref[prev_seal_sc]
                raw_pred_body = pred_seal.payload.get("body")
                pred_body = raw_pred_body if isinstance(raw_pred_body, dict) else {}
                if (
                    pred_seal.kind_path == EPOCH_SEAL_KIND
                    and sealed_stream is not None
                    and pred_body.get("stream") == sealed_stream
                    and type(pred_body.get("lastSeq")) is int
                    and pred_body.get("lastSeq") == first_seq_sc - 1
                ):
                    pred_finding = _finding(3, seal_ref, "seal_chain", "ok", "ok", prev_seal_sc)
                else:
                    pred_finding = _finding(
                        3,
                        seal_ref,
                        "seal_chain",
                        "failed",
                        "seal_predecessor_does_not_adjoin",
                        prev_seal_sc,
                    )
        pred_seal_chain_by_ref[seal_ref] = pred_finding
        if (
            sealed_stream is not None
            and type(first_seq_sc) is int
            and type(last_seq_sc) is int
            and first_seq_sc <= last_seq_sc
        ):
            seal_ranges_by_ref[seal_ref] = (sealed_stream, first_seq_sc, last_seq_sc)

        # Epoch check
        manifest_ref = (
            seal_body.get("manifestRef") if type(seal_body.get("manifestRef")) is str else None
        )
        raw_manifest = blobs_by_ref.get(manifest_ref) if manifest_ref is not None else None
        if raw_manifest is None:
            findings.append(
                _finding(3, seal_ref, "epoch", "incomplete", "manifest_not_carried", manifest_ref)
            )
            continue

        manifest_obj: dict[str, Any] | None = None
        try:
            cand_m = parse_canonical_json(raw_manifest)
            if isinstance(cand_m, dict) and validate_wire_schema(cand_m, manifest_schema):
                manifest_obj = cand_m
        except ValueError:
            manifest_obj = None

        if manifest_obj is None:
            findings.append(
                _finding(3, seal_ref, "epoch", "failed", "unreadable_manifest", manifest_ref)
            )
            continue

        events: list[str] = manifest_obj["events"]
        if any(ev_ref not in opened_by_ref for ev_ref in events):
            findings.append(
                _finding(
                    3, seal_ref, "epoch", "incomplete", "not_every_covered_record_is_carried"
                )
            )
            continue

        first_seq = seal_body.get("firstSeq")
        last_seq = seal_body.get("lastSeq")
        seal_root = seal_body.get("root")

        epoch_err: str | None = None
        if manifest_obj.get("format") != PROVENANCE_EPOCH_FORMAT:
            epoch_err = "epoch_manifest_format"
        elif bytes_ref(canonical_json_bytes(manifest_obj)) != manifest_ref:
            epoch_err = "epoch_manifest_ref"
        elif (
            type(first_seq) is not int
            or type(last_seq) is not int
            or (last_seq - first_seq + 1) != len(events)
        ):
            epoch_err = "epoch_range_length"
        elif merkle_root_for_events(events) != seal_root:
            epoch_err = "epoch_root"
        else:
            for idx, ev_ref in enumerate(events):
                cov = opened_by_ref[ev_ref]
                if cov.payload.get("stream") != sealed_stream:
                    epoch_err = "epoch_stream"
                    break
                if cov.payload.get("seq") != first_seq + idx:
                    epoch_err = "epoch_sequence"
                    break
                if idx == 0:
                    if first_seq == 1 and cov.payload.get("previous") is not None:
                        epoch_err = "epoch_previous"
                        break
                else:
                    if cov.payload.get("previous") != events[idx - 1]:
                        epoch_err = "epoch_previous"
                        break

        if epoch_err is not None:
            findings.append(_finding(3, seal_ref, "epoch", "failed", epoch_err))
        else:
            seal_covered_refs.setdefault(seal_ref, set()).update(events)
            findings.append(
                _finding(3, seal_ref, "epoch", "ok", "ok", f"seq:{first_seq}-{last_seq}")
            )

    # §7a Seal chain overlap check & single seal_chain finding emission per checked EpochSeal
    for seal_ref in checked_epoch_seals:
        pf = pred_seal_chain_by_ref.get(seal_ref)
        if pf is not None and pf["result"] == "failed":
            seal_chain_failed_refs.add(seal_ref)
            findings.append(pf)
            continue
        overlapping_refs: list[str] = []
        a_range = seal_ranges_by_ref.get(seal_ref)
        if a_range is not None:
            a_stream, a_first, a_last = a_range
            for b_ref, (b_stream, b_first, b_last) in seal_ranges_by_ref.items():
                if (
                    b_ref != seal_ref
                    and b_stream == a_stream
                    and a_first <= b_last
                    and b_first <= a_last
                ):
                    overlapping_refs.append(b_ref)
        if overlapping_refs:
            lowest_other = min(overlapping_refs, key=lambda r: r.encode("utf-8"))
            seal_chain_failed_refs.add(seal_ref)
            findings.append(
                _finding(3, seal_ref, "seal_chain", "failed", "seal_ranges_overlap", lowest_other)
            )
        elif pf is not None:
            findings.append(pf)

    # §8. Layer 3: membership proofs
    for proof in bundle["proofs"]:
        p_rec_ref = proof["record"]
        p_seal_ref = proof["seal"]
        p_index = proof["index"]
        p_siblings = proof["siblings"]

        target_rec = opened_by_ref.get(p_rec_ref)
        seal_rec = opened_by_ref.get(p_seal_ref)
        if target_rec is None or seal_rec is None:
            findings.append(
                _finding(
                    3,
                    p_rec_ref,
                    "membership",
                    "incomplete",
                    "seal_or_record_not_carried",
                    p_seal_ref,
                )
            )
            continue

        raw_p_seal_body = seal_rec.payload.get("body")
        seal_body = raw_p_seal_body if isinstance(raw_p_seal_body, dict) else {}
        first_seq = seal_body.get("firstSeq")
        last_seq = seal_body.get("lastSeq")
        sealed_stream = seal_body.get("stream")
        seal_root = seal_body.get("root")

        if (
            type(sealed_stream) is not str
            or target_rec.payload.get("stream") != sealed_stream
            or type(first_seq) is not int
            or target_rec.payload.get("seq") != first_seq + p_index
        ):
            findings.append(
                _finding(
                    3,
                    p_rec_ref,
                    "membership",
                    "failed",
                    "position_does_not_match_seal",
                    p_seal_ref,
                )
            )
            continue

        tree_size = (last_seq - first_seq + 1) if type(last_seq) is int else 0
        if not verify_merkle_inclusion(p_rec_ref, p_index, tree_size, p_siblings, seal_root):
            findings.append(
                _finding(
                    3,
                    p_rec_ref,
                    "membership",
                    "failed",
                    "proof_does_not_reach_root",
                    p_seal_ref,
                )
            )
            continue

        seal_covered_refs.setdefault(p_seal_ref, set()).add(p_rec_ref)
        findings.append(_finding(3, p_rec_ref, "membership", "ok", "ok", p_seal_ref))

    # §7a: Any seal with a failed seal_chain finding does not count as covering records in §6.3a / §6.4a.
    for failed_seal_ref in seal_chain_failed_refs:
        seal_covered_refs.pop(failed_seal_ref, None)

    # §6.3b / A6 §§3–4: Layer 2 start check, RootChangeApproval checks, and root tenures
    start_findings, start_report_member, a5_incomplete_chain, tenures_by_key = (
        _verify_start_stream(
            opened_records=opened_records,
            opened_by_ref=opened_by_ref,
            body_ok_by_ref=body_ok_by_ref,
            body_result_by_ref=body_result_by_ref,
            seal_covered_refs=seal_covered_refs,
            trusted_roots=trusted_roots,
            trusted_chain=trusted_chain,
            min_start_seq=min_start_seq,
        )
    )
    findings.extend(start_findings)

    # §6.3a & §6.3b Authority from trusted roots or pinned chain (Amendment A5 + A6 Slice 2 §4 + A7 §3)
    a5_qualifying_seal_refs: set[str] = set()
    if trusted_roots is not None or trusted_chain is not None:
        if a5_incomplete_chain and trusted_chain is not None:
            for rec in opened_records:
                if rec.kind_path not in A5_EXEMPT_KINDS:
                    authority_ok_by_ref[rec.ref] = False
                    findings.append(
                        _finding(
                            2,
                            rec.ref,
                            "authority",
                            "incomplete",
                            "chain_not_carried",
                            trusted_chain,
                        )
                    )
        else:
            a5_findings, a5_qualifying_seal_refs = _verify_a5_authority(
                opened_records=opened_records,
                opened_by_ref=opened_by_ref,
                body_ok_by_ref=body_ok_by_ref,
                body_result_by_ref=body_result_by_ref,
                parsed_def_by_ref=parsed_def_by_ref,
                seal_covered_refs=seal_covered_refs,
                tenures_by_key=tenures_by_key,
            )
            for af in a5_findings:
                authority_ok_by_ref[af["subject"]] = af["result"] == "ok"
            findings.extend(a5_findings)

    # §6.4 & §6.4a Content, Retention, Scoped Legal Holds, and Payload Disposition (Amendment A7 §§4–5)
    findings.extend(
        _verify_content_retention_and_disposition(
            opened_records=opened_records,
            opened_by_ref=opened_by_ref,
            blobs_by_ref=blobs_by_ref,
            base_def_index_refs=base_def_index_refs,
            omissions_by_ref=omissions_by_ref,
            body_ok_by_ref=body_ok_by_ref,
            authority_ok_by_ref=authority_ok_by_ref,
            profile_bounds_ok_by_ref=profile_bounds_ok_by_ref,
            sealer_ok_by_ref=sealer_ok_by_ref,
            valid_profile_by_ref=valid_profile_by_ref,
            by_stream=by_stream,
            seal_covered_refs=seal_covered_refs,
            a5_qualifying_seal_refs=a5_qualifying_seal_refs,
            use_root_or_chain_trust=(trusted_roots is not None or trusted_chain is not None),
        )
    )

    return _build_report(findings, start_info=start_report_member)


# ---------------------------------------------------------------------------
# §6.3b Deployment Start & ChainStarted Publication (Amendment A6 Slice 1)
# ---------------------------------------------------------------------------


def _extract_def_pairs(defs_val: Any) -> tuple[list[str], set[tuple[str, str]]] | None:
    if not isinstance(defs_val, list):
        return None
    kinds: list[str] = []
    pairs: set[tuple[str, str]] = set()
    for item in defs_val:
        if not isinstance(item, dict):
            return None
        k = item.get("kind")
        d = item.get("definition")
        if type(k) is not str or type(d) is not str:
            return None
        kinds.append(k)
        pairs.add((k, d))
    return kinds, pairs


def _verify_chain_started_publication(
    *,
    rec: OpenedRecord,
    opened_by_ref: dict[str, OpenedRecord],
    body_ok_by_ref: dict[str, bool],
    publisher_domains: dict[str, set[str] | None],
) -> dict[str, Any]:
    """Evaluate A6 §3 / A9 §4 tightened publication table for an opened ChainStarted with body == ok."""
    payload = rec.payload
    raw_body = payload.get("body")
    body: dict[str, Any] = raw_body if isinstance(raw_body, dict) else {}
    schema_ref = payload.get("schemaRef") if type(payload.get("schemaRef")) is str else None
    p_ref = body.get("publication")
    p_pub = body.get("publisher")
    d_list = body.get("definitions")

    if type(p_ref) is not str:
        return _finding(2, rec.ref, "publication", "incomplete", "publication_not_carried", None)

    p_rec = opened_by_ref.get(p_ref)
    if p_rec is None:
        return _finding(2, rec.ref, "publication", "incomplete", "publication_not_carried", p_ref)

    if (
        p_rec.kind_path != DEFINITION_PUBLISHED_KIND
        or not body_ok_by_ref.get(p_rec.ref, False)
        or type(p_pub) is not str
        or p_rec.payload.get("issuer") != p_pub
        or p_rec.any_signature_failed
    ):
        return _finding(2, rec.ref, "publication", "failed", "cited_publication_mismatch", p_ref)

    if not p_rec.all_signatures_ok:
        return _finding(2, rec.ref, "publication", "incomplete", "publication_not_verified", p_ref)

    cs_extracted = _extract_def_pairs(d_list)
    p_raw_body = p_rec.payload.get("body")
    p_extracted = _extract_def_pairs(
        p_raw_body.get("definitions") if isinstance(p_raw_body, dict) else None
    )
    if cs_extracted is None or p_extracted is None:
        return _finding(
            2, rec.ref, "publication", "failed", "definitions_differ_from_publication", p_ref
        )
    cs_kinds, cs_pairs = cs_extracted
    _, p_pairs = p_extracted
    if (
        len(set(cs_kinds)) != len(cs_kinds)
        or cs_pairs != p_pairs
        or schema_ref is None
        or (CHAIN_STARTED_KIND, schema_ref) not in cs_pairs
    ):
        return _finding(
            2, rec.ref, "publication", "failed", "definitions_differ_from_publication", p_ref
        )

    if not all(_publisher_believed_for_kind(publisher_domains, p_pub, k) for k in cs_kinds):
        return _finding(2, rec.ref, "publication", "incomplete", "publisher_not_trusted", p_ref)

    return _finding(2, rec.ref, "publication", "ok", "ok", p_ref)


Instant = tuple[int, str]


@dataclass(frozen=True)
class RootTenure:
    """One root key's period of office on a deployment (A6 Slice 2 §4.2)."""

    key: str
    admitted_at: Instant | None
    ended_by: tuple[Instant, str] | None


def _has_expected_start_record_shape(rec: OpenedRecord) -> bool:
    """Ensure opened ChainStarted / Deployment / RootsChanged records carry readable A6 body fields."""
    payload = rec.payload
    if parse_rfc3339_instant(payload.get("capturedAt")) is None:
        return False
    body = payload.get("body")
    if not isinstance(body, dict):
        return False
    if rec.kind_path == CHAIN_STARTED_KIND:
        defs = body.get("definitions")
        return (
            type(body.get("deployment")) is str
            and type(body.get("bootstrap")) is str
            and isinstance(defs, list)
            and all(isinstance(d, dict) and type(d.get("kind")) is str for d in defs)
        )
    if rec.kind_path in (DEPLOYMENT_KIND, ROOTS_CHANGED_KIND):
        roots = body.get("roots")
        if not (
            type(body.get("threshold")) is int
            and isinstance(roots, list)
            and len(roots) >= 1
            and all(
                isinstance(r, dict)
                and type(r.get("key")) is str
                and ("holder" not in r or type(r["holder"]) is str)
                for r in roots
            )
        ):
            return False
        if rec.kind_path == DEPLOYMENT_KIND:
            if not (
                type(body.get("accepts")) is str
                and type(body.get("bootstrap")) is str
                and type(body.get("claimedBy")) is str
            ):
                return False
        else:
            if not (
                type(body.get("chain")) is str
                and type(body.get("replaces")) is str
                and body.get("authorization") in ("quorum", "recovery")
                and type(body.get("signer")) is str
            ):
                return False
        if "recoveryKeys" in body:
            rk = body["recoveryKeys"]
            if not isinstance(rk, list) or not all(type(x) is str for x in rk):
                return False
        if "custodians" in body:
            cust = body["custodians"]
            if not isinstance(cust, list) or not all(
                isinstance(c, dict)
                and type(c.get("identity")) is str
                and ("key" not in c or type(c["key"]) is str)
                for c in cust
            ):
                return False
        return True
    return False


def _has_expected_approval_shape(rec: OpenedRecord) -> bool:
    """Ensure an opened RootChangeApproval carries readable A6 Slice 2 §1.2 fields."""
    payload = rec.payload
    if (
        type(payload.get("stream")) is not str
        or type(payload.get("seq")) is not int
        or parse_rfc3339_instant(payload.get("capturedAt")) is None
    ):
        return False
    body = payload.get("body")
    return (
        isinstance(body, dict)
        and type(body.get("change")) is str
        and type(body.get("root")) is str
        and type(body.get("custodian")) is str
        and type(body.get("custodianKey")) is str
    )


def _deployment_terms_valid(body: dict[str, Any], *, require_claimed_by: bool = True) -> bool:
    """Check A6 Slice 2 §3.2 terms consistency on Deployment (row 11) and RootsChanged (row 20)."""
    roots: list[dict[str, Any]] = body["roots"]
    root_keys = [r["key"] for r in roots]
    root_key_set = set(root_keys)
    if len(root_key_set) != len(root_keys):
        return False
    if any(r.get("holder") == "agent" for r in roots):
        return False
    threshold: int = body["threshold"]
    if threshold < 1 or threshold > len(roots):
        return False
    if require_claimed_by and body["claimedBy"] not in root_key_set:
        return False
    rec_key_set: set[str] = set()
    if "recoveryKeys" in body:
        rec_keys: list[str] = body["recoveryKeys"]
        rec_key_set = set(rec_keys)
        if len(rec_key_set) != len(rec_keys):
            return False
        if rec_key_set & root_key_set:
            return False
    if "custodians" in body:
        custodians: list[dict[str, Any]] = body["custodians"]
        cust_ids = [c["identity"] for c in custodians]
        if len(set(cust_ids)) != len(cust_ids):
            return False
        cust_keys = [c["key"] for c in custodians if "key" in c]
        cust_key_set = set(cust_keys)
        if len(cust_key_set) != len(cust_keys):
            return False
        if cust_key_set & (root_key_set | rec_key_set):
            return False
    return True


def _is_endorsement_sealed_before_change(
    *,
    endorsement_rec: OpenedRecord,
    change_time: Instant,
    prior_root_keys: set[str],
    opened_by_ref: dict[str, OpenedRecord],
    body_result_by_ref: dict[str, str],
    auth_links_by_ref: dict[str, OpenedRecord],
    revocations_by_target: dict[str, list[OpenedRecord]],
    succ_state: _SuccessionState,
    seal_covered_refs: dict[str, set[str]],
) -> bool:
    """Check A6 Slice 2 §3.5 pre-change EpochSeal corroboration for a late-bound custodian Endorsement."""
    prior_tenures: dict[str, list[RootTenure]] = {
        rk: [RootTenure(rk, None, None)] for rk in prior_root_keys
    }
    all_valid_links = list(auth_links_by_ref.values())
    empty_seals: dict[str, list[Instant]] = {}

    for seal_ref, covered_set in seal_covered_refs.items():
        if endorsement_rec.ref not in covered_set:
            continue
        seal_rec = opened_by_ref.get(seal_ref)
        if (
            seal_rec is None
            or seal_rec.kind_path != EPOCH_SEAL_KIND
            or not seal_rec.all_signatures_ok
        ):
            continue
        t_seal = parse_rfc3339_instant(seal_rec.payload.get("capturedAt"))
        if t_seal is None or not (t_seal < change_time):
            continue
        s_issuer = seal_rec.payload.get("issuer")
        if type(s_issuer) is not str or succ_state.key_ending.get(s_issuer) is not None:
            continue

        for bottom_link in all_valid_links:
            subj = bottom_link.payload["body"]["subject"]
            if bottom_link.kind_path == BADGE_KIND:
                if s_issuer != subj:
                    continue
            elif not succ_state.same_or_stands_in_for(s_issuer, subj, t_seal):
                continue
            if not _link_covers_record(bottom_link, seal_rec):
                continue
            full_chain, _ = _walk_up_from_link(
                bottom_link,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                succ_state,
                prior_tenures,
            )
            if full_chain is None or not all(_link_covers_record(lk, seal_rec) for lk in full_chain):
                continue
            if _chain_has_no_revocation_or_nonroot_succession(
                full_chain,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                revocations_by_target,
                succ_state,
                prior_tenures,
                empty_seals,
            ):
                return True
    return False


def _verify_root_change_approval(
    *,
    app_rec: OpenedRecord,
    candidate_streams: set[str],
    stream_seq_map: dict[str, dict[int, list[OpenedRecord]]],
    stream_opened_count: dict[str, int],
    opened_by_ref: dict[str, OpenedRecord],
    body_ok_by_ref: dict[str, bool],
    body_result_by_ref: dict[str, str],
    start_result_by_ref: dict[str, str],
    start_code_by_ref: dict[str, str],
    agent_principal_keys: set[str],
    auth_links_by_ref: dict[str, OpenedRecord],
    revocations_by_target: dict[str, list[OpenedRecord]],
    succ_state: _SuccessionState,
    seal_covered_refs: dict[str, set[str]],
) -> dict[str, Any]:
    """Evaluate A6 Slice 2 §3.3 Rows A1–A15 for an off-start-stream RootChangeApproval."""
    a_body_res = body_result_by_ref.get(app_rec.ref, "failed")
    if a_body_res == "failed" or app_rec.any_signature_failed:
        return _finding(2, app_rec.ref, "start", "failed", "invalid_root_change_approval", None)
    if a_body_res == "incomplete" or not app_rec.all_signatures_ok:
        return _finding(
            2, app_rec.ref, "start", "incomplete", "unverified_root_change_approval", None
        )
    if not _has_expected_approval_shape(app_rec):
        return _finding(2, app_rec.ref, "start", "failed", "invalid_root_change_approval", None)

    a_stream: str = app_rec.payload["stream"]
    a_seq: int = app_rec.payload["seq"]
    if a_seq != 1 or stream_opened_count.get(a_stream, 0) != 1:
        return _finding(
            2, app_rec.ref, "start", "failed", "approval_not_alone_on_stream", a_stream
        )

    a_body = app_rec.payload["body"]
    change_ref: str = a_body["change"]
    r_rec = opened_by_ref.get(change_ref)
    if r_rec is None:
        return _finding(
            2, app_rec.ref, "start", "incomplete", "approved_change_not_carried", change_ref
        )

    sole_stream = next(iter(candidate_streams)) if len(candidate_streams) == 1 else None
    r_stream = r_rec.payload.get("stream")
    r_seq = r_rec.payload.get("seq")
    r_body_res = body_result_by_ref.get(r_rec.ref, "failed")
    seq_map_for_r = stream_seq_map.get(sole_stream, {}) if sole_stream is not None else {}

    on_single_non_forked_start = (
        sole_stream is not None
        and VALID_START_STREAM_RE.match(sole_stream) is not None
        and r_rec.kind_path == ROOTS_CHANGED_KIND
        and r_stream == sole_stream
        and type(r_seq) is int
        and r_seq >= 3
        and len(seq_map_for_r.get(r_seq, [])) == 1
    )
    if not on_single_non_forked_start or r_body_res == "failed":
        return _finding(
            2, app_rec.ref, "start", "failed", "approval_not_for_quorum_change", change_ref
        )
    if r_body_res == "ok":
        if (
            not _has_expected_start_record_shape(r_rec)
            or r_rec.payload["body"].get("authorization") != "quorum"
        ):
            return _finding(
                2, app_rec.ref, "start", "failed", "approval_not_for_quorum_change", change_ref
            )
    else:
        # Row A6: R's body is incomplete
        return _finding(
            2, app_rec.ref, "start", "incomplete", "unverified_start_record", change_ref
        )

    assert type(r_seq) is int
    r_body = r_rec.payload["body"]
    replaces_ref: str = r_body["replaces"]
    recs_at_prev = seq_map_for_r.get(r_seq - 1, [])
    if not recs_at_prev:
        return _finding(
            2, app_rec.ref, "start", "incomplete", "prior_start_not_carried", replaces_ref
        )

    matching_p = [p for p in recs_at_prev if p.ref == replaces_ref]
    p_rec = (
        matching_p[0]
        if matching_p
        else min(recs_at_prev, key=lambda p: p.ref.encode("utf-8"))
    )
    p_start_res = start_result_by_ref.get(p_rec.ref)
    p_start_code = start_code_by_ref.get(p_rec.ref)

    if p_rec.ref != replaces_ref or p_start_res == "failed":
        return _finding(
            2, app_rec.ref, "start", "failed", "approval_not_for_quorum_change", p_rec.ref
        )
    if p_start_res == "incomplete" and p_start_code not in (
        "chain_not_trusted",
        "new_roots_not_trusted",
    ):
        return _finding(
            2, app_rec.ref, "start", "incomplete", "unverified_start_record", p_rec.ref
        )

    # Prior terms T = P.body
    t_terms = p_rec.payload["body"]
    prior_root_keys = {r["key"] for r in t_terms["roots"]}
    prior_recovery_keys = set(t_terms.get("recoveryKeys", ()))

    a_root: str = a_body["root"]
    a_custodian: str = a_body["custodian"]
    a_cust_key: str = a_body["custodianKey"]

    if a_root not in prior_root_keys or a_root in agent_principal_keys:
        return _finding(2, app_rec.ref, "start", "failed", "approver_not_in_quorum", a_root)
    if (
        a_cust_key in prior_root_keys
        or a_cust_key in prior_recovery_keys
        or a_cust_key in agent_principal_keys
    ):
        return _finding(2, app_rec.ref, "start", "failed", "approver_not_in_quorum", a_cust_key)

    cust_list = t_terms.get("custodians")
    c_entry: dict[str, Any] | None = None
    if isinstance(cust_list, list):
        for entry in cust_list:
            if entry.get("identity") == a_custodian:
                c_entry = entry
                break
    if c_entry is None:
        return _finding(2, app_rec.ref, "start", "failed", "approver_not_in_quorum", a_custodian)

    if "key" in c_entry:
        if a_cust_key != c_entry["key"]:
            return _finding(
                2, app_rec.ref, "start", "failed", "custodian_key_not_bound", a_cust_key
            )
        return _finding(2, app_rec.ref, "start", "ok", "ok", change_ref)

    # Rows A13–A15: late-bound custodian key via parentless Endorsement E
    t_a = parse_rfc3339_instant(app_rec.payload["capturedAt"])
    t_r = parse_rfc3339_instant(r_rec.payload["capturedAt"])
    assert t_a is not None and t_r is not None

    sealed_before_r: list[OpenedRecord] = []
    unsealed_dated_before_r: list[OpenedRecord] = []

    for e_rec in auth_links_by_ref.values():
        if e_rec.kind_path != ENDORSEMENT_KIND:
            continue
        e_body = e_rec.payload["body"]
        if "parent" in e_body:
            continue
        if (
            e_rec.payload.get("issuer") not in prior_root_keys
            or e_body.get("subject") != a_cust_key
            or e_body.get("actsFor") != a_custodian
            or ROOT_CHANGE_APPROVAL_KIND not in e_body.get("kinds", ())
        ):
            continue
        e_nb = parse_rfc3339_instant(e_body["notBefore"])
        e_na = parse_rfc3339_instant(e_body["notAfter"])
        if e_nb is None or e_na is None or not (e_nb <= t_a <= e_na):
            continue

        # Not revoked at or before R.capturedAt by an entitled root
        revoked_by_root = False
        for rev in revocations_by_target.get(e_rec.ref, ()):
            t_rev = parse_rfc3339_instant(rev.payload.get("capturedAt"))
            if (
                t_rev is not None
                and t_rev <= t_r
                and rev.payload.get("issuer") in prior_root_keys
            ):
                revoked_by_root = True
                break
        if revoked_by_root:
            continue

        if _is_endorsement_sealed_before_change(
            endorsement_rec=e_rec,
            change_time=t_r,
            prior_root_keys=prior_root_keys,
            opened_by_ref=opened_by_ref,
            body_result_by_ref=body_result_by_ref,
            auth_links_by_ref=auth_links_by_ref,
            revocations_by_target=revocations_by_target,
            succ_state=succ_state,
            seal_covered_refs=seal_covered_refs,
        ):
            sealed_before_r.append(e_rec)
        else:
            t_e = parse_rfc3339_instant(e_rec.payload["capturedAt"])
            if t_e is not None and t_e < t_r:
                unsealed_dated_before_r.append(e_rec)

    if sealed_before_r:
        return _finding(2, app_rec.ref, "start", "ok", "ok", change_ref)
    if unsealed_dated_before_r:
        lowest_e = min((e.ref for e in unsealed_dated_before_r), key=lambda r: r.encode("utf-8"))
        return _finding(
            2,
            app_rec.ref,
            "start",
            "incomplete",
            "custodian_key_not_sealed_before_change",
            lowest_e,
        )
    return _finding(2, app_rec.ref, "start", "failed", "custodian_key_not_bound", a_cust_key)


def _build_tenures_from_start_prefix(
    prefix_recs: list[OpenedRecord],
    *,
    initial_admitted_none: bool = False,
) -> dict[str, list[RootTenure]]:
    """Construct root tenures across contiguous valid [S_2, ..., S_m] (A6 Slice 2 §4.2.2)."""
    if not prefix_recs:
        return {}
    open_tenure_by_key: dict[str, Instant | None] = {}
    closed_tenures: dict[str, list[RootTenure]] = {}

    s2 = prefix_recs[0]
    t_s2 = parse_rfc3339_instant(s2.payload["capturedAt"])
    s2_admitted = None if initial_admitted_none else t_s2
    for r_entry in s2.payload["body"]["roots"]:
        open_tenure_by_key[r_entry["key"]] = s2_admitted

    for s_i in prefix_recs[1:]:
        t_si = parse_rfc3339_instant(s_i.payload["capturedAt"])
        assert t_si is not None
        si_keys = {r_entry["key"] for r_entry in s_i.payload["body"]["roots"]}
        for k in list(open_tenure_by_key):
            if k not in si_keys:
                adm = open_tenure_by_key.pop(k)
                closed_tenures.setdefault(k, []).append(RootTenure(k, adm, (t_si, s_i.ref)))
        for k in si_keys:
            if k not in open_tenure_by_key:
                open_tenure_by_key[k] = t_si

    result: dict[str, list[RootTenure]] = {k: list(v) for k, v in closed_tenures.items()}
    for k, adm in open_tenure_by_key.items():
        result.setdefault(k, []).append(RootTenure(k, adm, None))
    return result


def _verify_start_stream(
    *,
    opened_records: list[OpenedRecord],
    opened_by_ref: dict[str, OpenedRecord],
    body_ok_by_ref: dict[str, bool],
    body_result_by_ref: dict[str, str],
    seal_covered_refs: dict[str, set[str]],
    trusted_roots: Sequence[str] | None,
    trusted_chain: str | None,
    min_start_seq: int | None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool, dict[str, list[RootTenure]]]:
    """Run A6 Slice 1 & Slice 2 start checks, report start member, and root tenures."""
    candidate_streams: set[str] = set()
    stream_opened_count: dict[str, int] = {}
    for rec in opened_records:
        s = rec.payload.get("stream")
        if type(s) is str:
            stream_opened_count[s] = stream_opened_count.get(s, 0) + 1
            if CANDIDATE_START_STREAM_RE.match(s) is not None or rec.kind_path in START_STREAM_KINDS:
                candidate_streams.add(s)

    records_by_stream: dict[str, list[OpenedRecord]] = {}
    stream_seq_map: dict[str, dict[int, list[OpenedRecord]]] = {}
    unstreamed_start_records: list[OpenedRecord] = []
    off_stream_approvals: list[OpenedRecord] = []
    approvals_by_change_ref: dict[str, list[OpenedRecord]] = {}

    agent_principal_keys: set[str] = set()
    auth_links_by_ref: dict[str, OpenedRecord] = {}
    auth_successions: list[OpenedRecord] = []
    revocations_by_target: dict[str, list[OpenedRecord]] = {}

    for rec in opened_records:
        if body_ok_by_ref.get(rec.ref, False) and rec.all_signatures_ok:
            if rec.kind_path == PRINCIPAL_KIND:
                pbody = rec.payload.get("body")
                if (
                    isinstance(pbody, dict)
                    and pbody.get("holder") == "agent"
                    and type(pbody.get("key")) is str
                ):
                    agent_principal_keys.add(pbody["key"])
            elif rec.kind_path in (ENDORSEMENT_KIND, BADGE_KIND):
                if _is_link_shape_ok(rec):
                    auth_links_by_ref[rec.ref] = rec
            elif rec.kind_path == SUCCESSION_KIND:
                auth_successions.append(rec)
            elif rec.kind_path == REVOCATION_KIND:
                rbody = rec.payload.get("body")
                if isinstance(rbody, dict) and type(rbody.get("target")) is str:
                    revocations_by_target.setdefault(rbody["target"], []).append(rec)

        s = rec.payload.get("stream")
        if type(s) is str and s in candidate_streams:
            records_by_stream.setdefault(s, []).append(rec)
            seq = rec.payload.get("seq")
            if type(seq) is int:
                stream_seq_map.setdefault(s, {}).setdefault(seq, []).append(rec)
        elif type(s) is not str and rec.kind_path in START_STREAM_KINDS:
            unstreamed_start_records.append(rec)
        elif rec.kind_path == ROOT_CHANGE_APPROVAL_KIND:
            off_stream_approvals.append(rec)
            abody = rec.payload.get("body")
            if isinstance(abody, dict) and type(abody.get("change")) is str:
                approvals_by_change_ref.setdefault(abody["change"], []).append(rec)

    succ_state = _SuccessionState(auth_successions)

    stream_start_findings: list[dict[str, Any]] = []
    approval_start_findings: list[dict[str, Any]] = []
    evaluated_approval_refs: set[str] = set()
    start_result_by_ref: dict[str, str] = {}
    start_code_by_ref: dict[str, str] = {}
    emitted_chain_mismatch = False
    emitted_multiple_streams = False
    trusted_root_set = set(trusted_roots) if trusted_roots is not None else None

    def evaluate_approval_once(app_rec: OpenedRecord) -> None:
        if app_rec.ref in evaluated_approval_refs:
            return
        evaluated_approval_refs.add(app_rec.ref)
        af = _verify_root_change_approval(
            app_rec=app_rec,
            candidate_streams=candidate_streams,
            stream_seq_map=stream_seq_map,
            stream_opened_count=stream_opened_count,
            opened_by_ref=opened_by_ref,
            body_ok_by_ref=body_ok_by_ref,
            body_result_by_ref=body_result_by_ref,
            start_result_by_ref=start_result_by_ref,
            start_code_by_ref=start_code_by_ref,
            agent_principal_keys=agent_principal_keys,
            auth_links_by_ref=auth_links_by_ref,
            revocations_by_target=revocations_by_target,
            succ_state=succ_state,
            seal_covered_refs=seal_covered_refs,
        )
        approval_start_findings.append(af)
        start_result_by_ref[app_rec.ref] = af["result"]
        start_code_by_ref[app_rec.ref] = af["code"]

    for rec in unstreamed_start_records:
        raw_seq = rec.payload.get("seq")
        seq_about = f"seq:{raw_seq}" if type(raw_seq) is int else None
        if len(candidate_streams) > 1:
            lowest_uri = min(candidate_streams, key=lambda u: u.encode("utf-8"))
            emitted_multiple_streams = True
            f = _finding(2, rec.ref, "start", "failed", "multiple_start_streams", lowest_uri)
        else:
            f = _finding(2, rec.ref, "start", "failed", "wrong_start_position", seq_about)
        stream_start_findings.append(f)
        start_result_by_ref[rec.ref] = f["result"]
        start_code_by_ref[rec.ref] = f["code"]

    for r_stream in sorted(candidate_streams, key=lambda u: u.encode("utf-8")):
        seq_map = stream_seq_map.get(r_stream, {})
        ordered_recs = sorted(
            records_by_stream[r_stream],
            key=lambda r: (
                (0, r.payload["seq"]) if type(r.payload.get("seq")) is int else (1, 0)
            ),
        )
        spent_recovery_keys: set[str] = set()

        for rec in ordered_recs:
            raw_seq = rec.payload.get("seq")
            r_seq_int: int | None = raw_seq if type(raw_seq) is int else None
            kpath = rec.kind_path

            if len(candidate_streams) > 1:
                other_lowest = min(
                    (u for u in candidate_streams if u != r_stream),
                    key=lambda u: u.encode("utf-8"),
                )
                emitted_multiple_streams = True
                f = _finding(2, rec.ref, "start", "failed", "multiple_start_streams", other_lowest)
            elif kpath not in START_STREAM_KINDS:
                f = _finding(2, rec.ref, "start", "failed", "not_a_start_record", kpath)
            elif (
                VALID_START_STREAM_RE.match(r_stream) is None
                or (kpath == CHAIN_STARTED_KIND and r_seq_int != 1)
                or (kpath == DEPLOYMENT_KIND and r_seq_int != 2)
                or (kpath == ROOTS_CHANGED_KIND and (r_seq_int is None or r_seq_int < 3))
            ):
                seq_about = f"seq:{r_seq_int}" if r_seq_int is not None else None
                f = _finding(2, rec.ref, "start", "failed", "wrong_start_position", seq_about)
            elif r_seq_int is not None and len(seq_map.get(r_seq_int, [])) >= 2:
                f = _finding(2, rec.ref, "start", "failed", "forked_start_stream", f"seq:{r_seq_int}")
            elif body_result_by_ref.get(rec.ref) == "failed" or rec.any_signature_failed:
                f = _finding(2, rec.ref, "start", "failed", "invalid_start_record", None)
            elif body_result_by_ref.get(rec.ref) == "incomplete" or not rec.all_signatures_ok:
                f = _finding(2, rec.ref, "start", "incomplete", "unverified_start_record", None)
            elif not _has_expected_start_record_shape(rec):
                f = _finding(2, rec.ref, "start", "failed", "invalid_start_record", None)
            elif kpath == CHAIN_STARTED_KIND:
                r_body = rec.payload["body"]
                expected_stream = f"urn:r5e:stream:{r_body['deployment']}:start"
                def_kinds = [item["kind"] for item in r_body["definitions"]]
                if r_stream != expected_stream:
                    f = _finding(2, rec.ref, "start", "failed", "deployment_stream_mismatch", r_stream)
                elif len(set(def_kinds)) != len(def_kinds):
                    f = _finding(2, rec.ref, "start", "failed", "invalid_start_record", None)
                elif not seq_map.get(2):
                    f = _finding(2, rec.ref, "start", "incomplete", "deployment_not_carried", None)
                else:
                    f = _finding(2, rec.ref, "start", "ok", "ok", r_body["bootstrap"])
            elif kpath == DEPLOYMENT_KIND:
                r_body = rec.payload["body"]
                accepts_ref: str = r_body["accepts"]
                recs_at_1 = seq_map.get(1, [])
                if not _deployment_terms_valid(r_body, require_claimed_by=True):
                    f = _finding(2, rec.ref, "start", "failed", "invalid_deployment_terms", None)
                elif rec.payload.get("previous") != accepts_ref:
                    f = _finding(
                        2, rec.ref, "start", "failed", "accepts_is_not_chain_started", accepts_ref
                    )
                elif not recs_at_1:
                    f = _finding(
                        2, rec.ref, "start", "incomplete", "chain_started_not_carried", accepts_ref
                    )
                else:
                    matching_c = [c for c in recs_at_1 if c.ref == accepts_ref]
                    c_rec = (
                        matching_c[0]
                        if matching_c
                        else min(recs_at_1, key=lambda c: c.ref.encode("utf-8"))
                    )
                    c_start_res = start_result_by_ref.get(c_rec.ref)
                    c_raw_body = c_rec.payload.get("body")
                    c_bootstrap = (
                        c_raw_body.get("bootstrap") if isinstance(c_raw_body, dict) else None
                    )
                    if c_rec.ref != accepts_ref or c_start_res == "failed":
                        f = _finding(
                            2, rec.ref, "start", "failed", "accepts_is_not_chain_started", c_rec.ref
                        )
                    elif (
                        body_ok_by_ref.get(c_rec.ref, False)
                        and type(c_bootstrap) is str
                        and r_body["bootstrap"] != c_bootstrap
                    ):
                        f = _finding(
                            2, rec.ref, "start", "failed", "bootstrap_signer_mismatch", c_bootstrap
                        )
                    elif c_start_res == "incomplete":
                        f = _finding(
                            2, rec.ref, "start", "incomplete", "unverified_start_record", c_rec.ref
                        )
                    elif trusted_chain is not None and rec.ref != trusted_chain:
                        emitted_chain_mismatch = True
                        f = _finding(
                            2, rec.ref, "start", "failed", "chain_mismatch", trusted_chain
                        )
                    elif not (
                        trusted_chain == rec.ref
                        or (trusted_root_set is not None and r_body["claimedBy"] in trusted_root_set)
                    ):
                        f = _finding(
                            2, rec.ref, "start", "incomplete", "chain_not_trusted", rec.ref
                        )
                    else:
                        f = _finding(2, rec.ref, "start", "ok", "ok", c_rec.ref)
            else:
                # kpath == ROOTS_CHANGED_KIND at seq = n >= 3 (A6 Slice 2 §3.4 Rows 20–35)
                assert r_seq_int is not None and r_seq_int >= 3
                r_body = rec.payload["body"]
                replaces_ref: str = r_body["replaces"]
                auth_mode: str = r_body["authorization"]
                spent_at_n = (
                    spent_recovery_keys | {r_body["signer"]}
                    if auth_mode == "recovery"
                    else set(spent_recovery_keys)
                )
                spent_recovery_keys = spent_at_n

                for app_rec in approvals_by_change_ref.get(rec.ref, ()):
                    evaluate_approval_once(app_rec)

                recs_at_prev = seq_map.get(r_seq_int - 1, [])
                if not _deployment_terms_valid(r_body, require_claimed_by=False):
                    f = _finding(2, rec.ref, "start", "failed", "invalid_deployment_terms", None)
                elif rec.payload.get("previous") != replaces_ref:
                    f = _finding(
                        2, rec.ref, "start", "failed", "replaces_is_not_prior_start", replaces_ref
                    )
                elif not recs_at_prev:
                    f = _finding(
                        2, rec.ref, "start", "incomplete", "prior_start_not_carried", replaces_ref
                    )
                else:
                    matching_p = [p for p in recs_at_prev if p.ref == replaces_ref]
                    p_rec = (
                        matching_p[0]
                        if matching_p
                        else min(recs_at_prev, key=lambda p: p.ref.encode("utf-8"))
                    )
                    p_start_res = start_result_by_ref.get(p_rec.ref)
                    p_start_code = start_code_by_ref.get(p_rec.ref)
                    p_body_ok = body_ok_by_ref.get(p_rec.ref, False) and _has_expected_start_record_shape(
                        p_rec
                    )
                    d_ref: str | None = None
                    if p_body_ok:
                        d_ref = (
                            p_rec.ref
                            if r_seq_int == 3
                            else p_rec.payload["body"].get("chain")
                        )
                    t_r = parse_rfc3339_instant(rec.payload.get("capturedAt"))
                    t_p = parse_rfc3339_instant(p_rec.payload.get("capturedAt")) if p_body_ok else None

                    if p_rec.ref != replaces_ref or p_start_res == "failed":
                        f = _finding(
                            2, rec.ref, "start", "failed", "replaces_is_not_prior_start", p_rec.ref
                        )
                    elif p_body_ok and type(d_ref) is str and r_body["chain"] != d_ref:
                        f = _finding(2, rec.ref, "start", "failed", "start_chain_mismatch", d_ref)
                    elif p_body_ok and t_r is not None and t_p is not None and t_r < t_p:
                        f = _finding(
                            2, rec.ref, "start", "failed", "start_timestamp_regression", p_rec.ref
                        )
                    elif p_start_res == "incomplete" and p_start_code not in (
                        "chain_not_trusted",
                        "new_roots_not_trusted",
                    ):
                        f = _finding(
                            2, rec.ref, "start", "incomplete", "unverified_start_record", p_rec.ref
                        )
                    else:
                        p_body = p_rec.payload["body"]
                        p_rec_keys = p_body.get("recoveryKeys")
                        r_rec_keys = r_body.get("recoveryKeys")
                        spent_overlap = (
                            [k for k in r_rec_keys if k in spent_at_n]
                            if isinstance(r_rec_keys, list)
                            else []
                        )
                        p_root_keys = {r["key"] for r in p_body["roots"]}
                        p_custodians = p_body.get("custodians")
                        p_threshold: int = p_body["threshold"]

                        # Compute veto-free quorum_count when authorization == "quorum"
                        quorum_count = 0
                        if auth_mode == "quorum":
                            by_root: dict[str, set[tuple[str, str]]] = {}
                            roots_for_custodian: dict[str, set[str]] = {}
                            roots_for_cust_key: dict[str, set[str]] = {}
                            for app_rec in approvals_by_change_ref.get(rec.ref, ()):
                                if start_result_by_ref.get(app_rec.ref) != "ok":
                                    continue
                                ab = app_rec.payload["body"]
                                ar: str = ab["root"]
                                ac: str = ab["custodian"]
                                ak: str = ab["custodianKey"]
                                by_root.setdefault(ar, set()).add((ac, ak))
                                roots_for_custodian.setdefault(ac, set()).add(ar)
                                roots_for_cust_key.setdefault(ak, set()).add(ar)
                            for ar, pairs in by_root.items():
                                if len(pairs) != 1:
                                    continue
                                ac, ak = next(iter(pairs))
                                if (
                                    roots_for_custodian[ac] != {ar}
                                    or roots_for_cust_key[ak] != {ar}
                                ):
                                    continue
                                quorum_count += 1

                        if auth_mode == "recovery" and (
                            not isinstance(p_rec_keys, list) or r_body["signer"] not in p_rec_keys
                        ):
                            f = _finding(
                                2,
                                rec.ref,
                                "start",
                                "failed",
                                "unauthorized_recovery_signer",
                                r_body["signer"],
                            )
                        elif spent_overlap:
                            lowest_spent = min(spent_overlap, key=lambda k: k.encode("utf-8"))
                            f = _finding(
                                2,
                                rec.ref,
                                "start",
                                "failed",
                                "spent_recovery_key_retained",
                                lowest_spent,
                            )
                        elif auth_mode == "quorum" and r_body["signer"] not in p_root_keys:
                            f = _finding(
                                2, rec.ref, "start", "failed", "proposer_not_a_root", r_body["signer"]
                            )
                        elif auth_mode == "quorum" and (
                            not isinstance(p_custodians, list) or len(p_custodians) < p_threshold
                        ):
                            f = _finding(
                                2, rec.ref, "start", "failed", "quorum_not_configured", None
                            )
                        elif auth_mode == "quorum" and quorum_count < p_threshold:
                            f = _finding(
                                2,
                                rec.ref,
                                "start",
                                "incomplete",
                                "quorum_not_carried",
                                f"need:{p_threshold}",
                            )
                        elif trusted_chain is not None and r_body["chain"] != trusted_chain:
                            emitted_chain_mismatch = True
                            f = _finding(
                                2, rec.ref, "start", "failed", "chain_mismatch", trusted_chain
                            )
                        elif trusted_chain is None and trusted_root_set is not None and any(
                            r["key"] not in trusted_root_set for r in r_body["roots"]
                        ):
                            untrusted_new = [
                                r["key"]
                                for r in r_body["roots"]
                                if r["key"] not in trusted_root_set
                            ]
                            lowest_untrusted = min(untrusted_new, key=lambda k: k.encode("utf-8"))
                            f = _finding(
                                2,
                                rec.ref,
                                "start",
                                "incomplete",
                                "new_roots_not_trusted",
                                lowest_untrusted,
                            )
                        elif trusted_chain is None and trusted_root_set is None:
                            f = _finding(
                                2,
                                rec.ref,
                                "start",
                                "incomplete",
                                "chain_not_trusted",
                                r_body["chain"],
                            )
                        else:
                            f = _finding(2, rec.ref, "start", "ok", "ok", p_rec.ref)

            stream_start_findings.append(f)
            start_result_by_ref[rec.ref] = f["result"]
            start_code_by_ref[rec.ref] = f["code"]

    # Evaluate any remaining off-start-stream RootChangeApproval records
    for app_rec in off_stream_approvals:
        evaluate_approval_once(app_rec)

    # A6 §2.3 & Slice 2 §2.2: Top-level report "start" member
    start_report_member: dict[str, Any] | None = None
    contig_ok_head = 0
    if len(candidate_streams) == 1:
        sole_stream = next(iter(candidate_streams))
        s_map = stream_seq_map.get(sole_stream, {})
        while True:
            recs_at_k = s_map.get(contig_ok_head + 1, [])
            if len(recs_at_k) == 1 and start_result_by_ref.get(recs_at_k[0].ref) == "ok":
                contig_ok_head += 1
            else:
                break
        if contig_ok_head >= 1:
            pos1_rec = s_map[1][0]
            head_rec = s_map[contig_ok_head][0]
            chain_ref = s_map[2][0].ref if contig_ok_head >= 2 else None
            start_report_member = {
                "chain": chain_ref,
                "deployment": pos1_rec.payload["body"]["deployment"],
                "headCapturedAt": head_rec.payload["capturedAt"],
                "headRef": head_rec.ref,
                "headSeq": contig_ok_head,
                "stream": sole_stream,
            }

    # A6 §4.3: Reader-pin completeness findings (part of candidate start-stream establishment)
    if trusted_chain is not None:
        pinned_rec = opened_by_ref.get(trusted_chain)
        has_pinned_deployment = (
            pinned_rec is not None and pinned_rec.kind_path == DEPLOYMENT_KIND
        )
        if (
            not has_pinned_deployment
            and not emitted_chain_mismatch
            and not emitted_multiple_streams
        ):
            stream_start_findings.append(
                _finding(2, trusted_chain, "start", "incomplete", "chain_start_not_carried", None)
            )

    any_stream_start_failed = any(f["result"] == "failed" for f in stream_start_findings)
    if min_start_seq is not None and contig_ok_head < min_start_seq and not any_stream_start_failed:
        min_subj = next(iter(candidate_streams)) if len(candidate_streams) == 1 else "bundle"
        stream_start_findings.append(
            _finding(
                2,
                min_subj,
                "start",
                "incomplete",
                "start_below_minimum_position",
                f"seq:{min_start_seq}",
            )
        )

    any_stream_start_incomplete = any(f["result"] == "incomplete" for f in stream_start_findings)

    # A6 Slice 2 §4.2: Construct root tenures for A5
    a5_incomplete_chain = False
    tenures_by_key: dict[str, list[RootTenure]] = {}

    if trusted_chain is not None:
        if any_stream_start_failed:
            tenures_by_key = {}
        elif any_stream_start_incomplete:
            a5_incomplete_chain = True
        else:
            pinned_dep = opened_by_ref.get(trusted_chain)
            if (
                pinned_dep is not None
                and pinned_dep.kind_path == DEPLOYMENT_KIND
                and start_result_by_ref.get(pinned_dep.ref) == "ok"
                and len(candidate_streams) == 1
                and contig_ok_head >= 2
            ):
                sole_stream = next(iter(candidate_streams))
                s_map = stream_seq_map.get(sole_stream, {})
                prefix = [s_map[i][0] for i in range(2, contig_ok_head + 1)]
                tenures_by_key = _build_tenures_from_start_prefix(
                    prefix, initial_admitted_none=False
                )
            else:
                a5_incomplete_chain = True
    elif trusted_root_set is not None:
        if not any_stream_start_failed and len(candidate_streams) == 1:
            sole_stream = next(iter(candidate_streams))
            s_map = stream_seq_map.get(sole_stream, {})
            recs_2 = s_map.get(2, [])
            if len(recs_2) == 1 and start_result_by_ref.get(recs_2[0].ref) == "ok":
                m = 2
                while True:
                    nxt = s_map.get(m + 1, [])
                    if len(nxt) == 1 and start_code_by_ref.get(nxt[0].ref) in (
                        "ok",
                        "new_roots_not_trusted",
                    ):
                        m += 1
                    else:
                        break
                prefix = [s_map[i][0] for i in range(2, m + 1)]
                prefix_tenures = _build_tenures_from_start_prefix(
                    prefix, initial_admitted_none=True
                )
                for rk in trusted_root_set:
                    if rk in prefix_tenures:
                        tenures_by_key[rk] = prefix_tenures[rk]
                    else:
                        tenures_by_key[rk] = [RootTenure(rk, None, None)]
            else:
                for rk in trusted_root_set:
                    tenures_by_key[rk] = [RootTenure(rk, None, None)]
        else:
            for rk in trusted_root_set:
                tenures_by_key[rk] = [RootTenure(rk, None, None)]

    all_start_findings = stream_start_findings + approval_start_findings
    return all_start_findings, start_report_member, a5_incomplete_chain, tenures_by_key


# ---------------------------------------------------------------------------
# §6.3a Authority From Trusted Roots (Amendment A5, §§1–7 + A6 Slice 2 §4)
# ---------------------------------------------------------------------------



class _SuccessionState:
    """Resolved non-root succession stand-in graph and predecessor endings (A5 §7 + A6 Slice 2 §4.1)."""

    def __init__(self, successions: list[OpenedRecord]) -> None:
        self.clean_next: dict[str, tuple[str, Instant, str]] = {}
        self.key_ending: dict[str, tuple[Instant, str]] = {}

        # Multi-graph of all valid Succession authority records: pred -> list of (t, ref, succ)
        all_out: dict[str, list[tuple[Instant, str, str]]] = {}
        for rec in successions:
            body = rec.payload["body"]
            pred: str = body["predecessor"]
            succ: str = body["successor"]
            t = parse_rfc3339_instant(rec.payload["capturedAt"])
            if t is None:
                continue
            all_out.setdefault(pred, []).append((t, rec.ref, succ))

        for edges in all_out.values():
            edges.sort(key=lambda item: (item[0], item[1].encode("utf-8")))

        # Step 1 (A5 §7): Forks end predecessor at the earlier succession and grant stand-in to neither.
        single_out: dict[str, tuple[str, Instant, str]] = {}
        for pred, edges in all_out.items():
            distinct_succs = {succ for _, _, succ in edges}
            earliest_t, earliest_ref, sole_succ = edges[0]
            if len(distinct_succs) > 1:
                self.key_ending[pred] = (earliest_t, earliest_ref)
            else:
                single_out[pred] = (sole_succ, earliest_t, earliest_ref)

        # Step 2 (A5 §7): Detect loops in `single_out`.
        on_loop: set[str] = set()
        state: dict[str, int] = {}  # 0 = visiting, 1 = done
        for start in sorted(single_out):
            if start in state:
                continue
            path: list[str] = []
            idx_in_path: dict[str, int] = {}
            cur: str | None = start
            while cur is not None and cur in single_out and cur not in state:
                state[cur] = 0
                idx_in_path[cur] = len(path)
                path.append(cur)
                nxt, _, _ = single_out[cur]
                if nxt in idx_in_path:
                    loop_keys = path[idx_in_path[nxt] :]
                    min_edge = min(
                        ((single_out[k][1], single_out[k][2]) for k in loop_keys),
                        key=lambda item: (item[0], item[1].encode("utf-8")),
                    )
                    for k in loop_keys:
                        on_loop.add(k)
                        self.key_ending[k] = min_edge
                    break
                cur = nxt
            for visited_key in path:
                state[visited_key] = 1

        # Step 3: Keys in `single_out` not on any loop keep their own hand-over and stand-in edge.
        for pred, (sole_succ, earliest_t, earliest_ref) in single_out.items():
            if pred not in on_loop:
                self.key_ending[pred] = (earliest_t, earliest_ref)
                self.clean_next[pred] = (sole_succ, earliest_t, earliest_ref)

    def same_or_stands_in_for(self, actor_key: str, role_key: str, at_time: Instant) -> bool:
        """True if actor_key == role_key or actor_key succeeds role_key in <= 16 steps all <= at_time."""
        if actor_key == role_key:
            return True
        if role_key not in self.clean_next:
            return False
        cur = role_key
        for _ in range(16):
            step = self.clean_next.get(cur)
            if step is None:
                return False
            nxt, t_step, _ = step
            if at_time < t_step:
                return False
            if nxt == actor_key:
                return True
            cur = nxt
        return False


def _tenures_for_root_act(
    key: str,
    t_act: Instant,
    tenures_by_key: dict[str, list[RootTenure]],
) -> list[RootTenure]:
    """Return tenures of `key` whose `admitted_at <= t_act` (None means -∞)."""
    return [
        ten
        for ten in tenures_by_key.get(key, ())
        if ten.admitted_at is None or t_act >= ten.admitted_at
    ]


def _latest_tenure(matching: list[RootTenure]) -> RootTenure:
    """Return tenure with latest `admitted_at` among non-empty `matching`."""
    return max(
        matching,
        key=lambda ten: (1, ten.admitted_at) if ten.admitted_at is not None else (0, (0, "")),
    )


def _evaluate_root_act(
    rec: OpenedRecord,
    tenures_by_key: dict[str, list[RootTenure]],
    seal_times_by_ref: dict[str, list[Instant]],
    *,
    actor_key: str | None = None,
) -> tuple[str, str | None]:
    """Evaluate a root act `rec` against `tenures_by_key` (A6 Slice 2 §4.3.1 & §4.3.2).

    Returns `(status, ending_ref)` where `status` is one of:
    - `'no_tenure'` (`no_standing`)
    - `'before_tenure'` (`not_covered`)
    - `'ok'`
    - `'ended'` (`ending_ref` set)
    - `'clock_only'` (`ending_ref` set)
    """
    issuer = actor_key if actor_key is not None else rec.payload.get("issuer")
    if type(issuer) is not str or not tenures_by_key.get(issuer):
        return "no_tenure", None
    t_act = parse_rfc3339_instant(rec.payload.get("capturedAt"))
    if t_act is None:
        return "before_tenure", None

    matching = _tenures_for_root_act(issuer, t_act, tenures_by_key)
    if not matching:
        return "before_tenure", None
    if any(ten.ended_by is None for ten in matching):
        return "ok", None

    t_latest = _latest_tenure(matching)
    assert t_latest.ended_by is not None
    e_time, e_ref = t_latest.ended_by
    if any(s < e_time for s in seal_times_by_ref.get(rec.ref, ())):
        return "ok", None
    if t_act >= e_time:
        return "ended", e_ref
    return "clock_only", e_ref


def _is_link_shape_ok(rec: OpenedRecord) -> bool:
    """Validate that an Endorsement or Badge has readable §3/§4 link fields and is not self-issued."""
    if rec.kind_path not in (ENDORSEMENT_KIND, BADGE_KIND):
        return False
    payload = rec.payload
    issuer = payload.get("issuer")
    t_cap = parse_rfc3339_instant(payload.get("capturedAt"))
    body = payload.get("body")
    if type(issuer) is not str or t_cap is None or not isinstance(body, dict):
        return False
    subject = body.get("subject")
    if type(subject) is not str or subject == issuer:
        return False
    kinds = body.get("kinds")
    if not isinstance(kinds, list) or not kinds or not all(type(k) is str for k in kinds):
        return False
    nb = parse_rfc3339_instant(body.get("notBefore"))
    na = parse_rfc3339_instant(body.get("notAfter"))
    if nb is None or na is None or nb > na:
        return False
    if rec.kind_path == ENDORSEMENT_KIND:
        if type(body.get("mayEndorse")) is not bool:
            return False
        if "parent" in body and type(body.get("parent")) is not str:
            return False
    else:
        if type(body.get("parent")) is not str:
            return False
    for list_field in ("streamPrefixes", "actorPrefixes"):
        if list_field in body:
            val = body[list_field]
            if not isinstance(val, list) or not val or not all(type(s) is str for s in val):
                return False
    return not ("actsFor" in body and type(body.get("actsFor")) is not str)


def _link_covers_record_any_window(link: OpenedRecord, rec: OpenedRecord) -> bool:
    """Check A5 §3 link coverage over `rec` ignoring `[notBefore, notAfter]` (for §4.4 Condition 3)."""
    rec_kind = rec.kind_path
    if rec_kind is None:
        return False
    lbody = link.payload["body"]
    if rec_kind not in lbody["kinds"]:
        return False

    if "streamPrefixes" in lbody:
        if rec_kind == EPOCH_SEAL_KIND:
            rbody = rec.payload.get("body")
            stream = rbody.get("stream") if isinstance(rbody, dict) else None
        else:
            stream = rec.payload.get("stream")
        if type(stream) is not str or not any(
            stream.startswith(p) for p in lbody["streamPrefixes"]
        ):
            return False

    if "actorPrefixes" in lbody:
        actor = rec.payload.get("actor")
        if type(actor) is not str or not any(
            actor.startswith(p) for p in lbody["actorPrefixes"]
        ):
            return False

    if "actsFor" in lbody:
        obo = rec.payload.get("onBehalfOf")
        if type(obo) is not str or obo != lbody["actsFor"]:
            return False

    return True


def _link_covers_record(link: OpenedRecord, rec: OpenedRecord) -> bool:
    """Check A5 §3 link coverage over a target record."""
    if not _link_covers_record_any_window(link, rec):
        return False
    lbody = link.payload["body"]
    t_rec = parse_rfc3339_instant(rec.payload.get("capturedAt"))
    nb = parse_rfc3339_instant(lbody["notBefore"])
    na = parse_rfc3339_instant(lbody["notAfter"])
    return t_rec is not None and nb is not None and na is not None and (nb <= t_rec <= na)


def _child_continues_parent(
    parent: OpenedRecord,
    child: OpenedRecord,
    succ_state: _SuccessionState,
) -> bool:
    """Check A5 §4.2, §4.3, §4.5, §4.6, and §4.7 between adjacent parent and child links."""
    if parent.kind_path != ENDORSEMENT_KIND or parent.ref == child.ref:
        return False
    if not _is_link_shape_ok(parent) or not _is_link_shape_ok(child):
        return False
    pbody = parent.payload["body"]
    cbody = child.payload["body"]
    if pbody.get("mayEndorse") is not True:
        return False
    if cbody.get("parent") != parent.ref:
        return False

    t_child = parse_rfc3339_instant(child.payload["capturedAt"])
    p_nb = parse_rfc3339_instant(pbody["notBefore"])
    p_na = parse_rfc3339_instant(pbody["notAfter"])
    c_nb = parse_rfc3339_instant(cbody["notBefore"])
    c_na = parse_rfc3339_instant(cbody["notAfter"])
    if t_child is None or p_nb is None or p_na is None or c_nb is None or c_na is None:
        return False

    if not succ_state.same_or_stands_in_for(child.payload["issuer"], pbody["subject"], t_child):
        return False
    if not (p_nb <= t_child <= p_na):
        return False
    if not (p_nb <= c_nb and c_na <= p_na):
        return False
    if not set(cbody["kinds"]).issubset(set(pbody["kinds"])):
        return False

    if "streamPrefixes" in pbody:
        if "streamPrefixes" not in cbody:
            return False
        if not all(
            any(cp.startswith(pp) for pp in pbody["streamPrefixes"])
            for cp in cbody["streamPrefixes"]
        ):
            return False

    if "actorPrefixes" in pbody:
        if "actorPrefixes" not in cbody:
            return False
        if not all(
            any(ca.startswith(pa) for pa in pbody["actorPrefixes"])
            for ca in cbody["actorPrefixes"]
        ):
            return False

    return not ("actsFor" in pbody and cbody.get("actsFor") != pbody["actsFor"])


def _might_yet_be_valid_grant(
    ref: str,
    opened_by_ref: dict[str, OpenedRecord],
    body_result_by_ref: dict[str, str],
) -> bool:
    """Return True when `ref` might yet be a valid grant (A5 §5)."""
    cand = opened_by_ref.get(ref)
    if cand is None:
        return True
    if cand.kind_path not in (ENDORSEMENT_KIND, BADGE_KIND):
        return False
    body_res = body_result_by_ref.get(ref, "failed")
    if cand.any_signature_failed or body_res == "failed":
        return False
    if cand.all_signatures_ok and body_res == "ok":
        # If authority-stating, already in auth_links_by_ref; otherwise self-issued/ignored.
        return False
    return not (body_res == "ok" and not _is_link_shape_ok(cand))


def _walk_up_from_link(
    bottom_link: OpenedRecord,
    opened_by_ref: dict[str, OpenedRecord],
    body_result_by_ref: dict[str, str],
    auth_links_by_ref: dict[str, OpenedRecord],
    succ_state: _SuccessionState,
    tenures_by_key: dict[str, list[RootTenure]],
    *,
    extra_tail_ref: str | None = None,
) -> tuple[list[OpenedRecord] | None, tuple[list[OpenedRecord], str] | None]:
    """Walk `parent` links upward from `bottom_link`.

    Returns `(full_chain, missing_parent_run)`:
    - `full_chain`: `[L0, ..., bottom_link]` if rooted at a tenured root (`admitted_at <= L0.capturedAt`).
    - `missing_parent_run`: `([Lk, ..., bottom_link], missing_ref)` if `Lk.parent` might yet be
      a valid grant (§5) and total links (plus `extra_tail_ref` if set) <= 15.
    """
    max_links = 15 if extra_tail_ref is not None else 16
    seen: set[str] = {bottom_link.ref}
    if extra_tail_ref is not None:
        seen.add(extra_tail_ref)

    run_rev: list[OpenedRecord] = [bottom_link]
    curr = bottom_link

    while "parent" in curr.payload["body"]:
        p_ref: str = curr.payload["body"]["parent"]
        p_link = auth_links_by_ref.get(p_ref)
        if p_link is None:
            max_carried_for_missing = 14 if extra_tail_ref is not None else 15
            if (
                p_ref not in seen
                and len(run_rev) <= max_carried_for_missing
                and _might_yet_be_valid_grant(p_ref, opened_by_ref, body_result_by_ref)
            ):
                return None, (list(reversed(run_rev)), p_ref)
            return None, None

        if (
            p_ref in seen
            or len(run_rev) >= max_links
            or not _child_continues_parent(p_link, curr, succ_state)
        ):
            return None, None

        seen.add(p_ref)
        run_rev.append(p_link)
        curr = p_link

    # Reached a link with no `parent`: check §4.1 & A6 Slice 2 §4.3.1
    t_top = parse_rfc3339_instant(curr.payload["capturedAt"])
    if (
        curr.kind_path == ENDORSEMENT_KIND
        and t_top is not None
        and bool(_tenures_for_root_act(curr.payload["issuer"], t_top, tenures_by_key))
    ):
        return list(reversed(run_rev)), None
    return None, None


def _compare_step_with_ending(
    step_rec: OpenedRecord,
    ending_ref: str,
    ending_time: Instant,
    ending_kind: str,
    seal_times_by_ref: dict[str, list[Instant]],
) -> str:
    """Compare one step against one ending (A5 §6): returns 'precedes', 'applies', or 'clock_only'."""
    t = parse_rfc3339_instant(step_rec.payload.get("capturedAt"))
    if t is None:
        return "applies"
    e = ending_time

    step_seals = seal_times_by_ref.get(step_rec.ref, [])
    if ending_kind == "above":
        if any(s < e for s in step_seals):
            return "precedes"
        if t >= e:
            return "applies"
        return "clock_only"

    # ending_kind == "self"
    ending_seals = seal_times_by_ref.get(ending_ref, [])
    first_seals = [s for s in step_seals if not any(s_e <= s for s_e in ending_seals)]
    if any(s < e for s in first_seals):
        return "precedes"
    if t >= e and not first_seals:
        return "applies"
    return "clock_only"


def _revoker_active_at(
    rev_rec: OpenedRecord,
    succ_state: _SuccessionState,
    seal_times_by_ref: dict[str, list[Instant]],
) -> bool:
    """Check A5 §6 for non-root revokers: if revoker handed over, must be shown to precede hand-over."""
    issuer = rev_rec.payload.get("issuer")
    t_rev = parse_rfc3339_instant(rev_rec.payload.get("capturedAt"))
    if type(issuer) is not str or t_rev is None:
        return False
    k_end = succ_state.key_ending.get(issuer)
    if k_end is not None:
        e_time, e_ref = k_end
        if _compare_step_with_ending(rev_rec, e_ref, e_time, "self", seal_times_by_ref) != "precedes":
            return False
    return True


def _is_revoker_entitled(
    rev_rec: OpenedRecord,
    target_link: OpenedRecord,
    opened_by_ref: dict[str, OpenedRecord],
    body_result_by_ref: dict[str, str],
    auth_links_by_ref: dict[str, OpenedRecord],
    succ_state: _SuccessionState,
    tenures_by_key: dict[str, list[RootTenure]],
    seal_times_by_ref: dict[str, list[Instant]],
) -> tuple[bool, bool, str | None]:
    """Return `(entitled, from_above, missing_ancestor_ref)` for `rev_rec` revoking `target_link`."""
    rev_issuer = rev_rec.payload.get("issuer")
    t_rev = parse_rfc3339_instant(rev_rec.payload.get("capturedAt"))
    if type(rev_issuer) is not str or t_rev is None:
        return False, False, None

    non_root_above_keys: set[str] = set()
    if "parent" in target_link.payload["body"]:
        non_root_above_keys.add(target_link.payload["issuer"])

    seen: set[str] = {target_link.ref}
    curr = target_link
    missing_ancestor_ref: str | None = None
    while "parent" in curr.payload["body"]:
        p_ref: str = curr.payload["body"]["parent"]
        p_link = auth_links_by_ref.get(p_ref)
        if p_link is None:
            if (
                p_ref not in seen
                and len(seen) <= 15
                and _might_yet_be_valid_grant(p_ref, opened_by_ref, body_result_by_ref)
            ):
                missing_ancestor_ref = p_ref
            break
        if (
            p_ref in seen
            or len(seen) >= 16
            or not _child_continues_parent(p_link, curr, succ_state)
        ):
            break
        if "parent" in p_link.payload["body"]:
            non_root_above_keys.add(p_link.payload["issuer"])
        seen.add(p_ref)
        curr = p_link

    reaches_deployment_root = (
        "parent" not in curr.payload["body"]
        and curr.kind_path == ENDORSEMENT_KIND
        and bool(tenures_by_key.get(curr.payload["issuer"]))
    )

    # A6 Slice 2 §4.3.2: Deployment-root revocation across root tenures
    is_active_deployment_root = (
        bool(tenures_by_key.get(rev_issuer))
        and _evaluate_root_act(rev_rec, tenures_by_key, seal_times_by_ref)[0] == "ok"
    )
    if is_active_deployment_root and reaches_deployment_root:
        return True, True, None

    # Non-root ancestor issuer or target subject self-revocation
    non_root_active = _revoker_active_at(rev_rec, succ_state, seal_times_by_ref)
    if non_root_active:
        if any(succ_state.same_or_stands_in_for(rev_issuer, ak, t_rev) for ak in non_root_above_keys):
            return True, True, None
        target_subject = target_link.payload["body"]["subject"]
        if succ_state.same_or_stands_in_for(rev_issuer, target_subject, t_rev):
            return True, False, None

    if not is_active_deployment_root and not non_root_active:
        return False, False, None

    return False, False, missing_ancestor_ref


def _chain_has_no_revocation_or_nonroot_succession(
    chain: list[OpenedRecord],
    opened_by_ref: dict[str, OpenedRecord],
    body_result_by_ref: dict[str, str],
    auth_links_by_ref: dict[str, OpenedRecord],
    revocations_by_target: dict[str, list[OpenedRecord]],
    succ_state: _SuccessionState,
    tenures_by_key: dict[str, list[RootTenure]],
    empty_seals: dict[str, list[Instant]],
) -> bool:
    """Return True iff `chain` has no entitled Revocation and no non-root Succession on `chain[1:]`."""
    for link_k in chain:
        for rev in revocations_by_target.get(link_k.ref, ()):
            entitled, _, _ = _is_revoker_entitled(
                rev,
                link_k,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                succ_state,
                tenures_by_key,
                empty_seals,
            )
            if entitled:
                return False
    for child_link in chain[1:]:
        c_signer = child_link.payload.get("issuer")
        if type(c_signer) is str and succ_state.key_ending.get(c_signer) is not None:
            return False
    return True


def _evaluate_steps_endings(
    links: list[OpenedRecord],
    final_step: OpenedRecord,
    revocations_by_target: dict[str, list[OpenedRecord]],
    opened_by_ref: dict[str, OpenedRecord],
    body_result_by_ref: dict[str, str],
    auth_links_by_ref: dict[str, OpenedRecord],
    succ_state: _SuccessionState,
    tenures_by_key: dict[str, list[RootTenure]],
    seal_times_by_ref: dict[str, list[Instant]],
    *,
    final_step_signer: str | None = None,
) -> tuple[int, str | None]:
    """Evaluate root tenures, revocations, and non-root successions over `steps = links + [final_step]`.

    Returns:
    - `(1, None)` when every comparison precedes (or no ending touches)
    - `(2, min_ending_ref)` when none applies and at least one rests on signer's clock
    - `(4, min_ending_ref)` when at least one ending applies
    """
    steps = links + [final_step]
    applying_refs: list[str] = []
    clock_only_refs: list[str] = []

    # 0. Root tenure ending on parentless L0 (links[0], when present with no parent)
    if links and "parent" not in links[0].payload["body"]:
        l0_status, l0_end_ref = _evaluate_root_act(links[0], tenures_by_key, seal_times_by_ref)
        if l0_status == "ended" and l0_end_ref is not None:
            applying_refs.append(l0_end_ref)
        elif l0_status == "clock_only" and l0_end_ref is not None:
            clock_only_refs.append(l0_end_ref)
        elif l0_status in ("no_tenure", "before_tenure"):
            applying_refs.append(links[0].ref)

    # 1. Revocations of Lk (0 <= k < len(links)) compared with every step after Lk: steps[k+1:]
    for k, link_k in enumerate(links):
        for rev in revocations_by_target.get(link_k.ref, ()):
            entitled, from_above, _ = _is_revoker_entitled(
                rev,
                link_k,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                succ_state,
                tenures_by_key,
                seal_times_by_ref,
            )
            if not entitled:
                continue
            t_rev = parse_rfc3339_instant(rev.payload["capturedAt"])
            if t_rev is None:
                continue
            e_kind = "above" if from_above else "self"
            for step_after in steps[k + 1 :]:
                outcome = _compare_step_with_ending(
                    step_after, rev.ref, t_rev, e_kind, seal_times_by_ref
                )
                if outcome == "applies":
                    applying_refs.append(rev.ref)
                elif outcome == "clock_only":
                    clock_only_refs.append(rev.ref)

    # 2. Non-root Successions from P compared with each non-root step that P signed (A6 Slice 2 §4.1)
    for step in steps:
        if step is not final_step and "parent" not in step.payload["body"]:
            continue
        signer = (
            final_step_signer
            if (step is final_step and final_step_signer is not None)
            else step.payload.get("issuer")
        )
        t_step = parse_rfc3339_instant(step.payload.get("capturedAt"))
        if type(signer) is not str or t_step is None:
            continue
        k_end = succ_state.key_ending.get(signer)
        if k_end is None:
            continue
        e_time, e_ref = k_end
        outcome = _compare_step_with_ending(step, e_ref, e_time, "self", seal_times_by_ref)
        if outcome == "applies":
            applying_refs.append(e_ref)
        elif outcome == "clock_only":
            clock_only_refs.append(e_ref)

    if applying_refs:
        return 4, min(applying_refs, key=lambda r: r.encode("utf-8"))
    if clock_only_refs:
        return 2, min(clock_only_refs, key=lambda r: r.encode("utf-8"))
    return 1, None


def _verify_a5_authority(
    *,
    opened_records: list[OpenedRecord],
    opened_by_ref: dict[str, OpenedRecord],
    body_ok_by_ref: dict[str, bool],
    body_result_by_ref: dict[str, str],
    parsed_def_by_ref: dict[str, ParsedDefinition | None],
    seal_covered_refs: dict[str, set[str]],
    tenures_by_key: dict[str, list[RootTenure]],
) -> tuple[list[dict[str, Any]], set[str]]:
    """Compute VERIFY-V2 §6.3a / A5 + A6 Slice 2 §4 + A7 §3 authority findings and qualifying seals."""
    # §1. Collect authority records (signatures all ok and body check ok)
    auth_links_by_ref: dict[str, OpenedRecord] = {}
    auth_successions: list[OpenedRecord] = []
    revocations_by_target: dict[str, list[OpenedRecord]] = {}

    for rec in opened_records:
        if (
            rec.kind_path in (ENDORSEMENT_KIND, BADGE_KIND, SUCCESSION_KIND, REVOCATION_KIND)
            and rec.all_signatures_ok
            and body_ok_by_ref.get(rec.ref, False)
        ):
            if rec.kind_path in (ENDORSEMENT_KIND, BADGE_KIND):
                # §4.7: an endorsement of oneself is ignored
                if _is_link_shape_ok(rec):
                    auth_links_by_ref[rec.ref] = rec
            elif rec.kind_path == SUCCESSION_KIND:
                auth_successions.append(rec)
            elif rec.kind_path == REVOCATION_KIND:
                target_ref = rec.payload["body"]["target"]
                revocations_by_target.setdefault(target_ref, []).append(rec)

    succ_state = _SuccessionState(auth_successions)
    all_valid_links = list(auth_links_by_ref.values())

    def links_for_ordinary_record(rec: OpenedRecord, signer_key: Any = None) -> list[OpenedRecord]:
        signer = signer_key if signer_key is not None else rec.payload.get("issuer")
        t_rec = parse_rfc3339_instant(rec.payload.get("capturedAt"))
        if type(signer) is not str or t_rec is None:
            return []
        matched: list[OpenedRecord] = []
        for link in all_valid_links:
            subj = link.payload["body"]["subject"]
            if link.kind_path == BADGE_KIND:
                if signer != subj:
                    continue
            else:
                if not succ_state.same_or_stands_in_for(signer, subj, t_rec):
                    continue
            if _link_covers_record(link, rec):
                matched.append(link)
        return matched

    # Pass 1 (A5 §6 Condition 3 + A6 Slice 2 §4.4): Determine qualifying corroborating seals.
    empty_seals: dict[str, list[Instant]] = {}
    seal_times_by_ref: dict[str, list[Instant]] = {}
    a5_qualifying_seal_refs: set[str] = set()

    def sealer_vouched_by_open_root(seal_rec: OpenedRecord, seal_issuer: str) -> bool:
        for cand_link in all_valid_links:
            c_subj = cand_link.payload["body"]["subject"]
            if cand_link.kind_path == BADGE_KIND:
                if seal_issuer != c_subj:
                    continue
            else:
                c_na = parse_rfc3339_instant(cand_link.payload["body"]["notAfter"])
                if c_na is None or not succ_state.same_or_stands_in_for(
                    seal_issuer, c_subj, c_na
                ):
                    continue
            if not _link_covers_record_any_window(cand_link, seal_rec):
                continue
            vouch_chain, _ = _walk_up_from_link(
                cand_link,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                succ_state,
                tenures_by_key,
            )
            if vouch_chain is None or not all(
                _link_covers_record_any_window(mlk, seal_rec) for mlk in vouch_chain
            ):
                continue
            m0 = vouch_chain[0]
            t_m0 = parse_rfc3339_instant(m0.payload["capturedAt"])
            if t_m0 is None:
                continue
            m0_matching = _tenures_for_root_act(m0.payload["issuer"], t_m0, tenures_by_key)
            if not any(ten.ended_by is None for ten in m0_matching):
                continue
            if _chain_has_no_revocation_or_nonroot_succession(
                vouch_chain,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                revocations_by_target,
                succ_state,
                tenures_by_key,
                empty_seals,
            ):
                return True
        return False

    for seal_ref, covered_set in seal_covered_refs.items():
        if not covered_set:
            continue
        seal_rec = opened_by_ref.get(seal_ref)
        if seal_rec is None or seal_rec.kind_path != EPOCH_SEAL_KIND or not seal_rec.all_signatures_ok:
            continue
        t_seal = parse_rfc3339_instant(seal_rec.payload.get("capturedAt"))
        s_issuer = seal_rec.payload.get("issuer")
        if t_seal is None or type(s_issuer) is not str:
            continue
        if succ_state.key_ending.get(s_issuer) is not None:
            continue

        qualifies = False
        for bottom_link in links_for_ordinary_record(seal_rec):
            full_chain, _ = _walk_up_from_link(
                bottom_link,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                succ_state,
                tenures_by_key,
            )
            if full_chain is None or not all(_link_covers_record(lk, seal_rec) for lk in full_chain):
                continue
            if not _chain_has_no_revocation_or_nonroot_succession(
                full_chain,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                revocations_by_target,
                succ_state,
                tenures_by_key,
                empty_seals,
            ):
                continue
            l0 = full_chain[0]
            t_l0 = parse_rfc3339_instant(l0.payload["capturedAt"])
            if t_l0 is None:
                continue
            l0_matching = _tenures_for_root_act(l0.payload["issuer"], t_l0, tenures_by_key)
            if not l0_matching:
                continue
            if any(ten.ended_by is None for ten in l0_matching):
                qualifies = True
                break
            t_latest_l0 = _latest_tenure(l0_matching)
            assert t_latest_l0.ended_by is not None
            if t_l0 < t_latest_l0.ended_by[0] and sealer_vouched_by_open_root(seal_rec, s_issuer):
                qualifies = True
                break

        if qualifies:
            a5_qualifying_seal_refs.add(seal_ref)
            for c_ref in covered_set:
                seal_times_by_ref.setdefault(c_ref, []).append(t_seal)

    def has_any_standing(signer: str | None, t_act: Instant | None, rec: OpenedRecord) -> bool:
        if type(signer) is not str:
            return False
        if t_act is None:
            return bool(tenures_by_key.get(signer)) or any(
                lk.payload["body"]["subject"] == signer for lk in all_valid_links
            )
        if tenures_by_key.get(signer):
            r_status, _ = _evaluate_root_act(
                rec, tenures_by_key, seal_times_by_ref, actor_key=signer
            )
            if r_status in ("ok", "clock_only"):
                return True
        for lk in all_valid_links:
            subj = lk.payload["body"]["subject"]
            if subj == signer:
                return True
            if lk.kind_path == ENDORSEMENT_KIND and succ_state.same_or_stands_in_for(
                signer, subj, t_act
            ):
                return True
        return False

    def evaluate_ordinary_signer(
        rec: OpenedRecord, signer_key: str, t_rec: Instant | None
    ) -> tuple[str, str, str | None]:
        row1_abouts: list[str] = []
        row2_abouts: list[str] = []
        row3_abouts: list[str] = []
        row4_abouts: list[str] = []

        for bottom_link in links_for_ordinary_record(rec, signer_key):
            full_chain, missing_run = _walk_up_from_link(
                bottom_link,
                opened_by_ref,
                body_result_by_ref,
                auth_links_by_ref,
                succ_state,
                tenures_by_key,
            )
            if full_chain is not None and all(_link_covers_record(lk, rec) for lk in full_chain):
                row_num, ending_ref = _evaluate_steps_endings(
                    full_chain,
                    rec,
                    revocations_by_target,
                    opened_by_ref,
                    body_result_by_ref,
                    auth_links_by_ref,
                    succ_state,
                    tenures_by_key,
                    seal_times_by_ref,
                    final_step_signer=signer_key,
                )
                if row_num == 1:
                    row1_abouts.append(bottom_link.ref)
                elif row_num == 2 and ending_ref is not None:
                    row2_abouts.append(ending_ref)
                elif row_num == 4 and ending_ref is not None:
                    row4_abouts.append(ending_ref)
            elif missing_run is not None:
                part_links, missing_ref = missing_run
                if all(_link_covers_record(lk, rec) for lk in part_links):
                    row_num, _ = _evaluate_steps_endings(
                        part_links,
                        rec,
                        revocations_by_target,
                        opened_by_ref,
                        body_result_by_ref,
                        auth_links_by_ref,
                        succ_state,
                        tenures_by_key,
                        seal_times_by_ref,
                        final_step_signer=signer_key,
                    )
                    if row_num != 4:
                        row3_abouts.append(missing_ref)

        if row1_abouts:
            best = min(row1_abouts, key=lambda r: r.encode("utf-8"))
            return "ok", "ok", best
        if row2_abouts:
            best = min(row2_abouts, key=lambda r: r.encode("utf-8"))
            return "incomplete", "time_rests_on_the_signer", best
        if row3_abouts:
            best = min(row3_abouts, key=lambda r: r.encode("utf-8"))
            return "incomplete", "chain_not_carried", best
        if row4_abouts:
            best = min(row4_abouts, key=lambda r: r.encode("utf-8"))
            return "failed", "ended", best
        if not has_any_standing(signer_key, t_rec, rec):
            return "failed", "no_standing", signer_key
        return "failed", "not_covered", None

    # Pass 2 (VERIFY-V2 §6.3a–§6.3b / A5 §1 & §5 / A6 Slice 2 §2.1 & §4 / A7 §3.2):
    # Emit one authority finding per opened record not in A5_EXEMPT_KINDS.
    out_findings: list[dict[str, Any]] = []
    for rec in opened_records:
        kpath = rec.kind_path
        if kpath in A5_EXEMPT_KINDS:
            continue

        issuer = rec.payload.get("issuer") if type(rec.payload.get("issuer")) is str else None
        t_rec = parse_rfc3339_instant(rec.payload.get("capturedAt"))
        raw_body = rec.payload.get("body")
        body_dict: dict[str, Any] = raw_body if isinstance(raw_body, dict) else {}

        # Case 1: Revocation (5-row table in A5 §5)
        if kpath == REVOCATION_KIND:
            target_ref = body_dict.get("target") if type(body_dict.get("target")) is str else None
            if target_ref is None:
                out_findings.append(_finding(2, rec.ref, "authority", "failed", "not_covered"))
                continue
            target_auth_link = auth_links_by_ref.get(target_ref)
            if target_auth_link is not None:
                entitled, _, missing_anc = _is_revoker_entitled(
                    rec,
                    target_auth_link,
                    opened_by_ref,
                    body_result_by_ref,
                    auth_links_by_ref,
                    succ_state,
                    tenures_by_key,
                    seal_times_by_ref,
                )
                if entitled:
                    out_findings.append(_finding(2, rec.ref, "authority", "ok", "ok", target_ref))
                elif missing_anc is not None:
                    out_findings.append(
                        _finding(
                            2, rec.ref, "authority", "incomplete", "chain_not_carried", missing_anc
                        )
                    )
                else:
                    out_findings.append(
                        _finding(2, rec.ref, "authority", "failed", "no_standing", issuer)
                    )
                continue

            if _might_yet_be_valid_grant(target_ref, opened_by_ref, body_result_by_ref):
                out_findings.append(
                    _finding(2, rec.ref, "authority", "incomplete", "chain_not_carried", target_ref)
                )
            else:
                out_findings.append(_finding(2, rec.ref, "authority", "failed", "not_covered"))
            continue

        # Case 2: Endorsement or Badge (A5 §5 + A6 Slice 2 §4.3.1)
        if kpath in (ENDORSEMENT_KIND, BADGE_KIND):
            if not body_ok_by_ref.get(rec.ref, False):
                out_findings.append(_finding(2, rec.ref, "authority", "failed", "not_covered"))
                continue

            has_parent = "parent" in body_dict and body_dict.get("parent") is not None
            if not has_parent:
                if issuer is not None and body_dict.get("subject") == issuer:
                    out_findings.append(_finding(2, rec.ref, "authority", "failed", "not_covered"))
                elif kpath != ENDORSEMENT_KIND or issuer is None or not tenures_by_key.get(issuer):
                    out_findings.append(
                        _finding(2, rec.ref, "authority", "failed", "no_standing", issuer)
                    )
                else:
                    r_status, r_end_ref = _evaluate_root_act(rec, tenures_by_key, seal_times_by_ref)
                    if r_status == "ok":
                        out_findings.append(_finding(2, rec.ref, "authority", "ok", "ok", issuer))
                    elif r_status == "ended":
                        out_findings.append(
                            _finding(2, rec.ref, "authority", "failed", "ended", r_end_ref)
                        )
                    elif r_status == "clock_only":
                        out_findings.append(
                            _finding(
                                2,
                                rec.ref,
                                "authority",
                                "incomplete",
                                "time_rests_on_the_signer",
                                r_end_ref,
                            )
                        )
                    elif r_status == "before_tenure":
                        out_findings.append(
                            _finding(2, rec.ref, "authority", "failed", "not_covered")
                        )
                    else:
                        out_findings.append(
                            _finding(2, rec.ref, "authority", "failed", "no_standing", issuer)
                        )
                continue

            parent_ref = body_dict.get("parent")
            if type(parent_ref) is not str or not _is_link_shape_ok(rec):
                out_findings.append(_finding(2, rec.ref, "authority", "failed", "not_covered"))
                continue

            p_link = auth_links_by_ref.get(parent_ref)
            if p_link is None:
                if parent_ref != rec.ref and _might_yet_be_valid_grant(
                    parent_ref, opened_by_ref, body_result_by_ref
                ):
                    row_num, _ = _evaluate_steps_endings(
                        [],
                        rec,
                        revocations_by_target,
                        opened_by_ref,
                        body_result_by_ref,
                        auth_links_by_ref,
                        succ_state,
                        tenures_by_key,
                        seal_times_by_ref,
                    )
                    if row_num != 4:
                        out_findings.append(
                            _finding(
                                2,
                                rec.ref,
                                "authority",
                                "incomplete",
                                "chain_not_carried",
                                parent_ref,
                            )
                        )
                        continue
            elif _child_continues_parent(p_link, rec, succ_state):
                full_chain, missing_run = _walk_up_from_link(
                    p_link,
                    opened_by_ref,
                    body_result_by_ref,
                    auth_links_by_ref,
                    succ_state,
                    tenures_by_key,
                    extra_tail_ref=rec.ref,
                )
                if full_chain is not None:
                    row_num, ending_ref = _evaluate_steps_endings(
                        full_chain,
                        rec,
                        revocations_by_target,
                        opened_by_ref,
                        body_result_by_ref,
                        auth_links_by_ref,
                        succ_state,
                        tenures_by_key,
                        seal_times_by_ref,
                    )
                    if row_num == 1:
                        out_findings.append(
                            _finding(2, rec.ref, "authority", "ok", "ok", parent_ref)
                        )
                        continue
                    if row_num == 2:
                        out_findings.append(
                            _finding(
                                2,
                                rec.ref,
                                "authority",
                                "incomplete",
                                "time_rests_on_the_signer",
                                ending_ref,
                            )
                        )
                        continue
                    if row_num == 4:
                        out_findings.append(
                            _finding(2, rec.ref, "authority", "failed", "ended", ending_ref)
                        )
                        continue
                elif missing_run is not None:
                    part_links, missing_ref = missing_run
                    row_num, _ = _evaluate_steps_endings(
                        part_links,
                        rec,
                        revocations_by_target,
                        opened_by_ref,
                        body_result_by_ref,
                        auth_links_by_ref,
                        succ_state,
                        tenures_by_key,
                        seal_times_by_ref,
                    )
                    if row_num != 4:
                        out_findings.append(
                            _finding(
                                2,
                                rec.ref,
                                "authority",
                                "incomplete",
                                "chain_not_carried",
                                missing_ref,
                            )
                        )
                        continue

            out_findings.append(_finding(2, rec.ref, "authority", "failed", "not_covered"))
            continue

        # Case 3: Ordinary record (A5 §5 + A7 §3.2 Multi-Signer Authority Walk)
        pdef = parsed_def_by_ref.get(rec.ref)
        if pdef is not None and pdef.signatures > 1 and len(rec.signers) != pdef.signatures:
            out_findings.append(_finding(2, rec.ref, "authority", "failed", "not_covered", None))
            continue

        signer_outcomes = [evaluate_ordinary_signer(rec, s_i, t_rec) for s_i in rec.signers]
        first_failed = next((o for o in signer_outcomes if o[0] == "failed"), None)
        if first_failed is not None:
            out_findings.append(
                _finding(2, rec.ref, "authority", first_failed[0], first_failed[1], first_failed[2])
            )
            continue

        first_incomplete = next((o for o in signer_outcomes if o[0] == "incomplete"), None)
        if first_incomplete is not None:
            out_findings.append(
                _finding(
                    2,
                    rec.ref,
                    "authority",
                    first_incomplete[0],
                    first_incomplete[1],
                    first_incomplete[2],
                )
            )
            continue

        res_1, code_1, about_1 = signer_outcomes[0]
        out_findings.append(_finding(2, rec.ref, "authority", res_1, code_1, about_1))

    return out_findings, a5_qualifying_seal_refs


# ---------------------------------------------------------------------------
# §6.4 & §6.4a Content, Retention, Holds, Releases, & Dispositions (A7 §§4–5)
# ---------------------------------------------------------------------------


def _retention_stream_for_record(rec: OpenedRecord) -> str | None:
    """Return `retention_stream(R)` per A7 §4.1, or `None`."""
    stream = rec.payload.get("stream")
    if type(stream) is not str:
        return None
    m = DEPLOYMENT_STREAM_RE.match(stream)
    if m is None:
        return None
    return f"urn:r5e:stream:{m.group(1)}:retention"


def _content_scope_for_record(rec: OpenedRecord) -> str | None:
    """Return `content_scope(R)` per A7 §4.3, or `None`."""
    if rec.kind_path in NO_CONTENT_SCOPE_KINDS:
        return None
    if "session" in rec.payload:
        sess = rec.payload["session"]
        return sess if type(sess) is str else None
    stream = rec.payload.get("stream")
    return f"stream:{stream}" if type(stream) is str else None


def _hold_covers(
    hold_rec: OpenedRecord,
    rec: OpenedRecord,
    blob_ref: str,
    ret_stream: str | None,
    r_scope: str | None,
) -> bool:
    """Check whether counting `RetentionHold` `hold_rec` covers `(rec, blob_ref)` per A7 §4.5."""
    if ret_stream is None or hold_rec.payload.get("stream") != ret_stream:
        return False
    hbody = hold_rec.payload["body"]
    if "targets" in hbody:
        targets = hbody["targets"]
        return blob_ref in targets or rec.ref in targets
    if "scope" in hbody:
        return r_scope is not None and hbody["scope"] == r_scope
    return False


def _disposal_covers(
    disp_rec: OpenedRecord,
    rec: OpenedRecord,
    blob_ref: str,
    ret_stream: str | None,
    r_scope: str | None,
    r_ts_ns: int | None,
) -> bool:
    """Check whether counting `PayloadDisposition` `disp_rec` covers `(rec, blob_ref)` per A7 §4.5."""
    if ret_stream is None or disp_rec.payload.get("stream") != ret_stream:
        return False
    dbody = disp_rec.payload["body"]
    if dbody.get("action") not in ("expired", "deleted"):
        return False
    if r_ts_ns is None:
        return False
    d_ts_ns = parse_rfc3339_instant_ns(disp_rec.payload.get("capturedAt"))
    if d_ts_ns is None or r_ts_ns > d_ts_ns:
        return False
    if "targets" in dbody:
        targets = dbody["targets"]
        return blob_ref in targets or rec.ref in targets
    if "scope" in dbody:
        return r_scope is not None and dbody["scope"] == r_scope
    return False


def _verify_content_retention_and_disposition(
    *,
    opened_records: list[OpenedRecord],
    opened_by_ref: dict[str, OpenedRecord],
    blobs_by_ref: dict[str, bytes],
    base_def_index_refs: set[str],
    omissions_by_ref: dict[str, str],
    body_ok_by_ref: dict[str, bool],
    authority_ok_by_ref: dict[str, bool],
    profile_bounds_ok_by_ref: dict[str, bool],
    sealer_ok_by_ref: dict[str, bool],
    valid_profile_by_ref: dict[str, dict[str, Any]],
    by_stream: dict[str, dict[int, list[OpenedRecord]]],
    seal_covered_refs: dict[str, set[str]],
    a5_qualifying_seal_refs: set[str],
    use_root_or_chain_trust: bool,
) -> list[dict[str, Any]]:
    """Evaluate VERIFY-V2 §6.4 / §6.4a (Amendment A7 §§4–5) content findings for all opened records."""
    # §4.2 Index retention records that "count" by retention stream.
    counting_refs: set[str] = set()
    holds_by_stream: dict[str, list[OpenedRecord]] = {}
    releases_by_stream_hold: dict[tuple[str, str], list[OpenedRecord]] = {}
    disposals_by_stream: dict[str, list[OpenedRecord]] = {}
    t_end_by_stream: dict[str, int] = {}

    for rec in opened_records:
        kpath = rec.kind_path
        if kpath not in RETENTION_ACT_KINDS:
            continue
        stream = rec.payload.get("stream")
        if (
            type(stream) is not str
            or not RETENTION_STREAM_RE.match(stream)
            or not rec.all_signatures_ok
            or not body_ok_by_ref.get(rec.ref, False)
            or not authority_ok_by_ref.get(rec.ref, False)
        ):
            continue

        ts_ns = parse_rfc3339_instant_ns(rec.payload.get("capturedAt"))
        if ts_ns is None:
            continue

        counting_refs.add(rec.ref)
        prev_max = t_end_by_stream.get(stream)
        if prev_max is None or ts_ns > prev_max:
            t_end_by_stream[stream] = ts_ns

        if kpath == RETENTION_HOLD_KIND:
            holds_by_stream.setdefault(stream, []).append(rec)
        elif kpath == RETENTION_HOLD_RELEASE_KIND:
            hold_target = rec.payload["body"]["hold"]
            releases_by_stream_hold.setdefault((stream, hold_target), []).append(rec)
        elif kpath == PAYLOAD_DISPOSITION_KIND:
            disposals_by_stream.setdefault(stream, []).append(rec)

    # §4.6 Index qualifying seals `(seal_ref, seal_ts_ns)` covering each record reference.
    qualifying_seals_by_covered_ref: dict[str, list[tuple[str, int]]] = {}
    for seal_ref, covered_set in seal_covered_refs.items():
        if not covered_set:
            continue
        seal_rec = opened_by_ref.get(seal_ref)
        if (
            seal_rec is None
            or seal_rec.kind_path != EPOCH_SEAL_KIND
            or not seal_rec.all_signatures_ok
            or not body_ok_by_ref.get(seal_ref, False)
        ):
            continue
        if use_root_or_chain_trust:
            sealer_standing = seal_ref in a5_qualifying_seal_refs
        else:
            sealer_standing = (
                sealer_ok_by_ref.get(seal_ref, False)
                and profile_bounds_ok_by_ref.get(seal_ref, False)
                and authority_ok_by_ref.get(seal_ref, False)
            )
        if not sealer_standing:
            continue
        seal_ts_ns = parse_rfc3339_instant_ns(seal_rec.payload.get("capturedAt"))
        if seal_ts_ns is None:
            continue
        for cov_ref in covered_set:
            qualifying_seals_by_covered_ref.setdefault(cov_ref, []).append((seal_ref, seal_ts_ns))

    # §5 Evaluate one `content` finding per distinct collected `bytes:` reference on each opened record.
    out_findings: list[dict[str, Any]] = []
    for rec in opened_records:
        cited_bytes = _collect_record_content_refs(rec.kind_path, rec.payload.get("body"))
        if not cited_bytes:
            continue

        ret_stream = _retention_stream_for_record(rec)
        r_scope = _content_scope_for_record(rec)
        r_ts_ns = parse_rfc3339_instant_ns(rec.payload.get("capturedAt"))
        r_profile_ref = (
            rec.payload.get("profileRef") if type(rec.payload.get("profileRef")) is str else None
        )
        r_profile = (
            valid_profile_by_ref.get(r_profile_ref) if r_profile_ref is not None else None
        )

        for c_ref in cited_bytes:
            if c_ref in blobs_by_ref or c_ref in base_def_index_refs:
                out_findings.append(_finding(2, rec.ref, "content", "ok", "ok", c_ref))
                continue

            # §5.1 Select earliest applicable counting disposal `D` ordered by `(D.seq, D.ref)`.
            cand_disposals = (
                [
                    d_rec
                    for d_rec in disposals_by_stream.get(ret_stream, ())
                    if _disposal_covers(d_rec, rec, c_ref, ret_stream, r_scope, r_ts_ns)
                ]
                if ret_stream is not None
                else []
            )

            if cand_disposals:
                disp = min(
                    cand_disposals,
                    key=lambda d: (int(d.payload["seq"]), d.ref.encode("utf-8")),
                )
                d_stream: str = disp.payload["stream"]
                d_seq: int = disp.payload["seq"]
                d_ts_ns = parse_rfc3339_instant_ns(disp.payload["capturedAt"])
                assert d_ts_ns is not None and r_ts_ns is not None

                # §5.2 Row 1: `disposed_under_hold`
                blocking_holds: list[OpenedRecord] = []
                for h_rec in holds_by_stream.get(d_stream, ()):
                    h_seq: int = h_rec.payload["seq"]
                    if h_seq >= d_seq:
                        continue
                    if not _hold_covers(h_rec, rec, c_ref, ret_stream, r_scope):
                        continue
                    released_before_d = any(
                        h_seq < int(rel.payload["seq"]) < d_seq
                        for rel in releases_by_stream_hold.get((d_stream, h_rec.ref), ())
                    )
                    if released_before_d:
                        continue
                    h_body = h_rec.payload["body"]
                    if "until" in h_body:
                        h_until_ns = parse_rfc3339_instant_ns(h_body["until"])
                        if h_until_ns is not None and d_ts_ns >= h_until_ns:
                            continue
                    blocking_holds.append(h_rec)

                if blocking_holds:
                    first_hold = min(
                        blocking_holds,
                        key=lambda h: (int(h.payload["seq"]), h.ref.encode("utf-8")),
                    )
                    out_findings.append(
                        _finding(
                            2,
                            rec.ref,
                            "content",
                            "failed",
                            "disposed_under_hold",
                            first_hold.ref,
                        )
                    )
                    continue

                # §5.2 Row 2: `disposed_before_keep_until`
                if r_profile is not None:
                    ret_policy = r_profile.get("retention")
                    if (
                        not isinstance(ret_policy, dict)
                        or ret_policy.get("disposal") == "never"
                        or (
                            r_ts_ns + int(ret_policy["keepContentForSeconds"]) * 1_000_000_000
                            > d_ts_ns
                        )
                    ):
                        out_findings.append(
                            _finding(
                                2,
                                rec.ref,
                                "content",
                                "failed",
                                "disposed_before_keep_until",
                                disp.ref,
                            )
                        )
                        continue

                # §5.2 Row 3: `disposal_dated_after_its_seal`
                qual_seals = qualifying_seals_by_covered_ref.get(disp.ref, [])
                earlier_seals = [s_ref for s_ref, s_ts_ns in qual_seals if d_ts_ns > s_ts_ns]
                if earlier_seals:
                    lowest_seal = min(earlier_seals, key=lambda r: r.encode("utf-8"))
                    out_findings.append(
                        _finding(
                            2,
                            rec.ref,
                            "content",
                            "failed",
                            "disposal_dated_after_its_seal",
                            lowest_seal,
                        )
                    )
                    continue

                # §5.2 Row 4: `disposed_profile_not_shown`
                if r_profile is None:
                    out_findings.append(
                        _finding(
                            2,
                            rec.ref,
                            "content",
                            "incomplete",
                            "disposed_profile_not_shown",
                            r_profile_ref,
                        )
                    )
                    continue

                # §5.2 Row 5: `disposal_not_sealed`
                if not qual_seals:
                    out_findings.append(
                        _finding(
                            2,
                            rec.ref,
                            "content",
                            "incomplete",
                            "disposal_not_sealed",
                            disp.ref,
                        )
                    )
                    continue

                # §5.2 Row 6: `disposed_holds_not_shown`
                seq_map = by_stream.get(d_stream, {})
                holds_shown = True
                prev_ref: str | None = None
                for k in range(1, d_seq + 1):
                    recs_at_k = seq_map.get(k)
                    if recs_at_k is None or len(recs_at_k) != 1:
                        holds_shown = False
                        break
                    r_k = recs_at_k[0]
                    if k == d_seq and r_k.ref != disp.ref:
                        holds_shown = False
                        break
                    if k == 1:
                        if "previous" not in r_k.payload or r_k.payload["previous"] is not None:
                            holds_shown = False
                            break
                    else:
                        if r_k.payload.get("previous") != prev_ref:
                            holds_shown = False
                            break
                    if (
                        k < d_seq
                        and r_k.kind_path == RETENTION_HOLD_KIND
                        and r_k.ref not in counting_refs
                    ):
                        holds_shown = False
                        break
                    prev_ref = r_k.ref

                if not holds_shown:
                    out_findings.append(
                        _finding(
                            2,
                            rec.ref,
                            "content",
                            "incomplete",
                            "disposed_holds_not_shown",
                            disp.ref,
                        )
                    )
                    continue

                # §5.2 Row 7: `disposed_by_record`
                out_findings.append(
                    _finding(2, rec.ref, "content", "incomplete", "disposed_by_record", disp.ref)
                )
                continue

            # §5.3 No counting disposal covers `(R, B)` (Rows 8–10)
            om_reason = omissions_by_ref.get(c_ref)
            if (
                ret_stream is not None
                and (om_reason is None or om_reason not in ("not-selected", "withheld"))
            ):
                active_holds: list[OpenedRecord] = []
                stream_t_end = t_end_by_stream.get(ret_stream)
                for h_rec in holds_by_stream.get(ret_stream, ()):
                    if not _hold_covers(h_rec, rec, c_ref, ret_stream, r_scope):
                        continue
                    h_seq = h_rec.payload["seq"]
                    released = any(
                        int(rel.payload["seq"]) > h_seq
                        for rel in releases_by_stream_hold.get((ret_stream, h_rec.ref), ())
                    )
                    if released:
                        continue
                    h_body = h_rec.payload["body"]
                    if "until" in h_body:
                        h_until_ns = parse_rfc3339_instant_ns(h_body["until"])
                        if (
                            h_until_ns is not None
                            and stream_t_end is not None
                            and stream_t_end >= h_until_ns
                        ):
                            continue
                    active_holds.append(h_rec)

                if active_holds:
                    first_hold = min(
                        active_holds,
                        key=lambda h: (int(h.payload["seq"]), h.ref.encode("utf-8")),
                    )
                    out_findings.append(
                        _finding(
                            2,
                            rec.ref,
                            "content",
                            "incomplete",
                            "missing_under_hold",
                            first_hold.ref,
                        )
                    )
                    continue

            if om_reason is not None:
                code = "omitted_" + om_reason.replace("-", "_")
                out_findings.append(_finding(2, rec.ref, "content", "incomplete", code, c_ref))
            else:
                out_findings.append(
                    _finding(2, rec.ref, "content", "incomplete", "not_carried", c_ref)
                )

    return out_findings


def report_exit_code(report: dict[str, Any], *, allow_incomplete: bool = False) -> int:
    """Compute §10 CLI exit status from a §9 report."""
    summary = report["summary"]
    if summary["failed"] > 0:
        return 1
    if summary["incomplete"] > 0:
        return 0 if allow_incomplete else 3
    return 0


def verify_provenance_file(
    bundle_path: str | Path,
    *,
    trusted_profiles: Sequence[str] = (),
    trusted_publishers: Sequence[str] = (),
    trusted_roots: Sequence[str] | None = None,
    trusted_chain: str | None = None,
    min_start_seq: int | None = None,
    definitions_dir: str | Path | None = None,
    allow_incomplete: bool = False,
) -> tuple[bytes, int]:
    """Read a bundle file from disk, run Provenance v2 verification, return (canonical_bytes, exit_code)."""
    _validate_reader_options(trusted_roots, trusted_chain, min_start_seq, trusted_publishers)
    p = Path(bundle_path)
    if not p.is_file():
        raise ProvenanceInputError(f"cannot read bundle file at {bundle_path}")
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ProvenanceInputError(f"cannot read bundle file at {bundle_path}: {exc}") from exc

    installed = load_definitions_dir(definitions_dir) if definitions_dir is not None else None
    bundle = load_bundle_json(raw)
    report = verify_provenance_bundle(
        bundle,
        trusted_profiles=trusted_profiles,
        trusted_publishers=trusted_publishers,
        trusted_roots=trusted_roots,
        trusted_chain=trusted_chain,
        min_start_seq=min_start_seq,
        installed_definitions=installed,
    )
    return canonical_json_bytes(report), report_exit_code(report, allow_incomplete=allow_incomplete)
