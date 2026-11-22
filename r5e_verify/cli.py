"""Strict command-line interface and reader-supplied trust pins for Provenance v2."""

from __future__ import annotations

import sys

from .provenance import (
    EVIDENCE_REF_RE,
    ProvenanceInputError,
    _validate_reader_options,
    verify_provenance_file,
)

USAGE = (
    "usage: recurse_verify [provenance] PATH_TO_BUNDLE.json\n"
    "                                     [--profile r5e-api]\n"
    "                                     [--trusted-profile REF]...\n"
    "                                     [--publisher KEYID[=DOMAIN,...]]...\n"
    "                                     [--trusted-publisher KEYID[=DOMAIN,...]]...\n"
    "                                     [--root KEYID | --trusted-root KEYID]... [--establish-authority]\n"
    "                                     [--chain REF | --trusted-chain REF] [--min-start-seq N]\n"
    "                                     [--checkpoint SEQ=REF | --checkpoint SEQ:REF]...\n"
    "                                     [--definitions-dir PATH]\n"
    "                                     [--report FILE]\n"
    "                                     [--allow-incomplete]\n"
)

R5E_API_CHAIN_REF = (
    "evidence:sha256:7c45caf3de9a3014b662d67c44705b6fdb180c06492abbb9e4a216828ef686c5"
)
R5E_API_PUBLISHER_PIN = (
    "key:es256:sha256:2685eeac8d06dd75811f6b14fb45bde55c657957e3adface2ff8b0379c31cc33=r5e.io"
)

_PROVENANCE_VALUE_FLAGS = (
    "--profile",
    "--trusted-profile",
    "--trusted-publisher",
    "--publisher",
    "--trusted-root",
    "--root",
    "--trusted-chain",
    "--chain",
    "--min-start-seq",
    "--checkpoint",
    "--definitions-dir",
    "--report",
)


def _parse_checkpoint_pin(value: str) -> dict[str, object]:
    if "=" in value:
        seq_str, _, ref_str = value.partition("=")
    elif ":" in value:
        seq_str, _, ref_str = value.partition(":")
    else:
        raise ProvenanceInputError(
            f"invalid --checkpoint value {value!r} (expected SEQ=REF or SEQ:REF)"
        )
    if not (seq_str.isascii() and seq_str.isdigit()) or int(seq_str) < 1:
        raise ProvenanceInputError(f"invalid --checkpoint sequence integer: {seq_str!r}")
    if EVIDENCE_REF_RE.match(ref_str) is None:
        raise ProvenanceInputError(f"invalid --checkpoint evidence reference: {ref_str!r}")
    return {"seq": int(seq_str), "ref": ref_str}


def provenance_arguments(
    raw_args: list[str],
) -> tuple[
    str,
    list[str],
    list[str],
    list[str] | None,
    str | None,
    int | None,
    str | None,
    bool,
    str | None,
    list[dict[str, object]],
]:
    args = raw_args[1:] if raw_args and raw_args[0] == "provenance" else list(raw_args)
    positional: list[str] = []
    profile: str | None = None
    trusted_profiles: list[str] = []
    trusted_publishers: list[str] = []
    trusted_roots: list[str] = []
    establish_authority = False
    trusted_chain: str | None = None
    min_start_seq: int | None = None
    trusted_checkpoints: list[dict[str, object]] = []
    definitions_dir: str | None = None
    report_out: str | None = None
    allow_incomplete = False

    def apply_value_flag(flag: str, value: str) -> None:
        nonlocal profile, trusted_chain, min_start_seq, definitions_dir, report_out
        if not value:
            raise ProvenanceInputError(f"{flag} requires a value")
        if flag == "--profile":
            if profile is not None:
                raise ProvenanceInputError("--profile may not be specified more than once")
            if value != "r5e-api":
                raise ProvenanceInputError(
                    f"unknown --profile {value!r} (supported: r5e-api)"
                )
            profile = value
        elif flag == "--trusted-profile":
            trusted_profiles.append(value)
        elif flag in ("--trusted-publisher", "--publisher"):
            trusted_publishers.append(value)
        elif flag in ("--trusted-root", "--root"):
            trusted_roots.append(value)
        elif flag in ("--trusted-chain", "--chain"):
            if trusted_chain is not None:
                raise ProvenanceInputError(f"{flag} may not be specified more than once")
            trusted_chain = value
        elif flag == "--min-start-seq":
            if min_start_seq is not None:
                raise ProvenanceInputError("--min-start-seq may not be specified more than once")
            if not (value.isascii() and value.isdigit()):
                raise ProvenanceInputError(f"invalid --min-start-seq integer: {value!r}")
            min_start_seq = int(value)
        elif flag == "--checkpoint":
            trusted_checkpoints.append(_parse_checkpoint_pin(value))
        elif flag == "--report":
            if report_out is not None:
                raise ProvenanceInputError("--report may not be specified more than once")
            report_out = value
        else:
            definitions_dir = value

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--allow-incomplete":
            allow_incomplete = True
            i += 1
        elif arg == "--establish-authority":
            establish_authority = True
            i += 1
        elif arg.startswith("--") and "=" in arg:
            flag, _, value = arg.partition("=")
            if flag not in _PROVENANCE_VALUE_FLAGS:
                raise ValueError()
            apply_value_flag(flag, value)
            i += 1
        elif arg.startswith("-"):
            if (
                arg not in _PROVENANCE_VALUE_FLAGS
                or i + 1 == len(args)
                or args[i + 1].startswith("--")
            ):
                raise ValueError()
            apply_value_flag(arg, args[i + 1])
            i += 2
        else:
            positional.append(arg)
            i += 1

    if len(positional) != 1:
        raise ValueError()
    if profile == "r5e-api":
        if not trusted_roots:
            if trusted_chain is not None:
                raise ProvenanceInputError("--chain may not be specified more than once")
            trusted_chain = R5E_API_CHAIN_REF
        if R5E_API_PUBLISHER_PIN not in trusted_publishers:
            trusted_publishers.append(R5E_API_PUBLISHER_PIN)
    resolved_roots = trusted_roots if (trusted_roots or establish_authority) else None
    _validate_reader_options(resolved_roots, trusted_chain, min_start_seq, trusted_publishers)
    return (
        positional[0],
        trusted_profiles,
        trusted_publishers,
        resolved_roots,
        trusted_chain,
        min_start_seq,
        definitions_dir,
        allow_incomplete,
        report_out,
        trusted_checkpoints,
    )


def main(argv: list[str] | None = None) -> int:
    raw_args = sys.argv[1:] if argv is None else list(argv)
    try:
        try:
            (
                bundle_path,
                profiles,
                publishers,
                roots,
                chain,
                min_seq,
                defs_dir,
                allow_inc,
                report_out,
                checkpoints,
            ) = provenance_arguments(raw_args)
        except ProvenanceInputError:
            raise
        except ValueError:
            sys.stderr.write(USAGE)
            return 2
        report_bytes, status = verify_provenance_file(
            bundle_path,
            trusted_profiles=profiles,
            trusted_publishers=publishers,
            trusted_roots=roots,
            trusted_chain=chain,
            min_start_seq=min_seq,
            definitions_dir=defs_dir,
            allow_incomplete=allow_inc,
            trusted_checkpoints=checkpoints,
        )
        if report_out is not None:
            try:
                with open(report_out, "wb") as fh:
                    fh.write(report_bytes)
            except OSError as exc:
                raise ProvenanceInputError(
                    f"cannot write report file at {report_out}: {exc}"
                ) from exc
    except ProvenanceInputError as exc:
        sys.stderr.write("recurse_verify: " + str(exc) + "\n")
        return 2
    sys.stdout.buffer.write(report_bytes)
    return status
