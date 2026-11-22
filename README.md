# r5e-verify-py

Clean-room offline Python verifier for Provenance v2 export bundles (`r5e.provenance-export/v2`).

Written strictly from the Provenance v2 specification, wire JSON schemas, and conformance vectors without reading or consulting the Elixir reference implementation. Verification is completely offline: it opens no network connections, runs no policy engine, and consults no wall clock.

## Installation

Requires Python 3.10 or newer and `cryptography>=43`:

```sh
python3 -m pip install --only-binary=:all: 'cryptography>=43'
python3 -m r5e_verify PATH_TO_BUNDLE.json
```

Or install the package entrypoint (`recurse_verify` / `r5e-verify`) into a virtual environment:

```sh
python3 -m pip install .
recurse_verify PATH_TO_BUNDLE.json
```

## Usage

```sh
recurse_verify [provenance] PATH_TO_BUNDLE.json \
  [--profile r5e-api] \
  [--trusted-profile bytes:sha256:...] \
  [--trusted-publisher key:...[=domain,...] | --publisher key:...[=domain,...]] \
  [--trusted-root key:... | --root key:...] [--establish-authority] \
  [--trusted-chain evidence:sha256:... | --chain evidence:sha256:...] [--min-start-seq N] \
  [--definitions-dir PATH] \
  [--report FILE] \
  [--allow-incomplete]
```

Default trust is empty: no root, chain, capture profile, or definition publisher is trusted unless explicitly supplied by the reader. Passing `--profile r5e-api` opts in to the founding `r5e-api` Block 0 chain (`--chain evidence:sha256:7c45caf3de9a3014b662d67c44705b6fdb180c06492abbb9e4a216828ef686c5`, unless `--root` is explicitly given) and publisher pin (`--publisher key:es256:sha256:2685eeac8d06dd75811f6b14fb45bde55c657957e3adface2ff8b0379c31cc33=r5e.io`).

The verifier writes the `r5e.provenance-verify-report/v2` report as canonical JSON and exits:
- `0` when established (`failed == 0 && incomplete == 0`, or `failed == 0` with `--allow-incomplete`),
- `1` when any check failed (`failed > 0`),
- `2` when arguments or input cannot be read, or
- `3` when sound but incomplete (`failed == 0 && incomplete > 0` without `--allow-incomplete`).

## Founding `r5e-api` Block 0 Verification

[`genesis/r5e-api/`](genesis/r5e-api/) carries the public founding artifacts for `r5e-api` (`block-0-r5e-api.json`, `publications.json`, `r5e-root.pub.pem`, and `r5e-publisher.pub.pem`):

```sh
python3 -m r5e_verify genesis/r5e-api/block-0-r5e-api.json --profile r5e-api | shasum -a 256
# c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed  -
```

Verified by three independent implementations (the Elixir reference implementation, clean-room Python `r5e-verify-py`, and clean-room Rust `r5e-verify-rs` — the latter two written from the specification and conformance vectors without reading the reference implementation), exercised across six execution surfaces (Elixir in-process, Gateway HTTP `/v1/evidence/verify`, an independent second-operator clean-tree run of the reference verifier, Python CLI, Rust native CLI, and zero-import WebAssembly), all producing byte-identical canonical report `c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed` (`122 ok / 0 failed / 0 incomplete`).

## Running the Test Suite

With [`r5e-spec`](../r5e-spec) checked out beside this repository (or `R5E_PROVENANCE_VECTORS_DIR` pointing to it):

```sh
python3 -m unittest discover -s tests -v
```

## Contributing & License

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Licensed under Apache License 2.0 — see [`LICENSE`](LICENSE).
