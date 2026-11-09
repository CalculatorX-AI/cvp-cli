# CVP replay pack v1

A pack is a directory with `manifest.json` and the exact files it lists. A
publisher can also attach a detached `manifest.sig`. An external verifier
uses a trusted manifest SHA-256 or a separately distributed trusted PEM
public key. File hashes are SHA-256 of the raw UTF-8 bytes, including the final
line ending. Git checks out the JSON fixtures with LF line endings.

## Manifest

| Field | Meaning |
| --- | --- |
| `format` | `cvp-replay-pack-v1` |
| `capability_id` | Published capability identifier |
| `calculation_version` | Capability calculation version |
| `revision` | Version of the public replay evidence |
| `profile` | Installed verifier profile |
| `scope` | Human-readable scope for this public evidence |
| `bindings` | Profile-specific pins |
| `files` | Map of local JSON filenames to lowercase SHA-256 digests |

The verifier authenticates the manifest before reading the listed files, then
checks the file hashes before interpreting the cases. It reads regular files
from the pack directory using a bounded, closed filename format. It rejects
duplicate JSON keys, non-finite numeric literals, invalid Unicode, excessive
nesting and unsafe filenames. The profile and calculation version must be
registered together in the installed CLI.

## Cases

`cases.json` contains one object with a `cases` array. Each case has a unique
`id`, an `inputs` object, an `expected` object, a `source` and a short
`derivation`. Error expectations have the form:

```json
{"error":{"code":"DIVISION_BY_ZERO","field":"y"}}
```

Binary64 expectations use lowercase hexadecimal for the eight big-endian IEEE
754 bytes. Exact coefficients, integer numerators and denominators, and
decimal34 output use strings to preserve precision across JSON implementations.
The full expected object must match the replay projection.

## Built-in profiles

**`uuce-v1`** supports `units.convert@0.1.1`. Bindings carry the published
`version`, `content_digest`, `execution_projection_sha256` and
`integrity_manifest_sha256`. Reference definitions are in `reference-units.json`.
Each unit declares its source and independent transforms by quantity kind.
A transform specifies the reference unit, rational scale and offset, symbolic
π exponent, and supported scalar, point or interval roles. The verifier
checks dimension and role before exact rational conversion. Offsets apply
only to point values. It compares a reduced rational coefficient, π power,
decimal34 rounded ties-to-even, and binary64 bits or range status. Numerical
projection uses the frozen UUCE rational π policy. An unlisted unit requires
a new public reference definition before its cases can be replayed.

**`percentage-v1`** supports `math.percentage@1.2.0`. Bindings are empty.
The initial profile covers the canonical `of`, `is-what` and `of-what` modes
with decimal-string inputs. It interprets each accepted input as binary64,
uses the exact rational representation of those values for the formula,
and performs one final binary64 rounding. It compares mode, unit and bits
or a structured error.

## Extending the CLI

Add a reviewed reference profile to the installed CLI with a versioned input
contract, a defined expected-result projection and independently authored
positive, boundary and rejection cases. Keep the verification policy in code
and the evidence in the pack. For a calculator depending on UUCE, the new
profile should explicitly validate the registry pins and cover the full
calculation chain. Give a changed reference or comparison policy a new
profile identifier or a separate supported contract version.
