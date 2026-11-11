# CVP CLI

An offline-first verifier for public, versioned computational evidence. The same
CLI verifies UUCE unit conversions and basic calculators using capability
profiles. A verifier needs this repository, a public pack and a trust anchor
obtained separately from the pack.

## Quick start

Python 3.9 or newer. Run from this repository with the standard library:

```sh
python3 -m cvp_cli verify examples/uuce \
  --manifest-sha256 9bbb69129e989fa90326650a8d07526b65e272446c3efb4b98c581b3990ca967

python3 -m cvp_cli verify examples/percentage \
  --manifest-sha256 9004d6f27099be436ea94efc0bd9beb607f8ebf615b24ba7664eca28e43cb288
```

To install the `cvp` command in an active Python environment:

```sh
python3 -m pip install .
cvp --help
```

Use `--json` for an automation-friendly report. The sample pins above
authenticate the checked-in examples when obtained from a trusted checkout
of this repository. For a downloaded release, obtain the digest from a trusted
release record, or use a separately trusted publisher public key. Computing a
new pin from the download only gives a local fingerprint.

CalculatorX publishes versioned downloads and release pins on the
[public replay packs page](https://www.calculatorx.com/developers/cvp#replay-packs).
Version 0.1.1 adds decimal-text replay for Celsius/Kelvin and psi/bar.
The [release records](releases/) preserve the SHA-256 pins in this repository
so they can be obtained separately from the pack downloads. The UUCE packs
use the existing `uuce-v1` profile.

## What the report means

| Stage | Evidence checked |
| --- | --- |
| `artifact_integrity` | Manifest bytes match an external SHA-256 pin or detached signature. All listed artifacts match their manifest hashes. |
| `reference_replay` | Independent reference calculations and structured errors match the declared expected values for the listed cases. |
| `live_probe` | Optional. Responses from the chosen HTTPS origin match the pinned capability version and the replayed cases. The report includes the observation interval. |

Exit codes are **0** for a pass, **1** for a result mismatch and **2** for
malformed evidence, failed authentication, an unsupported contract or an
unavailable or invalid live response. An omitted live probe reports
`NOT_RUN`.

The examples are public samples. UUCE includes 14 cases for 9 definitions
under `units.convert@0.1.1` and registry snapshot `0.3.0-preview.3`.
Percentage includes 8 cases across 3 modes under `math.percentage@1.2.0`.
These results cover the listed cases. Production observations are a separate
result from the publisher's CVP attestation. This release performs independent
reference replay and optional API comparison. Offline replay of the published
production executable would require a separately released, pinned execution
artifact.

## Compare with the production API

Add `--live https://www.calculatorx.com` to either example command. Use repeatable
`--live-case ID` flags to select a subset. This sends only the selected pack
inputs to the explicit HTTPS origin, after offline replay succeeds.
The CLI chooses the endpoint from the installed profile, pins the calculation
version, disables redirects and bounds response sizes. Local replay works
without network access.

### Require production preflight

For CalculatorX UUCE `0.1.1`, supply a release record obtained separately
from the pack, explicitly select cases, and declare their low-risk use.
The CLI matches the authenticated pack to the release record, checks the
production receipt and its expiry, and requires a matching approval for
each request before executing it. The result still has to match the pinned
CVP and registry bindings and the independent replay.

```sh
cvp verify ./public-replay-1 \
  --manifest-sha256 4a02c7146ad66f8db17c7eb05a238cf485fe105a4f0fc15aa563e823bcbbfefa \
  --release-record ./releases/public-replay-1.json \
  --live https://www.calculatorx.com \
  --live-case two-international-feet \
  --use-case standalone_low_risk --json
```

Policy `1.0.0` covers scalar conversions between metres and international
feet. A blocked case reports its preflight decision and exits with code 2
without sending the conversion request for that case. Plain `--live`
continues to provide result comparison. Preflight appears as
`production_preflight` on each selected case in the JSON report.

## Use UUCE from an application

The Python module and TypeScript source run the receipt and preflight checks
before sending a conversion. Pass a binding from a separately trusted release
record and explicitly confirm low-risk use for the current task.
The [policy 1.0.0 release record](releases/uuce-agent-policy-1.0.0.json)
contains the pins for the current metre and international foot scope.

```python
import json
from pathlib import Path
from cvp_cli.uuce import convert_units

binding = json.loads(Path("releases/uuce-agent-policy-1.0.0.json").read_bytes())["binding"]
inputs = {
    "value": "2", "from_unit_id": "cx:ft_i", "to_unit_id": "cx:m",
    "quantity_kind": "length", "role": "scalar", "snapshot": binding["registry_version"],
}
response = convert_units(inputs, binding=binding, use_case="standalone_low_risk")
print(response["result"]["exact"])
```

For TypeScript, import the [source module](sdk/typescript/uuce.ts) into an app
that supports Fetch. Use the same release binding and input fields.

```typescript
import { convertUnits } from "./sdk/typescript/uuce.ts";

const response = await convertUnits(inputs, { binding, useCase: "standalone_low_risk" });
console.log(response.result.exact);
```

Both clients return the checked result and its preflight record. They throw
`UuceError` for a rejection or a verification failure. HTTP 429 exposes the
server's `Retry-After` value on the error as `retry_after` in Python and
`retryAfter` in TypeScript.

## Publish a pack

1. Author inputs, expected results, derivations and references under
   [the pack protocol](PROTOCOL.md). Use independent references and fixtures
   that are cleared for public redistribution.
2. Pin every data file in the manifest and deploy the versioned pack to
   CalculatorX. Then add its exact manifest SHA-256 to the release records in
   this repository so CI can verify the download. Preserve the original file
   bytes for historical replay. Tag the tested CLI when issuing a CLI version.
3. For detached signatures, sign the exact manifest bytes with an existing
   publisher RSA key kept outside the repository. Publish the signature with
   the pack and distribute the public key through a trusted channel.

```sh
openssl dgst -sha256 -sign /secure/path/publisher-private.pem \
  -out ./pack/manifest.sig ./pack/manifest.json

cvp verify ./pack --public-key /trusted/path/publisher-public.pem --json
```

The CLI uses OpenSSL only for detached signature verification. The SHA-256 pin
path needs only Python. Packs are data directories. The verifier loads JSON and
selects the validation code from the installed CLI. The examples include
new public fixtures and cited reference definitions.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -B -m scripts.verify_releases
```

The release replay checks every pack listed in this checkout's release records.
It downloads the versioned JSON from CalculatorX and authenticates the manifest
against the digest in the release record before replaying its cases. Use
`--public-dir /path/to/public` to run the same check on a local publication tree.
Release tags use `v<version>` and CI checks the tag against the installed
`cvp --version`.

See [PROTOCOL.md](PROTOCOL.md) for the evidence contract and profile extension
rules. The verifier code and original example data use the [MIT license](LICENSE).
Linked reference publications retain their own terms.
