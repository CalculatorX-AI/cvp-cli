import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cvp_cli.__main__ import main
from cvp_cli.live import ProbeError
from cvp_cli.pack import PackError, parse_json
from cvp_cli.preflight import ORIGIN, PREFLIGHT_CONTRACT, RECEIPT_CONTRACT, pinned_binding
from cvp_cli.reference import CelsiusKelvinReference, PsiBarReference
from cvp_cli.uuce import UuceError, convert_units

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
UUCE_PIN = "9bbb69129e989fa90326650a8d07526b65e272446c3efb4b98c581b3990ca967"
PERCENTAGE_PIN = "9004d6f27099be436ea94efc0bd9beb607f8ebf615b24ba7664eca28e43cb288"


def invoke(*args):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = main([str(arg) for arg in args] + ["--json"])
    return code, json.loads(output.getvalue())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "pack"
        shutil.copytree(EXAMPLES / "uuce", self.root)

    def repin(self, change_manifest=lambda manifest: None, *, rehash_cases=False):
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if rehash_cases:
            manifest["files"]["cases.json"] = digest(self.root / "cases.json")
        change_manifest(manifest)
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return digest(path)

    def verify(self, pin=UUCE_PIN, *options):
        return invoke("verify", self.root, "--manifest-sha256", pin, *options)

    def production_fixture(self):
        manifest = json.loads((self.root / "manifest.json").read_bytes())
        cases = json.loads((self.root / "cases.json").read_bytes())["cases"]
        case = cases[0]
        release = Path(self.temp.name) / "trusted-release.json"
        release.write_text(json.dumps({
            "format": "calculatorx-cvp-replay-releases-v1",
            "packs": [{
                **{key: manifest[key] for key in ("capability_id", "calculation_version", "revision", "profile")},
                "manifest_sha256": UUCE_PIN, "cvp_verification_revision": "review-1", "cvp_core_sha256": "a" * 64,
            }],
        }), encoding="utf-8")
        binding = pinned_binding(release, manifest, UUCE_PIN)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = lambda time: time.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        receipt = {
            "contract": RECEIPT_CONTRACT, "issuer": ORIGIN, "capability_id": "units.convert",
            "calculation_version": "0.1.1", "production_freshness": "CURRENT", "binding": binding,
            "attestation_id": "b" * 64, "checked_at": stamp(now - timedelta(hours=1)),
            "expires_at": stamp(now + timedelta(days=7, hours=-1)),
        }
        reply = {
            "contract": PREFLIGHT_CONTRACT, "policy_version": "1.0.0", "decision": "ALLOW", "code": "IN_POLICY",
            "receipt": receipt, "execute": {"method": "POST", "path": "/api/v1/units/convert",
                                            "body": {"calculation_version": "0.1.1", "inputs": case["inputs"]}},
        }
        options = ("--live", ORIGIN, "--live-case", case["id"], "--release-record", release,
                   "--use-case", "standalone_low_risk")
        return options, case, receipt, reply

    def test_production_preflight_reports_allow_before_execution(self):
        options, case, receipt, reply = self.production_fixture()
        with patch("cvp_cli.preflight.request_json", side_effect=[(200, receipt), (200, reply)]) as request, \
                patch("cvp_cli.__main__.observe", return_value=case["expected"]) as live:
            code, report = self.verify(UUCE_PIN, *options)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["live_probe"]["cases"][0]["production_preflight"]["decision"], "ALLOW")
        self.assertEqual(request.call_args.kwargs["body"]["trust"], receipt["binding"])
        self.assertEqual(live.call_args.kwargs["binding"], receipt["binding"])

    def test_production_preflight_fails_closed(self):
        options, _, receipt, reply = self.production_fixture()
        for changed_receipt, changed_reply, decision in (
            ({**receipt, "binding": {**receipt["binding"], "cvp_core_sha256": "c" * 64}}, reply, "UNAVAILABLE"),
            ({**receipt, "checked_at": "2000-01-01T00:00:00.000Z",
              "expires_at": "2000-01-08T00:00:00.000Z"}, reply, "UNAVAILABLE"),
            (receipt, {**reply, "decision": "DENY", "code": "CONVERSION_OUTSIDE_POLICY"}, "DENY"),
            (receipt, {**reply, "decision": "NEED_CONTEXT", "code": "CONTEXT_REQUIRED"}, "NEED_CONTEXT"),
            (receipt, {**reply, "execute": {**reply["execute"], "path": "/other"}}, "UNAVAILABLE"),
        ):
            with self.subTest(decision=decision), patch("cvp_cli.preflight.request_json", side_effect=[
                (200, changed_receipt), (200, changed_reply),
            ]), patch("cvp_cli.__main__.observe") as live:
                code, report = self.verify(UUCE_PIN, *options)
                self.assertEqual(code, 2, report)
                self.assertEqual(report["live_probe"]["cases"][0]["production_preflight"]["decision"], decision)
                live.assert_not_called()

    def test_approved_execution_still_requires_response_binding(self):
        options, _, receipt, reply = self.production_fixture()
        with patch("cvp_cli.preflight.request_json", side_effect=[(200, receipt), (200, reply)]), \
                patch("cvp_cli.live.request_json", return_value=(200, {
                    "status": "success", "capability_id": "units.convert", "calculation_version": "0.1.1",
                })):
            code, report = self.verify(UUCE_PIN, *options)
        self.assertEqual(code, 2, report)
        self.assertIn("CVP binding differs", report["live_probe"]["cases"][0]["detail"])

    def test_sdk_requires_context_and_preserves_rate_limit_details(self):
        _, case, receipt, reply = self.production_fixture()
        pins = receipt["binding"]
        with patch("cvp_cli.uuce.approve") as approve:
            with self.assertRaises(UuceError) as error:
                convert_units(case["inputs"], binding=pins, use_case="")
            self.assertEqual(error.exception.decision, "NEED_CONTEXT")
            approve.assert_not_called()
        with patch("cvp_cli.preflight.request_json", side_effect=[(200, receipt), (200, reply)]), \
                patch("cvp_cli.uuce.request_json", side_effect=ProbeError("rate limited", status=429, retry_after="7")):
            with self.assertRaises(UuceError) as error:
                convert_units(case["inputs"], binding=pins, use_case="standalone_low_risk")
        self.assertEqual((error.exception.code, error.exception.retry_after), ("RATE_LIMITED", "7"))

    def test_sdk_propagates_denial_without_converting(self):
        _, case, receipt, reply = self.production_fixture()
        denied = {**reply, "decision": "DENY", "code": "CONVERSION_OUTSIDE_POLICY"}
        with patch("cvp_cli.preflight.request_json", side_effect=[(200, receipt), (200, denied)]), \
                patch("cvp_cli.uuce.request_json") as execute:
            with self.assertRaises(UuceError) as error:
                convert_units(case["inputs"], binding=receipt["binding"], use_case="standalone_low_risk")
            execute.assert_not_called()
        self.assertEqual((error.exception.decision, error.exception.code), ("DENY", "CONVERSION_OUTSIDE_POLICY"))

    def test_expanded_policy_pins_gate_both_cli_and_sdk(self):
        options, case, receipt, reply = self.production_fixture()
        policy = json.loads((EXAMPLES.parent / "releases/uuce-agent-policy-1.1.0.json").read_bytes())
        policy["binding"] = receipt["binding"]
        digest = policy["policy_sha256"]
        expanded_reply = {**reply, "policy_version": "1.1.0", "policy_sha256": digest}
        policy_file = Path(options[options.index("--release-record") + 1]).with_name("policy.json")
        policy_file.write_text(json.dumps(policy), encoding="utf-8")
        with patch("cvp_cli.preflight.request_json", side_effect=[(200, receipt), (200, expanded_reply)]) as request, \
                patch("cvp_cli.__main__.observe", return_value=case["expected"]):
            code, report = self.verify(UUCE_PIN, *options, "--agent-policy", policy_file)
        self.assertEqual(code, 0, report)
        self.assertEqual(request.call_args.kwargs["body"]["policy_sha256"], digest)
        self.assertEqual(report["live_probe"]["cases"][0]["production_preflight"]["policy_sha256"], digest)
        mass = {**case["inputs"], "from_unit_id": "cx:kg", "to_unit_id": "cx:g", "quantity_kind": "mass"}
        approved_mass = {**expanded_reply, "execute": {
            **expanded_reply["execute"], "body": {"calculation_version": "0.1.1", "inputs": mass},
        }}
        sdk = {"binding": receipt["binding"], "use_case": "standalone_low_risk", "policy": policy}
        with patch("cvp_cli.preflight.request_json", side_effect=[(200, receipt), (200, approved_mass)]), \
                patch("cvp_cli.uuce.request_json", return_value=(200, {})) as execute, \
                patch("cvp_cli.uuce.check_uuce_result", return_value={"decimal": "2e3"}):
            converted = convert_units(mass, **sdk)
        execute.assert_called_once()
        self.assertEqual(converted["production_preflight"]["policy_version"], "1.1.0")
        for bad_policy, bad_reply, message in (
            ({**policy, "groups": {"mass": ["cx:kg", "cx:g"]}}, approved_mass, "scope does not match"),
            (policy, {**approved_mass, "policy_sha256": "0" * 64}, "policy pins differ"),
        ):
            with patch("cvp_cli.preflight.request_json", side_effect=[(200, receipt), (200, bad_reply)]), \
                    patch("cvp_cli.uuce.request_json") as execute:
                with self.assertRaisesRegex(UuceError, message):
                    convert_units(mass, **{**sdk, "policy": bad_policy})
                execute.assert_not_called()

    def test_examples_replay_offline(self):
        with patch("cvp_cli.__main__.observe") as live:
            for name, pin, count in (("uuce", UUCE_PIN, 14), ("percentage", PERCENTAGE_PIN, 8)):
                code, result = invoke("verify", EXAMPLES / name, "--manifest-sha256", pin)
                self.assertEqual(code, 0, result)
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(len(result["reference_replay"]["cases"]), count)
                self.assertEqual(result["live_probe"]["status"], "NOT_RUN")
            live.assert_not_called()

    def test_canonical_unit_profiles(self):
        bindings = json.loads((EXAMPLES / "uuce" / "manifest.json").read_text())["bindings"]
        cases = (
            (CelsiusKelvinReference, "c-k", "-273.15", {"binary64_hex": "0000000000000000"}),
            (CelsiusKelvinReference, "c-k", "-273.1500000000000000001",
             {"error": {"code": "VALUE_OUT_OF_RANGE", "field": "value"}}),
            (PsiBarReference, "psi-bar", "14.503773773020923", {"binary64_hex": "3ff0000000000000"}),
            (PsiBarReference, "psi-bar", "5e-324",
             {"error": {"code": "NUMERIC_UNDERFLOW", "field": "value"}}),
        )
        for profile, mode, value, expected in cases:
            with self.subTest(profile=profile, value=value):
                reference = profile(bindings, {})
                self.assertEqual(reference.replay({"mode": mode, "value": value}), expected)
        self.assertEqual(PsiBarReference(bindings, {}).observe({"result": 1}, {}),
                         {"binary64_hex": "3ff0000000000000"})

    def test_altered_manifest_fails_even_when_artifacts_are_valid(self):
        self.repin(lambda manifest: manifest.update(revision="different"))
        code, result = self.verify()
        self.assertEqual(code, 2)
        self.assertEqual(result["reference_replay"]["status"], "NOT_RUN")
        self.assertIn("Manifest SHA-256 mismatch", result["error"])

    def test_altered_cases_fail_artifact_check(self):
        path = self.root / "cases.json"
        path.write_bytes(path.read_bytes() + b" ")
        code, result = self.verify()
        self.assertEqual(code, 2)
        self.assertIn("SHA-256 mismatch for cases.json", result["error"])

    def test_rehashed_incorrect_expectation_fails_replay(self):
        path = self.root / "cases.json"
        cases = json.loads(path.read_text(encoding="utf-8"))
        cases["cases"][0]["expected"]["exact"]["numerator"] = "999"
        path.write_text(json.dumps(cases), encoding="utf-8")
        with patch("cvp_cli.__main__.observe") as live:
            code, result = self.verify(self.repin(rehash_cases=True), "--live", "https://www.example.com")
        self.assertEqual(code, 1)
        self.assertEqual(result["artifact_integrity"]["status"], "PASS")
        self.assertEqual(result["reference_replay"]["cases"][0]["status"], "FAIL")
        live.assert_not_called()

    def test_profile_cannot_claim_other_capability(self):
        code, result = self.verify(self.repin(lambda m: m.update(capability_id="math.percentage")))
        self.assertEqual(code, 2)
        self.assertIn("Profile capability or version mismatch", result["error"])

    def test_file_list_cannot_escape_pack(self):
        pin = self.repin(lambda m: m["files"].update({"../outside.json": "0" * 64}))
        code, result = self.verify(pin)
        self.assertEqual(code, 2)
        self.assertIn("Unsafe evidence filename", result["error"])

    def test_symlink_file_rejected(self):
        path = self.root / "cases.json"
        target = path.rename(self.root / "copy.json")
        try:
            path.symlink_to(target)
        except OSError as error:
            self.skipTest(str(error))
        code, result = self.verify()
        self.assertEqual(code, 2)
        self.assertIn("Expected a regular file", result["error"])

    def test_json_strictness(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":"\\ud800"}',
                    b"[" * 40 + b"0" + b"]" * 40):
            with self.subTest(raw=raw), self.assertRaises(PackError):
                parse_json(raw, "test")

    def test_probe_error_is_distinct_from_math_failure(self):
        with patch("cvp_cli.__main__.observe", side_effect=ProbeError("network unavailable")):
            code, result = self.verify(UUCE_PIN, "--live", "https://www.example.com",
                                       "--live-case", "half-turn")
        self.assertEqual(code, 2)
        self.assertEqual(result["reference_replay"]["status"], "PASS")
        self.assertEqual(result["live_probe"]["cases"][0]["status"], "ERROR")

    def test_probe_wrong_value_is_failure(self):
        with patch("cvp_cli.__main__.observe", return_value={"wrong": True}):
            code, result = self.verify(UUCE_PIN, "--live", "https://www.example.com",
                                       "--live-case", "half-turn")
        self.assertEqual(code, 1)
        self.assertEqual(result["live_probe"]["cases"][0]["status"], "FAIL")

    def test_live_origin_and_case_allowlist(self):
        for origin, case in (("http://example.com", "half-turn"), ("https://example.com/path", "half-turn"),
                             ("https://example.com", "missing")):
            with self.subTest(origin=origin, case=case), patch("cvp_cli.__main__.observe") as live:
                code, _ = self.verify(UUCE_PIN, "--live", origin, "--live-case", case)
                self.assertEqual(code, 2)
                live.assert_not_called()

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL not available")
    def test_detached_signature_and_tampering(self):
        key, public, signature = [Path(self.temp.name) / name for name in ("key.pem", "public.pem", "manifest.sig")]
        commands = [
            ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
            ["pkey", "-in", str(key), "-pubout", "-out", str(public)],
            ["dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(self.root / "manifest.json")],
        ]
        for args in commands:
            subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        options = ("verify", self.root, "--public-key", public, "--signature", signature)
        code, result = invoke(*options)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["artifact_integrity"]["trust"], "detached-signature")
        self.repin(lambda manifest: manifest.update(revision="tampered"))
        code, result = invoke(*options)
        self.assertEqual(code, 2)
        self.assertIn("Manifest signature does not match", result["error"])


if __name__ == "__main__":
    unittest.main()
