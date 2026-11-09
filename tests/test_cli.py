import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvp_cli.__main__ import main
from cvp_cli.live import ProbeError
from cvp_cli.pack import PackError, parse_json

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

    def test_examples_replay_offline(self):
        with patch("cvp_cli.__main__.observe") as live:
            for name, pin, count in (("uuce", UUCE_PIN, 14), ("percentage", PERCENTAGE_PIN, 8)):
                code, result = invoke("verify", EXAMPLES / name, "--manifest-sha256", pin)
                self.assertEqual(code, 0, result)
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(len(result["reference_replay"]["cases"]), count)
                self.assertEqual(result["live_probe"]["status"], "NOT_RUN")
            live.assert_not_called()

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
