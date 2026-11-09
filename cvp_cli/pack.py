"""Read bounded, data-only evidence bundles and verify their trust anchor."""

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

FORMAT = "cvp-replay-pack-v1"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_CASES = 2000
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FILE_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\.json\Z")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")


class PackError(ValueError):
    """Malformed evidence, unsupported contract, or failed integrity check."""


def require(condition, message):
    if not condition:
        raise PackError(message)


def object_fields(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected), f"{label}: unexpected or missing fields")
    return value


def valid_text(value, limit=1000):
    return isinstance(value, str) and 0 < len(value) <= limit and all(
        char.isprintable() and not 0xD800 <= ord(char) <= 0xDFFF for char in value
    )


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _invalid_constant(value):
    raise PackError(f"Non-finite JSON constant: {value}")


def _bounded_int(value):
    require(len(value) <= 64, "JSON integers longer than 64 characters must use strings")
    return int(value)


def _bounded_float(value):
    from math import isfinite

    require(len(value) <= 128, "Oversized JSON number")
    result = float(value)
    require(isfinite(result), "Non-finite JSON number")
    return result


def parse_json(raw, label):
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields, parse_int=_bounded_int,
                              parse_float=_bounded_float, parse_constant=_invalid_constant)
        _validate_tree(document, 0)
        return document
    except (ValueError, RecursionError) as error:
        raise PackError(f"{label}: {error}") from error


def _validate_tree(value, depth):
    require(depth <= 32, "JSON nesting exceeds 32 levels")
    if isinstance(value, str):
        value.encode("utf-8")  # Reject escaped unpaired surrogates.
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _validate_tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_tree(item, depth + 1)


def _read_file(path, limit):
    try:
        require(stat.S_ISREG(path.lstat().st_mode), f"Expected a regular file: {path.name}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), f"Expected a regular file: {path.name}")
            raw = handle.read(limit + 1)
    except OSError as error:
        raise PackError(f"Cannot read {path.name}: {error.strerror}") from error
    require(len(raw) <= limit, f"File exceeds its size limit: {path.name}")
    return raw


def _verify_signature(raw, public_key, signature):
    from tempfile import TemporaryDirectory

    # Pass the already-read bytes on stdin. Pack files never become commands.
    key_bytes = _read_file(public_key, MAX_MANIFEST_BYTES)
    signature_bytes = _read_file(signature, MAX_MANIFEST_BYTES)
    require(key_bytes.startswith(b"-----BEGIN PUBLIC KEY-----"), "Supply a PEM public key")
    with TemporaryDirectory(prefix="cvp-signature-") as directory:
        key = Path(directory) / "trusted.pem"
        sig = Path(directory) / "manifest.sig"
        key.write_bytes(key_bytes)
        sig.write_bytes(signature_bytes)
        try:
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(sig)],
                input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PackError(f"OpenSSL signature verification unavailable: {error}") from error
    require(result.returncode == 0, "Manifest signature does not match the trusted public key")


def load_pack(root, *, manifest_sha256=None, public_key=None, signature=None):
    raw = _read_file(root / "manifest.json", MAX_MANIFEST_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    if manifest_sha256 is not None:
        require(SHA256.fullmatch(manifest_sha256) and digest == manifest_sha256, "Manifest SHA-256 mismatch")
        trust = "sha256-pin"
    elif public_key is not None:
        _verify_signature(raw, public_key, signature or root / "manifest.sig")
        trust = "detached-signature"
    else:
        raise PackError("Supply a trusted manifest SHA-256 or publisher public key")

    manifest = object_fields(parse_json(raw, "manifest.json"), (
        "format", "capability_id", "calculation_version", "revision", "profile", "scope", "bindings", "files",
    ), "manifest")
    require(manifest["format"] == FORMAT, "Unsupported evidence pack format")
    for key in ("capability_id", "calculation_version", "revision", "profile"):
        require(isinstance(manifest[key], str) and IDENTIFIER.fullmatch(manifest[key]), f"Invalid {key}")
    require(valid_text(manifest["scope"]), "Invalid scope")
    files = manifest["files"]
    require(isinstance(files, dict) and 1 <= len(files) <= 4 and "cases.json" in files, "Invalid file list")
    documents = {}
    for name, expected in files.items():
        require(FILE_NAME.fullmatch(name) and name != "manifest.json", "Unsafe evidence filename")
        require(isinstance(expected, str) and SHA256.fullmatch(expected), f"Invalid digest for {name}")
        artifact = _read_file(root / name, MAX_ARTIFACT_BYTES)
        require(hashlib.sha256(artifact).hexdigest() == expected, f"SHA-256 mismatch for {name}")
        documents[name] = parse_json(artifact, name)
    return manifest, documents, digest, trust


def read_cases(document):
    cases = object_fields(document, ("cases",), "cases.json")["cases"]
    require(isinstance(cases, list) and 1 <= len(cases) <= MAX_CASES, "Expected 1–2000 replay cases")
    seen = set()
    for case in cases:
        object_fields(case, ("id", "inputs", "expected", "source", "derivation"), "case")
        case_id = case["id"]
        require(isinstance(case_id, str) and IDENTIFIER.fullmatch(case_id), "Invalid case ID")
        require(case_id not in seen, f"Duplicate case ID: {case_id}")
        seen.add(case_id)
        require(isinstance(case["inputs"], dict) and isinstance(case["expected"], dict), f"{case_id}: invalid case data")
        require(valid_text(case["source"]) and valid_text(case["derivation"]), f"{case_id}: missing source or derivation")
    return cases
