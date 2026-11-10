"""Authenticate the production receipt and gate an explicit UUCE live probe."""

import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from urllib.parse import urlencode

from .live import ProbeError, request_json
from .pack import IDENTIFIER, MAX_MANIFEST_BYTES, SHA256, _read_file, parse_json, require
from .reference import UUCE_POLICY

ORIGIN = "https://www.calculatorx.com"
USE_CASE = "standalone_low_risk"
POLICY_VERSION = "1.0.0"
RECEIPT_CONTRACT = "calculatorx-cvp-production-receipt-v1"
PREFLIGHT_CONTRACT = "calculatorx-uuce-agent-preflight-v1"
INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
VALUE = re.compile(r"(?:0|[1-9][0-9]{0,6})(?:\.[0-9]{1,12})?")


def pinned_binding(path, manifest, manifest_digest):
    require((manifest["capability_id"], manifest["calculation_version"], manifest["profile"]) ==
            ("units.convert", "0.1.1", "uuce-v1"), "Preflight supports units.convert 0.1.1 only")
    doc = parse_json(_read_file(path, MAX_MANIFEST_BYTES), "Trusted release record")
    require(isinstance(doc, dict) and doc.get("format") == "calculatorx-cvp-replay-releases-v1"
            and isinstance(doc.get("packs"), list), "Unexpected trusted release record format")
    matches = [
        row for row in doc["packs"]
        if isinstance(row, dict) and row.get("manifest_sha256") == manifest_digest
        and all(row.get(key) == manifest[key]
                for key in ("capability_id", "calculation_version", "revision", "profile"))
    ]
    require(len(matches) == 1, "Trusted release record must uniquely pin this pack")
    row = matches[0]
    revision, core = row.get("cvp_verification_revision"), row.get("cvp_core_sha256")
    require(isinstance(revision, str) and IDENTIFIER.fullmatch(revision)
            and isinstance(core, str) and SHA256.fullmatch(core), "Invalid release CVP pins")
    bindings = manifest["bindings"]
    return {
        "profile": "engineering", "verification_revision": revision, "cvp_core_sha256": core,
        "registry_version": bindings["version"], "definition_sha256": bindings["content_digest"],
        "execution_projection_sha256": bindings["execution_projection_sha256"],
        "integrity_manifest_sha256": bindings["integrity_manifest_sha256"], "numerical_policy": UUCE_POLICY,
    }


def _instant(value):
    if not isinstance(value, str) or not INSTANT.fullmatch(value):
        raise ProbeError("Production receipt timestamp is invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProbeError("Production receipt timestamp is invalid") from error


def _receipt_expiry(receipt, version, binding):
    attestation_id = receipt.get("attestation_id")
    if (receipt.get("contract") != RECEIPT_CONTRACT or receipt.get("issuer") != ORIGIN
            or receipt.get("capability_id") != "units.convert" or receipt.get("calculation_version") != version
            or receipt.get("production_freshness") != "CURRENT" or receipt.get("binding") != binding
            or not isinstance(attestation_id, str) or not SHA256.fullmatch(attestation_id)):
        raise ProbeError("Production receipt is not current or differs from the trusted pins")
    checked, expires = (_instant(receipt.get(field)) for field in ("checked_at", "expires_at"))
    if expires - checked != timedelta(days=7) or not checked <= datetime.now(timezone.utc) < expires:
        raise ProbeError("Production receipt is expired, future-dated, or has an invalid validity window")
    return expires


def _in_policy(inputs, binding):
    value = inputs.get("value")
    return (
        inputs.get("quantity_kind") == "length" and inputs.get("role") == "scalar"
        and (inputs.get("from_unit_id"), inputs.get("to_unit_id")) in (("cx:m", "cx:ft_i"), ("cx:ft_i", "cx:m"))
        and inputs.get("snapshot") == binding["registry_version"]
        and isinstance(value, str) and VALUE.fullmatch(value) and Decimal(value) <= 1000000
    )


def approve(version, binding, inputs, report):
    query = urlencode({"capability_id": "units.convert", "calculation_version": version})
    _, receipt = request_json(ORIGIN + "/api/v1/cvp/receipt?" + query)
    _receipt_expiry(receipt, version, binding)
    envelope = {"calculation_version": version, "inputs": inputs}
    _, reply = request_json(ORIGIN + "/api/v1/units/preflight", body={
        **envelope, "policy_version": POLICY_VERSION, "trust": binding, "context": {"use_case": USE_CASE},
    })
    if reply.get("contract") != PREFLIGHT_CONTRACT or reply.get("policy_version") != POLICY_VERSION:
        raise ProbeError("Unknown production preflight contract or policy version")
    decision, code = reply.get("decision"), reply.get("code")
    if not isinstance(code, str) or not IDENTIFIER.fullmatch(code.lower()):
        raise ProbeError("Invalid production preflight code")
    if decision in ("DENY", "NEED_CONTEXT"):
        report.update(decision=decision, code=code)
        raise ProbeError(f"Production preflight returned {decision} ({code})")
    if (decision != "ALLOW" or code != "IN_POLICY" or not _in_policy(inputs, binding)
            or reply.get("receipt") != receipt
            or reply.get("execute") != {"method": "POST", "path": "/api/v1/units/convert", "body": envelope}):
        raise ProbeError("Production preflight approval does not match the pinned policy, receipt, or request")
    _receipt_expiry(receipt, version, binding)
    report.update(decision="ALLOW", code=code, policy_version=POLICY_VERSION,
                  attestation_id=receipt["attestation_id"], expires_at=receipt["expires_at"])
