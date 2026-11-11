"""Application client for the versioned CalculatorX UUCE preflight contract."""

from pathlib import Path

from .live import ProbeError, check_uuce_result, request_json
from .pack import SHA256, load_pack
from .preflight import ORIGIN, USE_CASE, approve, pinned_binding

CALCULATION_VERSION = "0.1.1"
CONVERSION_PATH = "/api/v1/units/convert"
BINDING_FIELDS = {
    "profile", "verification_revision", "cvp_core_sha256", "registry_version",
    "definition_sha256", "execution_projection_sha256", "integrity_manifest_sha256", "numerical_policy",
}
INPUT_FIELDS = {"value", "from_unit_id", "to_unit_id", "quantity_kind", "role", "snapshot"}


class UuceError(RuntimeError):
    def __init__(self, message, *, decision=None, code=None, status=None, retry_after=None):
        super().__init__(message)
        self.decision = decision
        self.code = code
        self.status = status
        self.retry_after = retry_after


def binding_from_release(pack, release_record, *, manifest_sha256):
    """Resolve pins from an authenticated pack and a separately trusted release record."""
    manifest, _, digest, _ = load_pack(Path(pack), manifest_sha256=manifest_sha256)
    return pinned_binding(Path(release_record), manifest, digest)


def convert_units(inputs: dict[str, str], *, binding: dict[str, str], use_case: str, policy=None) -> dict:
    """Run an explicitly low-risk conversion only after production approval."""
    if use_case != USE_CASE:
        raise UuceError("Confirm standalone_low_risk before requesting a conversion",
                        decision="NEED_CONTEXT", code="CONTEXT_REQUIRED")
    inputs, binding = dict(inputs), dict(binding)
    if (set(binding) != BINDING_FIELDS or any(not isinstance(pin, str) or not pin for pin in binding.values())
            or any(not SHA256.fullmatch(pin) for name, pin in binding.items() if name.endswith("_sha256"))):
        raise UuceError("Supply a complete, independently trusted UUCE binding", code="INVALID_TRUST_PIN")
    if set(inputs) != INPUT_FIELDS or any(not isinstance(value, str) or not value for value in inputs.values()):
        raise UuceError("Supply explicit unit IDs, decimal text, quantity kind, role and snapshot", code="INVALID_INPUT")
    gate = {}
    try:
        approve(CALCULATION_VERSION, binding, inputs, gate, policy=policy)
        _, response = request_json(
            ORIGIN + CONVERSION_PATH, body={"calculation_version": CALCULATION_VERSION, "inputs": inputs},
            version=CALCULATION_VERSION,
        )
        result = check_uuce_result(response, CALCULATION_VERSION, binding, inputs)
    except ProbeError as error:
        decision = gate.get("decision")
        code = gate.get("code") if decision in ("DENY", "NEED_CONTEXT") else None
        if error.status == 429:
            code = "RATE_LIMITED"
        raise UuceError(str(error), decision=decision, code=code,
                        status=error.status, retry_after=error.retry_after) from error
    return {"result": result, "production_preflight": gate}
