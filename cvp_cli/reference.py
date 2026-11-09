"""Independent reference arithmetic for the supported public profiles."""

import math
import re
import struct
from decimal import Context, Decimal, ROUND_HALF_EVEN
from fractions import Fraction

from .pack import SHA256, PackError, object_fields, require, valid_text

DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE]([+-]?[0-9]+))?\Z")
UUCE_DECIMAL = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE]([+-]?(?:[0-2]?[0-9]{1,2}|30[0-8])))?\Z")
RATIONAL = re.compile(r"-?[0-9]{1,128}(?:/[1-9][0-9]{0,127})?\Z")
UNIT_ID = re.compile(r"cx:[A-Za-z0-9_.-]{1,124}\Z")
ROLES = {"scalar", "point", "interval"}
PI = Fraction("3.14159265358979323846264338327950288419716939937510582097494459230781640628620899")
UUCE_POLICY = "uuce-rational-pi-decimal34-v1"


def bounded_decimal(value, *, uuce=False):
    pattern = UUCE_DECIMAL if uuce else DECIMAL
    limit = 128 if uuce else 512
    match = pattern.fullmatch(value) if isinstance(value, str) and len(value) <= limit else None
    if match is None or abs(int(match[1] or "0")) > (308 if uuce else 1000):
        return None
    return Fraction(value)


def rational(value):
    require(isinstance(value, str) and RATIONAL.fullmatch(value), "Invalid rational constant")
    return Fraction(value)


def rejected(code, field):
    return {"error": {"code": code, "field": field}}


def binary64_hex(value):
    require(type(value) in (int, float), "Expected a binary64 number")
    try:
        value = float(value)
    except OverflowError as error:
        raise PackError("Binary64 value is out of range") from error
    require(math.isfinite(value), "Binary64 value must be finite")
    return struct.pack(">d", value).hex()


def project(value):
    try:
        number = float(value)
    except OverflowError:
        return None, "overflow"
    if not math.isfinite(number):
        return None, "overflow"
    if number == 0 and value:
        return None, "underflow"
    return binary64_hex(number), "finite"


def decimal34(value):
    if not value:
        return "0"
    context = Context(prec=34, rounding=ROUND_HALF_EVEN)
    decimal = context.divide(Decimal(value.numerator), Decimal(value.denominator))
    mantissa, exponent = format(decimal, "e").split("e")
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    return f"{mantissa}e{int(exponent)}"


class UuceReference:
    capability_id = "units.convert"
    calculation_version = "0.1.1"
    endpoint = "/api/v1/units/convert"
    files = {"cases.json", "reference-units.json"}

    def __init__(self, bindings, documents):
        self.snapshot = object_fields(bindings, (
            "version", "content_digest", "execution_projection_sha256", "integrity_manifest_sha256",
        ), "UUCE snapshot bindings")
        require(valid_text(self.snapshot["version"], 100), "Invalid registry version")
        for name in ("content_digest", "execution_projection_sha256", "integrity_manifest_sha256"):
            value = self.snapshot[name]
            require(isinstance(value, str) and SHA256.fullmatch(value), f"Invalid {name}")
        definitions = object_fields(documents["reference-units.json"], ("units",), "reference units")["units"]
        require(isinstance(definitions, dict) and 1 <= len(definitions) <= 512, "Invalid reference unit list")
        self.units = {}
        for unit_id, definition in definitions.items():
            require(UNIT_ID.fullmatch(unit_id), f"Invalid unit ID {unit_id!r}")
            definition = object_fields(definition, ("transforms", "source"), f"unit {unit_id}")
            require(valid_text(definition["source"]), f"{unit_id}: missing independent source")
            transforms = definition["transforms"]
            require(isinstance(transforms, dict) and 1 <= len(transforms) <= 8, f"{unit_id}: invalid transforms")
            unit_transforms = {}
            for kind, transform in transforms.items():
                require(valid_text(kind, 80), "Invalid quantity kind")
                transform = object_fields(transform, ("reference", "scale", "offset", "pi_power", "roles"), "transform")
                reference = transform["reference"]
                require(isinstance(reference, str) and UNIT_ID.fullmatch(reference), "Invalid reference unit")
                roles = transform["roles"]
                require(isinstance(roles, list) and 1 <= len(roles) <= 3 and all(
                    isinstance(role, str) and role in ROLES for role in roles
                ) and len(set(roles)) == len(roles), "Invalid role list")
                scale, offset = rational(transform["scale"]), rational(transform["offset"])
                power = transform["pi_power"]
                require(scale > 0 and type(power) is int and -4 <= power <= 4, "Invalid exact scale")
                unit_transforms[kind] = (reference, scale, offset, power, roles)
            self.units[unit_id] = unit_transforms
        for transforms in self.units.values():
            for kind, (reference, _, _, _, roles) in transforms.items():
                target = self.units.get(reference, {}).get(kind)
                require(target is not None and target[:4] == (reference, 1, 0, 0) and
                        set(roles) <= set(target[4]), "Reference transform must be a supported identity")

    def replay(self, inputs):
        object_fields(inputs, ("value", "from_unit_id", "to_unit_id", "quantity_kind", "role", "snapshot"), "UUCE inputs")
        if not isinstance(inputs["snapshot"], str) or not inputs["snapshot"]:
            return rejected("INVALID_INPUT", "snapshot")
        if inputs["snapshot"] != self.snapshot["version"]:
            return rejected("SNAPSHOT_MISMATCH", "snapshot")
        source, target = inputs["from_unit_id"], inputs["to_unit_id"]
        require(isinstance(source, str) and isinstance(target, str) and source in self.units and target in self.units,
                "The public reference table does not define a requested unit")
        kind, role = inputs["quantity_kind"], inputs["role"]
        require(isinstance(kind, str) and isinstance(role, str), "Quantity kind and role must be strings")
        a, b = self.units[source].get(kind), self.units[target].get(kind)
        if a is None or b is None:
            return rejected("QUANTITY_KIND_MISMATCH", "quantity_kind")
        if role not in a[4] or role not in b[4]:
            return rejected("UNIT_ROLE_MISMATCH", "role")
        if a[0] != b[0]:
            return rejected("UNSUPPORTED_CONVERSION", "to_unit_id")
        value = bounded_decimal(inputs["value"], uuce=True)
        if value is None:
            return rejected("INVALID_INPUT", "value")
        offset = a[2] - b[2] if role == "point" else 0
        if offset and (a[3] or b[3]):
            return rejected("UNSUPPORTED_CONVERSION", "role")
        if kind == "temperature" and role == "point" and value * a[1] + a[2] < 0:
            return rejected("VALUE_OUT_OF_RANGE", "value")
        coefficient = (value * a[1] + offset) / b[1]
        power = a[3] - b[3] if coefficient else 0
        approximation = coefficient * PI ** power
        bits, status = project(approximation)
        return {
            "exact": {"numerator": str(coefficient.numerator), "denominator": str(coefficient.denominator), "pi_power": power},
            "decimal": decimal34(approximation),
            "binary64_hex": bits,
            "binary64_status": status,
        }

    def observe(self, response, inputs):
        result = response.get("result")
        require(isinstance(result, dict), "UUCE response has no result object")
        require(result.get("snapshot") == self.snapshot, "Live UUCE snapshot binding differs from the pack")
        require(result.get("numerical_policy") == UUCE_POLICY, "Live UUCE numerical policy differs")
        require(result.get("input") == {key: inputs[key] for key in ("value", "quantity_kind", "role")}, "Live UUCE input differs")
        for side in ("from", "to"):
            binding = result.get(side)
            require(isinstance(binding, dict) and binding.get("unit_id") == inputs[f"{side}_unit_id"], f"Live UUCE {side} unit differs")
        bits = result.get("binary64")
        require("binary64" in result, "Live UUCE binary64 projection is missing")
        return {"exact": result.get("exact"), "decimal": result.get("decimal"),
                "binary64_hex": None if bits is None else binary64_hex(bits), "binary64_status": result.get("binary64_status")}


class PercentageReference:
    capability_id = "math.percentage"
    calculation_version = "1.2.0"
    endpoint = "/api/v1/calc/percentage"
    files = {"cases.json"}
    fields = {"of": ("p", "x"), "is-what": ("x", "y"), "of-what": ("x", "p")}

    def __init__(self, bindings, documents):
        object_fields(bindings, (), "percentage bindings")

    def replay(self, inputs):
        mode = inputs.get("mode")
        require(isinstance(mode, str) and mode in self.fields, "Unsupported percentage reference mode")
        left, right = self.fields[mode]
        object_fields(inputs, ("mode", left, right), "percentage inputs")
        values = {}
        for field in (left, right):
            raw = inputs[field]
            if raw is None or (isinstance(raw, str) and not raw.strip()):
                return rejected("MISSING_REQUIRED_INPUT", field)
            require(isinstance(raw, str) and len(raw) <= 512, "Use bounded decimal strings in percentage cases")
            value = bounded_decimal(raw.strip())
            require(value is not None, "Unsupported decimal syntax or exponent in percentage case")
            try:
                number = float(value)
            except OverflowError:
                return rejected("INVALID_NUMBER", field)
            if value and not number:
                return rejected("NUMERIC_RANGE", field)
            values[field] = Fraction.from_float(number)
        a, b = values[left], values[right]
        if mode != "of" and b == 0:
            return rejected("DIVISION_BY_ZERO", right)
        value = a * b / 100 if mode == "of" else 100 * a / b
        bits, status = project(value)
        return rejected("NUMERIC_RANGE", "value") if status != "finite" else {
            "mode": mode, "unit": "%" if mode == "is-what" else None, "binary64_hex": bits,
        }

    def observe(self, response, inputs):
        result = response.get("result")
        require(isinstance(result, dict) and result.get("status") == "success", "Percentage response has no successful result")
        require(result.get("calculation_version") == self.calculation_version, "Percentage result version differs")
        require("unit" in result, "Percentage result unit is missing")
        return {"mode": result.get("mode"), "unit": result["unit"], "binary64_hex": binary64_hex(result.get("value"))}


PROFILES = {"uuce-v1": UuceReference, "percentage-v1": PercentageReference}
