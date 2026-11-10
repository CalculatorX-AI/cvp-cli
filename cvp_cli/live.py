"""Explicit, version-pinned HTTPS probes for built-in capability profiles."""

import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .pack import PackError, parse_json, require
from .reference import rejected

MAX_LIVE_CASES = 40
MAX_RESPONSE_BYTES = 256 * 1024


class ProbeError(RuntimeError):
    """A response could not be obtained or interpreted."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin_url(value):
    try:
        parts = urlsplit(value)
        port = parts.port
        require(parts.scheme == "https" and parts.hostname and parts.username is None and parts.password is None
                and parts.path in ("", "/") and not parts.query and not parts.fragment
                and (port is None or 0 < port <= 65535), "Live origin must be an HTTPS origin without credentials")
    except ValueError as error:
        raise PackError(f"Invalid live origin: {error}") from error
    return f"https://{parts.netloc}"


def request_json(url, *, body=None, statuses=(200,), version=None):
    headers = {"Accept": "application/json", "User-Agent": "cvp-replay-cli/0.1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if version is not None:
        headers["CalculatorX-Spec-Version"] = version
    request = Request(
        url, data=None if body is None else json.dumps(body, allow_nan=False).encode("utf-8"),
        headers={**headers, "Cache-Control": "no-cache"},
    )
    try:
        try:
            handle = build_opener(NoRedirect()).open(request, timeout=10)
        except HTTPError as error:
            handle = error
        with handle:
            status = handle.getcode()
            if status not in statuses:
                raise ProbeError(f"Unexpected HTTP {status}")
            raw = handle.read(MAX_RESPONSE_BYTES + 1)
    except (URLError, OSError, TimeoutError) as error:
        raise ProbeError(f"HTTPS probe failed: {error}") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProbeError("HTTPS response exceeds its size limit")
    try:
        response = parse_json(raw, "HTTPS response")
    except PackError as error:
        raise ProbeError(str(error)) from error
    if not isinstance(response, dict):
        raise ProbeError("HTTPS response must be a JSON object")
    return status, response


def observe(origin, profile, inputs, *, binding=None):
    body = {"inputs": inputs}
    if binding is not None:
        body["calculation_version"] = profile.calculation_version
    status, response = request_json(
        origin + profile.endpoint, body=body, version=profile.calculation_version,
        statuses=(200,) if binding is not None else (200, 400, 409, 422),
    )
    if response.get("capability_id") != profile.capability_id:
        raise ProbeError("Live capability ID differs")
    if response.get("calculation_version") != profile.calculation_version:
        raise ProbeError("Live calculation version differs")
    if status == 200:
        if response.get("status") != "success":
            raise ProbeError("HTTP 200 response lacks a success envelope")
        if binding is not None:
            verification = response.get("verification")
            if (not isinstance(verification, dict) or verification.get("cvp") != "verified"
                    or verification.get("calculation_version") != profile.calculation_version
                    or verification.get("verification_revision") != binding["verification_revision"]
                    or verification.get("evidence_digest") != binding["cvp_core_sha256"]
                    or verification.get("execution_projection_sha256") != binding["execution_projection_sha256"]):
                raise ProbeError("Live UUCE CVP binding differs from the approved request")
        try:
            return profile.observe(response, inputs)
        except PackError as error:
            raise ProbeError(str(error)) from error
    if response.get("status") != "error" or not isinstance(response.get("code"), str):
        raise ProbeError("HTTP rejection lacks a structured error code")
    return rejected(response["code"], response.get("field"))


def observed_at():
    return datetime.now(timezone.utc).isoformat()
