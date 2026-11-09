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


def _response(origin, profile, inputs):
    request = Request(
        origin + profile.endpoint, data=json.dumps({"inputs": inputs}, allow_nan=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "CalculatorX-Spec-Version": profile.calculation_version,
                 "User-Agent": "cvp-replay-cli/0.1"},
        method="POST",
    )
    try:
        try:
            handle = build_opener(NoRedirect()).open(request, timeout=10)
        except HTTPError as error:
            handle = error
        with handle:
            status = handle.getcode()
            if status not in (200, 400, 409, 422):
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


def observe(origin, profile, inputs):
    status, response = _response(origin, profile, inputs)
    if response.get("capability_id") != profile.capability_id:
        raise ProbeError("Live capability ID differs")
    if response.get("calculation_version") != profile.calculation_version:
        raise ProbeError("Live calculation version differs")
    if status == 200:
        if response.get("status") != "success":
            raise ProbeError("HTTP 200 response lacks a success envelope")
        try:
            return profile.observe(response, inputs)
        except PackError as error:
            raise ProbeError(str(error)) from error
    if response.get("status") != "error" or not isinstance(response.get("code"), str):
        raise ProbeError("HTTP rejection lacks a structured error code")
    return rejected(response["code"], response.get("field"))


def observed_at():
    return datetime.now(timezone.utc).isoformat()
