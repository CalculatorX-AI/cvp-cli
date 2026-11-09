"""Command line for CVP evidence replay."""

import argparse
import json
from pathlib import Path

from . import __version__
from .live import MAX_LIVE_CASES, ProbeError, observe, observed_at, origin_url
from .pack import PackError, load_pack, read_cases, require
from .reference import PROFILES


def _matches(actual, expected):
    return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False)


def _row(case, actual):
    matches = _matches(actual, case["expected"])
    return {
        "id": case["id"], "status": "PASS" if matches else "FAIL", "source": case["source"],
        "derivation": case["derivation"], "expected": case["expected"], "actual": actual,
    }


def _status(rows):
    states = {row["status"] for row in rows}
    return "ERROR" if "ERROR" in states else "FAIL" if "FAIL" in states else "PASS"


def verify(args, report):
    manifest, documents, digest, trust = load_pack(
        args.pack, manifest_sha256=args.manifest_sha256, public_key=args.public_key, signature=args.signature,
    )
    report["artifact_integrity"] = {"status": "PASS", "trust": trust, "manifest_sha256": digest}
    report["pack"] = {key: manifest[key] for key in (
        "capability_id", "calculation_version", "revision", "profile", "scope", "bindings",
    )}
    profile_type = PROFILES.get(manifest["profile"])
    require(profile_type is not None, "Unsupported profile")
    require((manifest["capability_id"], manifest["calculation_version"]) ==
            (profile_type.capability_id, profile_type.calculation_version), "Profile capability or version mismatch")
    require(set(documents) == profile_type.files, "Unexpected files for this profile")
    profile = profile_type(manifest["bindings"], documents)
    cases = read_cases(documents["cases.json"])
    report["reference_replay"] = {"status": "ERROR", "cases": []}
    rows = report["reference_replay"]["cases"]
    for case in cases:
        try:
            rows.append(_row(case, profile.replay(case["inputs"])))
        except PackError as error:
            rows.append({"id": case["id"], "status": "ERROR", "detail": str(error)})
    status = _status(rows)
    report["reference_replay"]["status"] = status
    if status != "PASS":
        return 1 if status == "FAIL" else 2
    if args.live is None:
        return 0

    origin = origin_url(args.live)
    selected = set(args.live_case or [])
    subset = [case for case in cases if not selected or case["id"] in selected]
    require(not selected or selected == {case["id"] for case in subset}, "Unknown --live-case ID")
    require(len(subset) <= MAX_LIVE_CASES, "Select up to 40 live cases with --live-case")
    report["live_probe"] = {"status": "ERROR", "origin": origin, "started_at": observed_at(), "cases": []}
    rows = report["live_probe"]["cases"]
    for case in subset:
        try:
            rows.append(_row(case, observe(origin, profile, case["inputs"])))
        except ProbeError as error:
            rows.append({"id": case["id"], "status": "ERROR", "detail": str(error)})
    status = _status(rows)
    report["live_probe"].update(status=status, finished_at=observed_at())
    return {"PASS": 0, "FAIL": 1, "ERROR": 2}[status]


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cvp", description="Verify a versioned public CVP replay pack")
    parser.add_argument("--version", action="version", version=__version__)
    command = parser.add_subparsers(dest="command", required=True)
    verify_parser = command.add_parser("verify", help="Authenticate an evidence pack and replay its public cases")
    verify_parser.add_argument("pack", type=Path, help="Directory containing manifest.json")
    trust = verify_parser.add_mutually_exclusive_group(required=True)
    trust.add_argument("--manifest-sha256", help="Manifest digest obtained from a trusted release channel")
    trust.add_argument("--public-key", type=Path, help="Trusted publisher PEM key obtained separately")
    verify_parser.add_argument("--signature", type=Path, help="Detached signature, defaults to PACK/manifest.sig")
    verify_parser.add_argument("--live", metavar="HTTPS_ORIGIN", help="Also compare the selected cases with this API origin")
    verify_parser.add_argument("--live-case", action="append", metavar="ID", help="Limit live requests to this case ID, repeatable")
    verify_parser.add_argument("--json", action="store_true", help="Write a machine-readable report to stdout")
    args = parser.parse_args(argv)
    if args.signature and not args.public_key:
        parser.error("--signature requires --public-key")
    if args.live_case and not args.live:
        parser.error("--live-case requires --live")

    report = {
        "format": "cvp-replay-report-v1", "verifier_version": __version__,
        "artifact_integrity": {"status": "ERROR"}, "reference_replay": {"status": "NOT_RUN"},
        "live_probe": {"status": "NOT_RUN"},
    }
    try:
        code = verify(args, report)
    except PackError as error:
        report["error"] = str(error)
        code = 2
    report["status"] = {0: "PASS", 1: "FAIL", 2: "ERROR"}[code]
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    else:
        pack = report.get("pack", {})
        if pack:
            print(f"{pack['capability_id']}@{pack['calculation_version']} ({pack['revision']})")
            print(pack["scope"])
        for stage in ("artifact_integrity", "reference_replay", "live_probe"):
            result = report[stage]
            cases = result.get("cases", [])
            suffix = f" ({len(cases)} cases)" if cases else ""
            print(f"{stage}: {result['status']}{suffix}")
            for row in cases:
                if row["status"] != "PASS":
                    print(f"  {row['id']}: {row['status']} {row.get('detail', '')}")
                    if row["status"] == "FAIL":
                        print(f"    expected {json.dumps(row['expected'], ensure_ascii=False)}")
                        print(f"    actual   {json.dumps(row['actual'], ensure_ascii=False)}")
        if report.get("error"):
            print(f"ERROR: {report['error']}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
