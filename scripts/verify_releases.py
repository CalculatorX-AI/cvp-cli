"""Verify every released pack using pins from this CLI checkout."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import Request, build_opener

from cvp_cli import __version__
from cvp_cli.live import NoRedirect

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://www.calculatorx.com"
MAX_ARTIFACT_BYTES = 1024 * 1024
RELEASE_FORMAT = "calculatorx-cvp-replay-releases-v1"
FILES = {"manifest.json", "cases.json"}
BASE_PATH = re.compile(
    r"/developers/cvp/packs/[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+"
    r"/[0-9]+\.[0-9]+\.[0-9]+/public-replay-[1-9][0-9]*"
)


def release_rows():
    seen = set()
    for path in sorted((ROOT / "releases").glob("public-replay-*.json")):
        release = json.loads(path.read_bytes())
        if release["format"] != RELEASE_FORMAT or not release["packs"]:
            raise ValueError(f"{path.name}: invalid or empty release record")
        for row in release["packs"]:
            base = row["base_path"]
            expected_path = "/developers/cvp/packs/{capability_id}/{calculation_version}/{revision}".format(**row)
            if (not BASE_PATH.fullmatch(base) or base != expected_path or row["revision"] != path.stem
                    or base in seen or not re.fullmatch(r"[a-f0-9]{64}", row["manifest_sha256"])):
                raise ValueError(f"{path.name}: invalid or duplicate pack pin for {base}")
            files = set(row["files"])
            if len(files) != len(row["files"]) or files not in (FILES, FILES | {"reference-units.json"}):
                raise ValueError(f"{base}: unexpected release files")
            seen.add(base)
            yield row
    if not seen:
        raise ValueError("No release records found")


def download_pack(opener, row, destination):
    destination.mkdir()
    for name in row["files"]:
        url = ORIGIN + row["base_path"] + "/" + name
        request = Request(url, headers={
            "Accept": "application/json",
            "User-Agent": f"cvp-replay-ci/{__version__}",
        })
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise ValueError(f"{url}: expected HTTP 200, got {response.status}")
            data = response.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError(f"{url}: artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
        (destination / name).write_bytes(data)


def verify_pack(pack, row):
    command = [sys.executable, "-B", "-m", "cvp_cli", "verify", str(pack),
               "--manifest-sha256", row["manifest_sha256"], "--json"]
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if process.returncode:
        raise ValueError(f"{row['base_path']}: verifier exited with {process.returncode}\n"
                         f"{process.stdout}{process.stderr}")
    report = json.loads(process.stdout)
    pack_identity = report["pack"]
    replay = report["reference_replay"]
    count = len(replay["cases"])
    if (any(pack_identity[field] != row[field] for field in ("capability_id", "calculation_version", "revision", "profile"))
            or count != row["case_count"] or replay["status"] != "PASS"):
        raise ValueError(f"{row['base_path']}: replay report differs from the release record")
    print(f"{row['base_path']}: {count} cases PASS", flush=True)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-dir", type=Path, help="Use a local publication tree instead of downloading.")
    args = parser.parse_args()
    try:
        rows = list(release_rows())
        count = 0
        if args.public_dir:
            public = args.public_dir.resolve()
            for row in rows:
                count += verify_pack(public / row["base_path"].lstrip("/"), row)
        else:
            opener = build_opener(NoRedirect())
            with tempfile.TemporaryDirectory(prefix="cvp-release-") as temp:
                for i, row in enumerate(rows):
                    pack = Path(temp) / str(i)
                    download_pack(opener, row, pack)
                    count += verify_pack(pack, row)
        print(f"CVP CLI {__version__}: {len(rows)} release packs, {count} cases PASS")
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"CVP release replay failed: {error}\n")


if __name__ == "__main__":
    main()
