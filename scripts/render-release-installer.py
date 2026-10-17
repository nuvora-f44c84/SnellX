#!/usr/bin/env python3
"""Generate the public bootstrap with a fixed release URL and payload digest."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
release = json.loads((ROOT / "release.json").read_text())
repository, tag = release["repository"], release["tag"]
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
    raise ValueError("Invalid GitHub repository")
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag):
    raise ValueError("Invalid release tag")
payload = ROOT / "outputs" / "snell-auto.sh"
digest = hashlib.sha256(payload.read_bytes()).hexdigest()
source = (ROOT / "scripts" / "snell-release-install.sh").read_text()
for marker, value in {
    "__TEMPLATE_NOTE__": "Generated from scripts/snell-release-install.sh by scripts/render-release-installer.py; do not edit.",
    "__GITHUB_REPOSITORY__": repository,
    "__RELEASE_TAG__": tag,
    "__BUNDLE_SHA256__": digest,
}.items():
    if marker not in source:
        raise ValueError(f"Missing bootstrap placeholder: {marker}")
    source = source.replace(marker, value)
target = ROOT / "install.sh"
target.write_text(source)
target.chmod(0o755)
subprocess.run(["bash", "-n", str(target)], check=True)
print(f"Generated install.sh for {repository} {tag}; SHA256 {digest}")
