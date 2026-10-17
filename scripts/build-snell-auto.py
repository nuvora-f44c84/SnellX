#!/usr/bin/env python3
"""Build the self-contained distribution from audited local Bash components."""
from pathlib import Path
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "outputs" / "snell-auto.sh"
parts = [("installer", "snell-v6.sh"), ("menu", "snellx"), ("network", "snell-net.sh"), ("security", "snell-security.sh")]
text = (ROOT / "scripts" / "snell-auto-launcher.sh").read_text()
for name, filename in parts:
    source = (ROOT / "outputs" / filename).read_text()
    subprocess.run(["bash", "-n", str(ROOT / "outputs" / filename)], check=True)
    delimiter = f"SNELL_AUTO_{name.upper()}_PAYLOAD_END"
    if delimiter in source.splitlines():
        raise ValueError(f"heredoc delimiter collision: {filename}")
    text += f"\nwrite_{name}() {{\n  cat <<'{delimiter}'\n{source.rstrip()}\n{delimiter}\n}}\n"
text += '\nif [[ "${BASH_SOURCE[0]}" == "$0" ]]; then auto_main "$@"; fi\n'
OUT.write_text(text)
OUT.chmod(0o755)
subprocess.run(["bash", "-n", str(OUT)], check=True)
digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
(OUT.parent / "snell-auto.sh.sha256").write_text(f"{digest}  snell-auto.sh\n")
print(f"Built {OUT.name}: {OUT.stat().st_size} bytes; SHA256 {digest}")
