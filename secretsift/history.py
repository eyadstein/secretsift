"""Scan secrets that were ADDED anywhere in git history (even if deleted later)."""
from __future__ import annotations
import subprocess
from .scanner import scan_text


def scan_history(repo: str, mode: str = "ml", max_commits: int = 2000) -> list:
    cmd = ["git", "-C", repo, "log", "-p", "--all", "--no-color", "-U0", f"--max-count={max_commits}", "--format=commit:%H"]
    raw = subprocess.run(cmd, capture_output=True, text=True, errors="ignore").stdout
    out, commit, path, buf = [], "", "", []

    def flush():
        if commit and path and buf:
            for f in scan_text(f"{path}@{commit[:8]}", "\n".join(buf) + "\n", mode):
                out.append(f)

    for line in raw.splitlines():
        if line.startswith("commit:"):
            flush(); commit, path, buf = line[7:], "", []
        elif line.startswith("+++ b/"):
            flush(); path, buf = line[6:], []
        elif line.startswith("+") and not line.startswith("+++"):
            buf.append(line[1:])
    flush()
    return out
