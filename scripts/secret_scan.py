"""Minimal secret scanner for staged files (pre-commit hook) or the whole tree.

Usage:
    python scripts/secret_scan.py --staged     # scan files staged for commit
    python scripts/secret_scan.py --all        # scan every tracked/untracked, non-ignored file

Exit code 1 if a possible secret is found. This is a safety net, not a replacement for a
full scanner such as gitleaks. Add `# secret-scan: ignore` on a line to allow a known fake value.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PLACEHOLDERS = ("change-me", "changeme", "your-", "example", "placeholder", "<", "xxx", "dummy")

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("Google AI Studio key (AQ.)", re.compile(r"\bAQ\.[0-9A-Za-z_\-]{20,}")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "Secret assignment",
        re.compile(
            r"""(?ix)
            \b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*
            ["']?([A-Za-z0-9/+_\-\.]{12,})["']?
            """
        ),
    ),
]

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".docx",
    ".xlsx",
    ".pptx",
    ".lock",
}
SKIP_NAMES = {".env.example", "secret_scan.py", "uv.lock", "package-lock.json"}


def git_files(staged: bool) -> list[Path]:
    if staged:
        cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    else:
        cmd = ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout  # noqa: S603
    return [Path(p) for p in out.splitlines() if p.strip()]


def is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(p in low for p in PLACEHOLDERS)


def scan_file(path: Path) -> list[str]:
    if path.suffix.lower() in SKIP_SUFFIXES or path.name in SKIP_NAMES or not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    findings: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "secret-scan: ignore" in line:
            continue
        for label, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(match.lastindex) if match.lastindex else match.group(0)
            if label == "Secret assignment" and is_placeholder(value):
                continue
            findings.append(f"{path}:{lineno}: possible {label}")
    return findings


def main() -> int:
    staged = "--staged" in sys.argv
    if not staged and "--all" not in sys.argv:
        print(__doc__)
        return 2
    findings: list[str] = []
    for path in git_files(staged):
        findings.extend(scan_file(path))
    if findings:
        print("Possible secrets found (commit blocked):")
        for f in findings:
            print("  " + f)
        print("Remove the secret, or add '# secret-scan: ignore' for a known fake value.")
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
