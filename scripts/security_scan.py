"""Run every security scan in one go (Stage 8, AC-52).

    uv run python -m scripts.security_scan

1. Secret scan of the whole tree           (scripts/secret_scan.py --all)
2. Python dependency vulnerabilities       (pip-audit on the locked, non-dev packages)
3. Dashboard dependency vulnerabilities    (npm audit, production packages only)

Exit code 0 only if all three are clean. Needs network access: the two audits ask public
vulnerability databases. A scan that cannot run counts as a failure, never as clean.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "apps" / "dashboard"


def run(name: str, command: list[str], cwd: Path = ROOT) -> bool:
    print(f"\n== {name}\n$ {' '.join(command)}")
    try:
        done = subprocess.run(command, cwd=cwd, check=False)  # noqa: S603
    except OSError as exc:
        print(f"{name}: could not run ({exc})")
        return False
    print(f"{name}: {'clean' if done.returncode == 0 else 'FINDINGS or failure'}")
    return done.returncode == 0


def python_dependencies() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        reqs = Path(tmp) / "requirements.txt"
        export = ["uv", "export", "--frozen", "--no-dev", "--no-hashes", "--no-emit-project"]
        with reqs.open("w", encoding="utf-8") as out:
            try:
                done = subprocess.run(export, cwd=ROOT, stdout=out, check=False)  # noqa: S603
            except OSError as exc:
                print(f"python dependencies: could not run uv ({exc})")
                return False
        if done.returncode != 0:
            print("python dependencies: could not export the locked packages")
            return False
        # --no-deps: the lock file already lists every package, so nothing is resolved again.
        audit = [sys.executable, "-m", "pip_audit", "-r", str(reqs), "--no-deps", "--disable-pip"]
        return run("python dependencies", audit)


def main() -> int:
    npm = "npm.cmd" if sys.platform == "win32" else "npm"
    results = {
        "secrets": run("secrets", [sys.executable, "scripts/secret_scan.py", "--all"]),
        "python dependencies": python_dependencies(),
        "dashboard dependencies": run(
            "dashboard dependencies", [npm, "audit", "--omit=dev"], cwd=DASHBOARD
        ),
    }
    print("\n== summary")
    for name, ok in results.items():
        print(f"  {name:<24}{'clean' if ok else 'NOT CLEAN'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
