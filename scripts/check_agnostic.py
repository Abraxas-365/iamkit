#!/usr/bin/env python3
"""Fail when project-specific names leak into the generic product tree (D42).

Scans tracked and untracked, not ignored files (git ls-files) under the product directories for the
forbidden words, case-insensitively, and prints file:line for each hit.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRS = ["internal", "sdk", "clients", "migrations", "docs", "api",
        "frontend/src", "cmd", "examples"]
FORBIDDEN = re.compile(r"odicea|freerouter", re.IGNORECASE)
SKIP_PARTS = {"node_modules", ".next", "dist", "build"}


def tracked():
    # Tracked and untracked (not ignored) files: a new file fails before
    # it is committed.
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others",
                          "--exclude-standard", "--", *DIRS], cwd=ROOT,
                         check=True, capture_output=True).stdout
    for name in out.decode("utf-8", "surrogateescape").split("\0"):
        if name and not SKIP_PARTS.intersection(Path(name).parts):
            yield name


def main():
    hits = []
    for name in tracked():
        path = ROOT / name
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            if FORBIDDEN.search(line):
                hits.append(f"{name}:{number}: {line.strip()[:120]}")
    if hits:
        print("Forbidden project-specific names (odicea, freerouter) found:")
        print("\n".join(hits))
        return 1
    print("check_agnostic: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
