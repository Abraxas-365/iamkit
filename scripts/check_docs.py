#!/usr/bin/env python3
"""Check repository documentation without network access or third-party packages."""
from collections import Counter
from pathlib import Path
import os
import re
import sys
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def headings(text):
    result, counts = set(), Counter()
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        if fenced:
            continue
        match = re.match(r"^#{1,6}\s+(.+?)(?:\s+#+)?$", line)
        if not match:
            continue
        title = re.sub(r"<[^>]+>", "", match[1]).lower()
        slug = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        suffix = f"-{counts[slug]}" if counts[slug] else ""
        counts[slug] += 1
        result.add(slug + suffix)
    result.update(re.findall(r'(?:id|name)="([^"]+)"', text))
    return result


# Dependency/build directories and agent instructions are not reader docs.
EXCLUDED_DIRS = {".git", "node_modules", "dist", ".astro", ".venv", "venv", "__pycache__"}
AGENT_FILES = {"AGENTS.md", "CLAUDE.md", "copilot-instructions.md"}


def documentation_files(root):
    files = []
    for directory, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith("."))
        for name in sorted(names):
            if name.endswith(".md") and name not in AGENT_FILES:
                files.append(Path(directory) / name)
    return sorted(files)


def main():
    files = documentation_files(ROOT)
    errors = []
    for path in files:
        text = path.read_text()
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", text):
            errors.append(f"{path.relative_to(ROOT)}: private key material")
        for number, line in enumerate(text.splitlines(), 1):
            if line.rstrip() != line:
                errors.append(f"{path.relative_to(ROOT)}:{number}: trailing whitespace")
        # Inline links/images plus reference-link definitions. Fenced examples
        # are excluded because shell syntax may contain ](...).
        prose = re.sub(r"^```[^\n]*\n.*?^```\s*$", "", text, flags=re.M | re.S)
        links = re.findall(r"!?\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)", prose)
        links += re.findall(r"^\[[^\]]+\]:\s*(\S+)", prose, flags=re.M)
        for raw in links:
            url = urlsplit(raw.strip("<>"))
            if url.scheme or url.netloc:
                continue
            target = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not target.exists():
                errors.append(f"{path.relative_to(ROOT)}: missing link {raw}")
            elif url.fragment and target.suffix == ".md":
                if unquote(url.fragment) not in headings(target.read_text()):
                    errors.append(f"{path.relative_to(ROOT)}: missing anchor {raw}")
    for path in (ROOT / "docs").rglob("*"):
        if not path.is_file():
            continue
        if path.suffix == ".svg":
            try:
                ET.parse(path)
            except ET.ParseError as exc:
                errors.append(f"{path.relative_to(ROOT)}: invalid SVG: {exc}")
        if path.suffix in (".sh", ".go", ".js", ".json", ".svg"):
            if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", path.read_text()):
                errors.append(f"{path.relative_to(ROOT)}: private key material")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Documentation checks passed ({len(files)} Markdown files, local links/anchors, SVGs, whitespace and private-key markers).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
