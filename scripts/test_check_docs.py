"""Regression tests for reader-document discovery and anchor preservation."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_docs
from check_docs import documentation_files, headings


class DocumentationChecksTest(unittest.TestCase):
    def test_discovers_readmes_but_not_dependencies_builds_or_agent_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            included = ["README.md", "docs/start/overview.md", "clients/python/README.md",
                        "examples/nextjs-login/README.md", "scripts/README.md", "website/README.md"]
            excluded = ["AGENTS.md", "CLAUDE.md", "frontend/node_modules/pkg/README.md",
                        "website/dist/README.md", "clients/python/.venv/pkg/README.md",
                        ".git/README.md", ".rness/notes.md"]
            for relative in included + excluded:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Example\n")
            self.assertEqual(documentation_files(root), sorted(root / p for p in included))

    def test_private_key_markers_are_checked_in_readmes_outside_docs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ["README.md", "clients/python/README.md", "sdk/README.md"]:
                with self.subTest(path=relative):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    # Assemble the marker so this test itself is not secret-like.
                    path.write_text("-----BEGIN " + "PRIVATE KEY-----\n")
                    output, errors = StringIO(), StringIO()
                    with patch.object(check_docs, "ROOT", root), redirect_stdout(output), redirect_stderr(errors):
                        self.assertEqual(check_docs.main(), 1)
                    self.assertIn(f"{relative}: private key material", errors.getvalue())
                    path.unlink()

    def test_explicit_legacy_anchor_and_duplicate_headings(self):
        anchors = headings('# Page\n\n<a id="legacy-step"></a>\n## Step\n## Step\n'
                           '```md\n## Not a heading\n```\n')
        self.assertEqual(anchors, {"page", "legacy-step", "step", "step-1"})


if __name__ == "__main__":
    unittest.main()
