"""Exercise rendered-link validation at both root and project-site mounts."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('check_links.py')


class RenderedLinksTest(unittest.TestCase):
    def run_checker(self, base, html):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / 'scripts'
            scripts.mkdir()
            shutil.copyfile(SCRIPT, scripts / SCRIPT.name)
            dist = root / 'dist'
            dist.mkdir()
            (dist / 'index.html').write_text(html)
            (dist / 'image.webp').write_bytes(b'image fixture')
            docs = dist / 'docs'
            docs.mkdir()
            (docs / 'index.html').write_text('<h1 id="start">Start</h1>')
            return subprocess.run(
                ['python3', str(scripts / SCRIPT.name)],
                env={**os.environ, 'SITE_BASE_PATH': base},
                text=True, capture_output=True, check=False,
            )

    def test_root_and_project_links(self):
        for base in ['/', '/iamkit/']:
            with self.subTest(base=base):
                result = self.run_checker(base, f'<a href="{base}docs/#start">Docs</a>'
                                          f'<img src="{base}image.webp" srcset="{base}image.webp 2x">')
                self.assertEqual(result.returncode, 0, result.stdout)

    def test_project_links_cannot_escape_base(self):
        result = self.run_checker('/iamkit/', '<a href="/docs/#start">Docs</a>')
        self.assertEqual(result.returncode, 1)
        self.assertIn('link escapes site base', result.stdout)

    def test_missing_responsive_image_is_rejected(self):
        result = self.run_checker('/iamkit/', '<img src="/iamkit/image.webp" srcset="/iamkit/missing.webp 2x">')
        self.assertEqual(result.returncode, 1)
        self.assertIn('missing /iamkit/missing.webp', result.stdout)


if __name__ == '__main__':
    unittest.main()
