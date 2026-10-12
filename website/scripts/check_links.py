"""Check rendered local links, fragments and assets without network access."""
from html.parser import HTMLParser
from pathlib import Path
import os
from urllib.parse import unquote, urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[1] / 'dist'
BASE = '/' + os.environ.get('SITE_BASE_PATH', '').strip('/')
BASE = BASE.rstrip('/') + '/'


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids, self.links = set(), []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        for name in ('href', 'src'):
            if name in attrs:
                self.links.append(attrs[name])
        if 'srcset' in attrs:
            self.links.extend(candidate.strip().split()[0] for candidate in attrs['srcset'].split(',') if candidate.strip())


pages = {p: Page(p.read_text()) for p in ROOT.rglob('*.html')}
errors = []
for file, page in pages.items():
    url = BASE + file.relative_to(ROOT).as_posix().removesuffix('index.html')
    for link in page.links:
        target = urlsplit(urljoin(url, link))
        if target.scheme or target.netloc:
            continue
        local_path = unquote(target.path)
        if not local_path.startswith(BASE):
            errors.append(f'{url}: link escapes site base {link}')
            continue
        dest = ROOT / local_path[len(BASE):]
        if dest.is_dir():
            dest /= 'index.html'
        if not dest.exists():
            errors.append(f'{url}: missing {link}')
        elif target.fragment and dest in pages and unquote(target.fragment) not in pages[dest].ids:
            errors.append(f'{url}: missing anchor {link}')
for error in errors:
    print(error)
print(f'Checked {len(pages)} HTML pages; {len(errors)} broken links/anchors/assets.')
raise SystemExit(bool(errors))
