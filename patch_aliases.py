# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\framework\core\http_client.py")
content = f.read_text(encoding="utf-8")

# Add aliases before in_scope
old_anchor = '''    # ----------------------------------------------------------
    # Scope check
    # ----------------------------------------------------------'''

new_aliases = '''    # ----------------------------------------------------------
    # Aliases (for backward compat with modules)
    # ----------------------------------------------------------
    def scan_request(self, url: str, method: str = "GET", **kw):
        """Alias: scan_request(url, method='GET') -> HTTPResponse"""
        return self.request(method, url, **kw)

    def scan_get(self, url: str, **kw):
        return self.get(url, **kw)

    def scan_post(self, url: str, **kw):
        return self.post(url, **kw)

    def scan_put(self, url: str, **kw):
        return self.put(url, **kw)

    def scan_delete(self, url: str, **kw):
        return self.delete(url, **kw)

    def scan_options(self, url: str, **kw):
        return self.options(url, **kw)

    def scan_head(self, url: str, **kw):
        return self.head(url, **kw)

    # ----------------------------------------------------------
    # Scope check
    # ----------------------------------------------------------'''

if old_anchor in content and 'def scan_request' not in content:
    content = content.replace(old_anchor, new_aliases, 1)
    print("[OK] aliases added (scan_request, scan_get, scan_post, ...)")
elif 'def scan_request' in content:
    print("[SKIP] aliases already present")
else:
    print("[FAIL] anchor not found")

f.write_text(content, encoding="utf-8")
print("=== Done ===")
