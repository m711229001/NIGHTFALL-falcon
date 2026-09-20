# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\v2\index.css")
content = f.read_text(encoding="utf-8")

# ابحث عن @import "tailwindcss"
old = '@import "tailwindcss";'
new = '''@import "tailwindcss";
@import "./styles/design-tokens.css";
@import "./styles/animations.css";'''

if old not in content:
    print("[FAIL] tailwindcss import not found")
    raise SystemExit(1)

if 'design-tokens.css' in content:
    print("[SKIP] design-tokens already imported")
    raise SystemExit(0)

content = content.replace(old, new, 1)
f.write_text(content, encoding="utf-8")
print("[OK] CSS imports added to v2/index.css")
