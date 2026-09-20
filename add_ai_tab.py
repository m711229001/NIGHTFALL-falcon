# -*- coding: utf-8 -*-
from pathlib import Path

f = Path(r"C:\BugBounty\NIGHTFALL\web\frontend\src\v2\components\VulnDetailDrawer.jsx")
content = f.read_text(encoding="utf-8")

old = '''  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)'''

new = '''  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiTab, setAiTab] = useState("explanation")'''

if old in content and 'const [aiTab' not in content:
    content = content.replace(old, new, 1)
    print("[OK] aiTab state added")
elif 'const [aiTab' in content:
    print("[SKIP] aiTab already present")
else:
    print("[FAIL] anchor not found")

f.write_text(content, encoding="utf-8")
print("=== Done ===")
