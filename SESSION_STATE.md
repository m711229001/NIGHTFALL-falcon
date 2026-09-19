# Falcon MAG v2 — حالة الجلسة

**التاريخ:** 2026-09-19  
**آخر commit:** (سيُحدَّث بعد push)  
**Git tag:** `v2.0-snapshot`  

---

## ✅ ما تم إنجازه

### 1. تنظيف المشروع
- تقليص الملفات من **1091 → 94**
- حذف 19 ملف فوضى (shell errors)
- حذف 3 auth modules قديمة
- تحديث `.gitignore` + إضافة `.dockerignore`

### 2. AI Provider Config System (Backend)
- **`framework/core/ai_config_store.py`** — تشفير Fernet + hot reload
  - 9 مزودين: DeepSeek, OpenAI, Anthropic, Gemini, Groq, Mistral, OpenRouter, Together, Ollama
  - تخزين مشفّر في `framework/config/ai_config.json`
  - Master key في `framework/config/.ai_master_key` (مُستثنى من Git)
- **`web/backend/api/ai_config.py`** — 8 endpoints REST
  - `GET /api/ai/providers` — قائمة المزودين
  - `GET /api/ai/config` — الإعدادات الحالية
  - `POST /api/ai/config` — حفظ مزود
  - `POST /api/ai/activate` — تفعيل
  - `DELETE /api/ai/config/{provider}` — حذف
  - `POST /api/ai/test` — اختبار الاتصال
  - `GET /api/ai/models/{provider}` — الموديلات
  - `POST /api/ai/clear` — مسح
- **`web/backend/main.py`** — تسجيل `ai_config.router`

### 3. Docker Fixes
- **Dockerfile**: استبدال `apt install exploitdb` بـ `git clone` (Debian Trixie compat)
- **importlib fix**: تحميل `ai_config_store` بـ absolute path بدلاً من `sys.path` (حل تعارض `core/`)

---

## 🔴 مشاكل معروفة (للمستقبل)

### 1. `core/` مزدوج
- `web/backend/core/` (backend)
- `framework/core/` (framework)
- **الحل الدائم:** إعادة تسمية `framework/core/` → `framework/falcon_core/`
- **الحل المؤقت:** `importlib.util` (مستخدم حالياً في `ai_config.py`)

### 2. `config.py` BASE_DIR خاطئ
- `Path(__file__).resolve().parent.parent.parent.parent`
- داخل Docker → `BASE_DIR = /` (خطأ)
- **الحل الحالي:** `docker-compose.yml` overrides
- **الحل الدائم:** استخدام `Path("/app")` كـ fallback

### 3. `web/backend/models/nightfall_core.py` ضخم
- يحتاج refactor
- **مؤجل** لجلسة منفصلة

---

## 🎯 المهمة التالية (جلسة جديدة)

### 1. Frontend AI Settings Page
- **ملف:** `web/frontend/src/v2/pages/AISettingsV2.jsx` 🆕
- **المحتوى:**
  - Dropdown لاختيار المزود (9 مزودين)
  - Input لـ API key (يُخفي + زر إظهار)
  - Dropdown للموديل (يتحمّل من `/api/ai/models/{provider}`)
  - Input لـ Base URL (auto-fill)
  - زر Test Connection
  - زر Save
  - قائمة المزودين المُعدّين + Activate/Delete

### 2. Route
- **`web/frontend/src/v2/App.jsx`**: إضافة `/v2/ai-settings`

### 3. Sidebar
- **`web/frontend/src/v2/components/TacticalSidebar.jsx`**: إضافة رابط في قسم "الإعدادات"

### 4. i18n
- **`web/frontend/src/v2/i18n.js`** + `locales/ar.json` + `locales/en.json`

### 5. اختبار E2E
- افتح `/v2/ai-settings`
- أدخل DeepSeek API key
- اضغط Test → Save → Activate
- تحقق: `git log` يشير إلى مزود نشط

---

## 🔐 تعليمات أمنية

**Revoke مفتاح DeepSeek القديم:**
- المفتاح: `REDACTED`
- الرابط: https://platform.deepseek.com/api_keys
- **الحالة:** ⚠️ لم يُنفّذ بعد — افعله أول شيء

---

## 🛠️ أوامر مرجعية

### إعادة تشغيل Backend
```cmd
docker compose build backend && docker compose up -d backend