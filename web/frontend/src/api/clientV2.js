/**
 * Falcon MAG v2 — Framework CLI API client
 * Wraps /api/v2/* and /api/ai/* endpoints.
 *
 * FIXED 2026-09-18: Use relative paths (nginx proxies /api/v2/*).
 * ADDED 2026-09-19: aiConfigApi for AI provider settings.
 */
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "";

const clientV2 = axios.create({
  baseURL: API_URL,
  headers: { "Content-Type": "application/json" },
});

// Token interceptor (same pattern as client.js)
clientV2.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

clientV2.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
    }
    return Promise.reject(err);
  }
);

// ============================================================
// Framework Scan API (/api/v2/scans/*)
// ============================================================
export const frameworkScanApi = {
  start:        (data)                => clientV2.post("/api/v2/scans/start", data),
  status:       (scanId)              => clientV2.get(`/api/v2/scans/status/${scanId}`),
  log:          (scanId, tail = 200)  => clientV2.get(`/api/v2/scans/log/${scanId}?tail=${tail}`),
  cancel:       (scanId)              => clientV2.post(`/api/v2/scans/cancel/${scanId}`),
  pause:        (scanId)              => clientV2.post(`/api/v2/scans/pause/${scanId}`),
  resume:       (scanId)              => clientV2.post(`/api/v2/scans/resume/${scanId}`),
  report:       (scanId)              => clientV2.get(`/api/v2/scans/report/${scanId}`),
  links:        (scanId)              => clientV2.get(`/api/v2/scans/links/${scanId}`),
  linksLatest:  ()                    => clientV2.get("/api/v2/scans/links-latest"),
  list:         ()                    => clientV2.get("/api/v2/scans/list"),
  diagnose:     ()                    => clientV2.get("/api/v2/scans/diagnose"),
};

// ============================================================
// Profiles API (/api/v2/profiles/*)
// ============================================================
export const profilesV2Api = {
  list: ()     => clientV2.get("/api/v2/profiles/list"),
  get:  (name) => clientV2.get(`/api/v2/profiles/${name}`),
};

// ============================================================
// Auth API (/api/v2/auth/*)
// ============================================================
export const authV2Api = {
  types:       ()                     => clientV2.get("/api/v2/auth/types"),
  login:       (data)                 => clientV2.post("/api/v2/auth/login", data),
  loginStatus: (loginId)              => clientV2.get(`/api/v2/auth/login/${loginId}`),
  loginLog:    (loginId, tail = 200)  => clientV2.get(`/api/v2/auth/login/${loginId}/log?tail=${tail}`),
};

// ============================================================
// AI Config API (/api/ai/*)
// ADDED 2026-09-19: AI provider configuration
// ============================================================
export const aiConfigApi = {
  /** قائمة المزودين المعروفين + المُعدّين */
  providers:    ()                => clientV2.get("/api/ai/providers"),
  /** الإعدادات الحالية (بدون مفاتيح) */
  config:       ()                => clientV2.get("/api/ai/config"),
  /** الموديلات المعروفة لمزود */
  models:       (provider)        => clientV2.get(`/api/ai/models/${provider}`),
  /** حفظ مزود (يُشفّر المفتاح) */
  save:         (data)            => clientV2.post("/api/ai/config", data),
  /** تفعيل مزود */
  activate:     (provider)        => clientV2.post("/api/ai/activate", { provider }),
  /** حذف مزود */
  remove:       (provider)        => clientV2.delete(`/api/ai/config/${provider}`),
  /** اختبار الاتصال */
  test:         (data)            => clientV2.post("/api/ai/test", data || {}),
  /** مسح كل الإعدادات */
  clear:        ()                => clientV2.post("/api/ai/clear"),
};

export default clientV2;