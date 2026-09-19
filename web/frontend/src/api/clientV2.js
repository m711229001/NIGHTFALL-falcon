/**
 * Falcon MAG v2 — Framework CLI API client
 * Wraps /api/v2/* endpoints (scans, profiles, auth).
 *
 * FIXED 2026-09-18: Use relative paths (nginx proxies /api/v2/*).
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
  start:    (data)                => clientV2.post("/api/v2/scans/start", data),
  status:   (scanId)              => clientV2.get(`/api/v2/scans/status/${scanId}`),
  log:      (scanId, tail = 200)  => clientV2.get(`/api/v2/scans/log/${scanId}?tail=${tail}`),
  cancel:   (scanId)              => clientV2.post(`/api/v2/scans/cancel/${scanId}`),
  list:     ()                    => clientV2.get("/api/v2/scans/list"),
  diagnose: ()                    => clientV2.get("/api/v2/scans/diagnose"),
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

export default clientV2;