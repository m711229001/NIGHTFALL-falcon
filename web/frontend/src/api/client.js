/**
 * Falcon MAG — API client (V1 endpoints)
 *
 * FIXED 2026-09-18: Use relative paths so nginx proxies /api/ (no CORS).
 *   - In production (nginx): API_URL = "" → http://localhost/api/*
 *   - In dev (vite): set VITE_API_URL=http://localhost:8888 in .env.local
 */
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "";

const client = axios.create({
  baseURL: API_URL,
  headers: { "Content-Type": "application/json" },
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

client.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      // Don't hard-redirect here; let components handle it.
    }
    return Promise.reject(err);
  }
);

// ============================================================
// V1 API groups (existing — kept as-is)
// ============================================================
export const scanApi = {
  start:  (data)        => client.post("/api/scans/start", data),
  status: ()            => client.get("/api/scans/status"),
  log:    (lines = 200) => client.get(`/api/scans/log?lines=${lines}`),
  stop:   ()            => client.post("/api/scans/stop"),
  stats:  ()            => client.get("/api/scans/stats"),
  list:   (limit = 50)  => client.get(`/api/scans/list?limit=${limit}`),
  get:    (id)          => client.get(`/api/scans/${id}`),
};

export const findingsApi = {
  list:       (params)  => client.get("/api/findings", { params }),
  get:        (id)      => client.get(`/api/findings/${id}`),
  objectives: ()        => client.get("/api/findings/objectives/list"),
  campaign:   ()        => client.get("/api/findings/campaign/info"),
  callbacks:  ()        => client.get("/api/findings/callbacks/list"),
  evidence:   ()        => client.get("/api/findings/evidence/list"),
};

export const authApi = {
  login:    (data) => client.post("/api/auth/login", data),
  register: (data) => client.post("/api/auth/register", data),
  me:       ()     => client.get("/api/auth/me"),
};

export default client;