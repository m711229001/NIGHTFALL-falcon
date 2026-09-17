import axios from "axios";

const API_URL = "http://localhost:8888";

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
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

export const scanApi = {
  start: (data) => client.post("/api/scans/start", data),
  status: () => client.get("/api/scans/status"),
  log: (lines = 200) => client.get(`/api/scans/log?lines=${lines}`),
  stop: () => client.post("/api/scans/stop"),
  stats: () => client.get("/api/scans/stats"),
};

export const findingsApi = {
  list: (params) => client.get("/api/findings", { params }),
  get: (id) => client.get(`/api/findings/${id}`),
  objectives: () => client.get("/api/findings/objectives/list"),
  campaign: () => client.get("/api/findings/campaign/info"),
  callbacks: () => client.get("/api/findings/callbacks/list"),
  evidence: () => client.get("/api/findings/evidence/list"),
};

export default client;
