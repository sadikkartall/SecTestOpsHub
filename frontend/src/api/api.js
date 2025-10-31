import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => config,
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  (error) => Promise.reject(error)
);

// Targets
export const getTargets = () => api.get('/api/targets');
export const getTarget = (id) => api.get(`/api/targets/${id}`);
export const createTarget = (data) => api.post('/api/targets', data);
export const deleteTarget = (id) => api.delete(`/api/targets/${id}`);

// Scans
export const getScans = (params) => api.get('/api/scans', { params });
export const getScan = (id) => api.get(`/api/scans/${id}`);
export const createScan = (data) => api.post('/api/scans', data);

// Findings
export const getFindings = (params) => api.get('/api/findings', { params });
export const getFinding = (id) => api.get(`/api/findings/${id}`);
export const getScanFindings = (scanId) => api.get(`/api/scans/${scanId}/findings`);

// Statistics
export const getStatistics = () => api.get('/api/statistics');

// Reports
export const downloadReport = (scanId, format = 'json') =>
  api.get(`/api/reports/${scanId}`, { params: { format }, responseType: format === 'pdf' ? 'blob' : 'text' });

// Playbooks
export const getPlaybooks = () => api.get('/api/playbooks');
export const createPlaybook = (data) => api.post('/api/playbooks', data);
export const deletePlaybook = (id) => api.delete(`/api/playbooks/${id}`);

export default api;

