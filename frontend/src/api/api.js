import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('API Error:', error.response || error.message);
    return Promise.reject(error);
  }
);

// ==================== TARGETS ====================

export const getTargets = () => api.get('/api/targets');
export const getTarget = (id) => api.get(`/api/targets/${id}`);
export const createTarget = (data) => api.post('/api/targets', data);
export const deleteTarget = (id) => api.delete(`/api/targets/${id}`);

// ==================== SCANS ====================

export const getScans = (params) => api.get('/api/scans', { params });
export const getScan = (id) => api.get(`/api/scans/${id}`);
export const createScan = (data) => api.post('/api/scans', data);

// ==================== FINDINGS ====================

export const getFindings = (params) => api.get('/api/findings', { params });
export const getFinding = (id) => api.get(`/api/findings/${id}`);
export const getScanFindings = (scanId) => api.get(`/api/scans/${scanId}/findings`);

// ==================== STATISTICS ====================

export const getStatistics = () => api.get('/api/statistics');

export default api;

