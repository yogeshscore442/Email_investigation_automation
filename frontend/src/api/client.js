import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 45000,
});

// Attach JWT token from localStorage if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('phishscope_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => Promise.reject(error));

// Response interceptor for session expiration
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && localStorage.getItem('phishscope_token')) {
      // Token expired or invalid
      console.warn('Session expired or unauthorized. Clearing stored token.');
      localStorage.removeItem('phishscope_token');
      localStorage.removeItem('phishscope_user');
      window.dispatchEvent(new Event('phishscope-auth-change'));
    }
    return Promise.reject(error);
  }
);

// ==================== Authentication & Session ====================

export const login = async (username, password) => {
  const res = await api.post('/auth/login', { username, password });
  if (res.data?.token) {
    localStorage.setItem('phishscope_token', res.data.token);
    if (res.data.user) {
      localStorage.setItem('phishscope_user', JSON.stringify(res.data.user));
    }
    window.dispatchEvent(new Event('phishscope-auth-change'));
  }
  return res.data;
};

export const logout = async () => {
  try {
    await api.post('/auth/logout');
  } catch (err) {
    // Ignore network errors on logout
  } finally {
    localStorage.removeItem('phishscope_token');
    localStorage.removeItem('phishscope_user');
    window.dispatchEvent(new Event('phishscope-auth-change'));
  }
};

export const getCurrentUser = () => {
  try {
    const raw = localStorage.getItem('phishscope_user');
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
};

export const getAuthToken = () => {
  return localStorage.getItem('phishscope_token');
};

export const fetchProfile = async () => {
  const res = await api.get('/auth/me');
  if (res.data?.user) {
    localStorage.setItem('phishscope_user', JSON.stringify(res.data.user));
  }
  return res.data;
};

// ==================== Core Platform Endpoints ====================

export const getDashboardStats = async () => {
  const res = await api.get('/dashboard/stats');
  return res.data;
};

export const getHealth = async () => {
  const res = await api.get('/health');
  return res.data;
};

export const getInvestigations = async (params = {}) => {
  const res = await api.get('/investigations', { params });
  return res.data;
};

export const getInvestigation = async (id) => {
  const res = await api.get(`/investigate/${id}`);
  return res.data;
};

export const uploadEmailFile = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const res = await api.post('/investigate/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
  return res.data;
};

export const investigateHeaders = async (raw_headers, raw_body = '') => {
  const res = await api.post('/investigate/headers', { raw_headers, raw_body });
  return res.data;
};

export const getIocs = async (id) => {
  const res = await api.get(`/investigate/${id}/iocs`);
  return res.data;
};

export const getSocReport = async (id) => {
  const res = await api.get(`/investigate/${id}/report`);
  return res.data;
};

export const deleteInvestigation = async (id) => {
  const res = await api.delete(`/investigate/${id}`);
  return res.data;
};

export const getIocsExportUrl = (id, format = 'csv') => {
  return `/api/investigate/${id}/iocs/export?format=${format}`;
};

export const getReportHtmlUrl = (id) => {
  return `/api/investigate/${id}/report/html`;
};

export const getReportPdfUrl = (id) => {
  return `/api/investigate/${id}/report/pdf`;
};

// ==================== Phase 3: Incidents & SIEM ====================

export const getIncidents = async (params = {}) => {
  const res = await api.get('/incidents', { params });
  return res.data;
};

export const getIncidentStats = async () => {
  const res = await api.get('/incidents/stats');
  return res.data;
};

export const getIncident = async (id) => {
  const res = await api.get(`/incidents/${id}`);
  return res.data;
};

export const triggerCorrelation = async () => {
  const res = await api.post('/incidents/correlate');
  return res.data;
};

export const approvePlaybookAction = async (incidentId, actionId, analystName = 'SOC Lead Analyst') => {
  const res = await api.post(`/incidents/${incidentId}/actions/${actionId}/approve`, { analyst_name: analystName });
  return res.data;
};

export const rejectPlaybookAction = async (incidentId, actionId, analystName = 'SOC Lead Analyst', reason = 'Analyst override') => {
  const res = await api.post(`/incidents/${incidentId}/actions/${actionId}/reject`, { analyst_name: analystName, reason });
  return res.data;
};

export const executePlaybookAction = async (incidentId, actionId) => {
  const res = await api.post(`/incidents/${incidentId}/actions/${actionId}/execute`);
  return res.data;
};

export const getSiemStatus = async () => {
  const res = await api.get('/siem/status');
  return res.data;
};

// ==================== Phase 5: Attack Sim & Detection ====================

export const getPhase5Status = async () => {
  const res = await api.get('/phase5/status');
  return res.data;
};

export const getPhase5Rules = async () => {
  const res = await api.get('/phase5/rules');
  return res.data;
};

export const runPhase5Simulation = async (testId) => {
  const res = await api.post(`/phase5/run/${testId}`);
  return res.data;
};

export const getPhase5Results = async () => {
  const res = await api.get('/phase5/results');
  return res.data;
};

export const getPhase5Timeline = async () => {
  const res = await api.get('/phase5/timeline');
  return res.data;
};

export default api;

