// config/api.js
// Complete API client for Online File Editor

const API_BASE = import.meta.env.VITE_API_URL || 'https://online-file-editor-backend.onrender.com';
const TOKEN_KEY = 'auth_token';

// ========== TOKEN MANAGEMENT ==========
const getToken = () => {
  try {
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token || token === 'null' || token === 'undefined' || token.trim() === '') {
      if (token) localStorage.removeItem(TOKEN_KEY);
      return null;
    }
    
    // Validate JWT format
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.warn('Invalid token format detected');
      localStorage.removeItem(TOKEN_KEY);
      return null;
    }
    
    return token;
  } catch (error) {
    console.error('Token retrieval error:', error);
    localStorage.removeItem(TOKEN_KEY);
    return null;
  }
};

const setToken = (token) => {
  try {
    if (!token || token === 'null' || token === 'undefined') {
      throw new Error('Invalid token provided');
    }
    
    // Validate JWT format
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    
    localStorage.setItem(TOKEN_KEY, token);
  } catch (error) {
    console.error('Token storage error:', error);
    localStorage.removeItem(TOKEN_KEY);
  }
};

const clearToken = () => {
  localStorage.removeItem(TOKEN_KEY);
};

// ========== AUTH HEADERS ==========
const getAuthHeaders = () => {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
};

// ========== UTILITIES ==========
const safeJsonParse = (text) => {
  try {
    if (!text || text.trim() === '') return {};
    return JSON.parse(text);
  } catch (err) {
    console.warn('JSON parse error:', err.message, 'Text:', text.substring(0, 100));
    return {};
  }
};

const handleResponse = async (response) => {
  const text = await response.text();
  const data = safeJsonParse(text);
  
  if (!response.ok) {
    const errorMessage = data.message || `HTTP ${response.status}: ${response.statusText}`;
    throw new Error(errorMessage);
  }
  
  return data;
};

// ========== AUTHENTICATION ==========
export const login = async (email, password) => {
  try {
    if (!email || !password) {
      throw new Error('Email and password are required');
    }
    
    const response = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim(), password })
    });
    
    const data = await handleResponse(response);
    
    if (data.success && data.token) {
      setToken(data.token);
      return { success: true, user: data.user };
    }
    
    throw new Error(data.message || 'Login failed');
  } catch (error) {
    clearToken();
    console.error('Login error:', error.message);
    throw error;
  }
};

export const register = async (username, email, password, fullName = '', company = '') => {
  try {
    if (!username || !email || !password) {
      throw new Error('Username, email, and password are required');
    }
    
    if (username.length < 3) {
      throw new Error('Username must be at least 3 characters');
    }
    
    if (password.length < 6) {
      throw new Error('Password must be at least 6 characters');
    }
    
    const response = await fetch(`${API_BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        username: username.trim(),
        email: email.trim().toLowerCase(),
        password,
        fullName: fullName.trim(),
        company: company.trim()
      })
    });
    
    const data = await handleResponse(response);
    
    if (data.success && data.token) {
      setToken(data.token);
      return { success: true, user: data.user };
    }
    
    throw new Error(data.message || 'Registration failed');
  } catch (error) {
    console.error('Registration error:', error.message);
    throw error;
  }
};

export const logout = () => {
  clearToken();
  return Promise.resolve();
};

export const isLoggedIn = () => {
  const token = getToken();
  if (!token) return false;
  
  // Check token expiration
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      clearToken();
      return false;
    }
    return true;
  } catch (error) {
    return false;
  }
};

// ========== PROFILE ==========
export const fetchProfile = async () => {
  try {
    const response = await fetch(`${API_BASE}/api/profile`, {
      headers: getAuthHeaders()
    });
    
    const data = await handleResponse(response);
    
    if (data.success && data.user) {
      return data.user;
    }
    
    throw new Error(data.message || 'Failed to fetch profile');
  } catch (error) {
    console.error('Profile fetch error:', error.message);
    if (error.message.includes('401')) clearToken();
    throw error;
  }
};

export const updateProfile = async (updates) => {
  try {
    const response = await fetch(`${API_BASE}/api/profile`, {
      method: 'PUT',
      headers: {
        ...getAuthHeaders(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(updates)
    });
    
    const data = await handleResponse(response);
    
    if (data.success && data.user) {
      return data.user;
    }
    
    throw new Error(data.message || 'Profile update failed');
  } catch (error) {
    console.error('Profile update error:', error.message);
    throw error;
  }
};

// ========== FILE PROCESSING ==========
export const processFiles = async (files, tool, options = {}, onProgress = () => {}) => {
  // Input validation
  if (!files || !files.length) {
    throw new Error('No files selected');
  }
  
  const validTools = ['compress', 'merge', 'convert', 'enhance', 'preview'];
  if (!validTools.includes(tool)) {
    throw new Error(`Invalid tool: ${tool}. Valid tools: ${validTools.join(', ')}`);
  }
  
  // Tool-specific validation
  if (tool === 'merge' && files.length < 2) {
    throw new Error('Merge requires at least 2 files');
  }
  
  if (tool === 'convert' && !options.format) {
    throw new Error('Format is required for conversion');
  }
  
  if (tool === 'convert' && options.format) {
    const validFormats = ['jpg', 'jpeg', 'png', 'webp', 'mp3', 'wav'];
    if (!validFormats.includes(options.format.toLowerCase())) {
      throw new Error(`Unsupported format: ${options.format}. Valid: ${validFormats.join(', ')}`);
    }
  }
  
  if (tool === 'enhance' && files[0] && !files[0].type.startsWith('image/')) {
    throw new Error('Only images can be enhanced');
  }
  
  const formData = new FormData();
  
  // Append files with correct field name (matches server expectation)
  files.forEach(file => {
    formData.append('files', file);
  });
  
  formData.append('tool', tool);
  
  // Tool-specific options
  if (tool === 'compress' && options.compressLevel) {
    const level = Math.max(1, Math.min(9, Math.round((options.compressLevel / 100) * 9)));
    formData.append('compressLevel', level.toString());
  }
  
  if (tool === 'merge' && options.order && Array.isArray(options.order)) {
    formData.append('order', JSON.stringify(options.order));
  }
  
  if (tool === 'convert' && options.format) {
    formData.append('format', options.format.toLowerCase());
  }
  
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API_BASE}/api/process`);
    
    const token = getToken();
    if (token) {
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    }
    
    // Upload progress tracking
    if (onProgress && typeof onProgress === 'function') {
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable) {
          const percent = Math.round((event.loaded / event.total) * 100);
          onProgress(percent);
        }
      });
    }
    
    xhr.onload = () => {
      const data = safeJsonParse(xhr.responseText);
      
      if (xhr.status === 200 && data.success) {
        if (tool === 'preview') {
          resolve({
            success: true,
            files: data.files,
            message: data.message,
            tool: 'preview'
          });
        } else {
          resolve({
            success: true,
            url: data.url.startsWith('http') ? data.url : `${API_BASE}${data.url}`,
            fileName: data.fileName,
            size: data.size,
            originalSize: data.originalSize,
            savings: data.savings,
            tool: data.tool || tool,
            compressionRatio: data.compressionRatio
          });
        }
      } else {
        reject(new Error(data.message || `Server error: ${xhr.status}`));
      }
    };
    
    xhr.onerror = () => reject(new Error('Network error - please check your connection'));
    xhr.ontimeout = () => reject(new Error('Request timeout - file may be too large'));
    
    xhr.timeout = 300000; // 5 minutes timeout
    xhr.send(formData);
  });
};

// ========== HISTORY ==========
export const getHistory = async (page = 1, limit = 10) => {
  try {
    const response = await fetch(
      `${API_BASE}/api/history?page=${page}&limit=${limit}`,
      { headers: getAuthHeaders() }
    );
    
    const data = await handleResponse(response);
    
    if (data.success) {
      return {
        files: data.files,
        total: data.total,
        page: data.page,
        pages: data.pages,
        limit: limit
      };
    }
    
    throw new Error(data.message || 'Failed to fetch history');
  } catch (error) {
    console.error('History fetch error:', error.message);
    throw error;
  }
};

// ========== FILE DOWNLOAD ==========
export const downloadFile = (filename) => {
  try {
    const token = getToken();
    const url = `${API_BASE}/api/download/${filename}`;
    
    if (token) {
      // Open in new tab with token in URL (for direct download)
      window.open(`${url}?token=${encodeURIComponent(token)}`, '_blank');
    } else {
      window.open(url, '_blank');
    }
  } catch (error) {
    console.error('Download error:', error.message);
    throw new Error('Failed to initiate download');
  }
};

// ========== FILE PREVIEW ==========
export const getFileUrl = (filename, type = 'processed') => {
  const token = getToken();
  const baseUrl = type === 'upload' ? '/api/uploads' : '/api/processed';
  const url = `${API_BASE}${baseUrl}/${filename}`;
  
  if (token) {
    return `${url}?token=${encodeURIComponent(token)}`;
  }
  return url;
};

// ========== HEALTH CHECK ==========
export const checkHealth = async () => {
  try {
    const response = await fetch(`${API_BASE}/api/health`);
    const data = await handleResponse(response);
    return { 
      ok: true, 
      data,
      serverTime: data.timestamp,
      dbStatus: data.db
    };
  } catch (error) {
    console.error('Health check failed:', error.message);
    return { 
      ok: false, 
      error: error.message || 'Backend server is offline'
    };
  }
};

// ========== ADMIN FUNCTIONS ==========
export const getAdminUsers = async () => {
  try {
    const response = await fetch(`${API_BASE}/api/admin/users`, {
      headers: getAuthHeaders()
    });
    
    const data = await handleResponse(response);
    
    if (data.success) {
      return data.data;
    }
    
    throw new Error(data.message || 'Failed to fetch users');
  } catch (error) {
    console.error('Admin users fetch error:', error.message);
    throw error;
  }
};

export const getAdminFileProcesses = async () => {
  try {
    const response = await fetch(`${API_BASE}/api/admin/file-processes`, {
      headers: getAuthHeaders()
    });
    
    const data = await handleResponse(response);
    
    if (data.success) {
      return data.data;
    }
    
    throw new Error(data.message || 'Failed to fetch file processes');
  } catch (error) {
    console.error('Admin processes fetch error:', error.message);
    throw error;
  }
};

// ========== REACT HOOKS ==========
import { useState, useEffect } from 'react';

// Auth Hook
export const useAuth = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    if (!isLoggedIn()) {
      setLoading(false);
      return;
    }

    try {
      const profile = await fetchProfile();
      setUser(profile);
    } catch (err) {
      console.error('Auth check failed:', err);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (email, password) => {
    setError(null);
    try {
      const result = await login(email, password);
      setUser(result.user);
      return { success: true, user: result.user };
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    }
  };

  const handleRegister = async (username, email, password, fullName, company) => {
    setError(null);
    try {
      const result = await register(username, email, password, fullName, company);
      setUser(result.user);
      return { success: true, user: result.user };
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    }
  };

  const handleLogout = () => {
    logout();
    setUser(null);
  };

  return {
    user,
    loading,
    error,
    login: handleLogin,
    register: handleRegister,
    logout: handleLogout,
    isAuthenticated: !!user
  };
};

// Files Hook
export const useFiles = () => {
  const [processing, setProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const processFilesHandler = async (files, tool, options = {}) => {
    setProcessing(true);
    setProgress(0);
    setError(null);
    
    try {
      const result = await processFiles(
        files,
        tool,
        options,
        (percent) => setProgress(percent)
      );
      
      setResult(result);
      return { success: true, data: result };
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    } finally {
      setProcessing(false);
    }
  };

  const reset = () => {
    setResult(null);
    setError(null);
    setProgress(0);
  };

  return {
    processing,
    progress,
    result,
    error,
    processFiles: processFilesHandler,
    reset
  };
};

// Profile Hook
export const useProfile = () => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchProfileData = async () => {
    if (!isLoggedIn()) {
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const data = await fetchProfile();
      setProfile(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const updateProfileData = async (updates) => {
    setError(null);
    try {
      const updated = await updateProfile(updates);
      setProfile(updated);
      return { success: true, profile: updated };
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    }
  };

  useEffect(() => {
    fetchProfileData();
  }, []);

  return {
    profile,
    loading,
    error,
    updateProfile: updateProfileData,
    refresh: fetchProfileData
  };
};

// History Hook
export const useHistory = () => {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalFiles, setTotalFiles] = useState(0);

  const fetchHistory = async (pageNum = page) => {
    setLoading(true);
    setError(null);
    try {
      const data = await getHistory(pageNum);
      setFiles(data.files);
      setTotalPages(data.pages);
      setTotalFiles(data.total);
      setPage(data.page);
      return data;
    } catch (err) {
      setError(err.message);
      return null;
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  return {
    files,
    loading,
    error,
    page,
    totalPages,
    totalFiles,
    fetchHistory,
    setPage: (newPage) => {
      setPage(newPage);
      fetchHistory(newPage);
    }
  };
};

// ========== DEFAULT EXPORT ==========
export default {
  // Core functions
  login,
  register,
  logout,
  isLoggedIn,
  fetchProfile,
  updateProfile,
  processFiles,
  getHistory,
  downloadFile,
  getFileUrl,
  checkHealth,
  getAdminUsers,
  getAdminFileProcesses,
  TOKEN_KEY,
  
  // Hooks
  useAuth,
  useFiles,
  useProfile,
  useHistory
};
