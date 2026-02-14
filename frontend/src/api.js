const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5001';

const TOKEN_KEY = 'auth_token';


// ================= TOKEN FUNCTIONS =================

const getToken = () => {

  const token = localStorage.getItem(TOKEN_KEY);

  if (!token || token === 'null' || token === 'undefined' || token.trim() === '') {

    console.warn('Invalid token found in storage');

    localStorage.removeItem(TOKEN_KEY);

    return null;

  }

  return token;

};


const setToken = (token) => {

  if (!token || token === 'null' || token === 'undefined') {

    console.error('Attempt to set invalid token');

    localStorage.removeItem(TOKEN_KEY);

    return;

  }

  const parts = token.split('.');

  if (parts.length !== 3) {

    console.error('Invalid JWT format');

    return;

  }

  localStorage.setItem(TOKEN_KEY, token);

};


const clearToken = () => {

  localStorage.removeItem(TOKEN_KEY);

};


const authHeaders = () => {

  const token = getToken();

  if (!token) return {};

  return {
    Authorization: `Bearer ${token}`
  };

};


// ================= HELPER =================

const safeJsonParse = (text) => {

  try {
    return text?.trim() ? JSON.parse(text) : {};
  }
  catch {
    return {};
  }

};


const handleResponse = async (res) => {

  const text = await res.text();

  const data = safeJsonParse(text);

  if (!res.ok) {

    throw new Error(data.message || `HTTP ${res.status}`);

  }

  return data;

};


// ================= AUTH =================


// LOGIN

export const login = (email, password) =>

  fetch(`${API_BASE}/api/login`, {

    method: 'POST',

    headers: {
      'Content-Type': 'application/json'
    },

    body: JSON.stringify({
      email,
      password
    })

  })

  .then(handleResponse)

  .then(data => {

    if (data.success && data.token) {

      setToken(data.token);

      return data.user;

    }

    throw new Error(data.message || 'Login failed');

  })

  .catch(err => {

    clearToken();

    throw err;

  });




// SIGNUP (UPDATED)

export const register = (

  username,
  email,
  password,
  fullName = '',
  company = ''

) =>

  fetch(`${API_BASE}/api/signup`, {

    method: 'POST',

    headers: {
      'Content-Type': 'application/json'
    },

    body: JSON.stringify({

      username,
      email,
      password,
      fullName,
      company

    })

  })

  .then(handleResponse)

  .then(data => {

    if (data.success && data.token) {

      setToken(data.token);

      return data.user;

    }

    throw new Error(data.message || 'Signup failed');

  });




// LOGOUT

export const logout = () => {

  clearToken();

};




// CHECK LOGIN

export const isLoggedIn = () => {

  return !!getToken();

};




// ================= PROFILE =================


export const fetchProfile = () =>

  fetch(`${API_BASE}/api/profile`, {

    headers: authHeaders()

  })

  .then(handleResponse)

  .then(data => data.user);




export const updateProfile = (updates) =>

  fetch(`${API_BASE}/api/profile`, {

    method: 'PUT',

    headers: {

      ...authHeaders(),

      'Content-Type': 'application/json'

    },

    body: JSON.stringify(updates)

  })

  .then(handleResponse)

  .then(data => data.user);




// ================= FILE PROCESS =================


export const processFiles = (

  files,
  tool,
  options = {},
  onProgress = () => {}

) => {

  return new Promise((resolve, reject) => {

    const form = new FormData();

    files.forEach(f => form.append('files', f));

    form.append('tool', tool);

    if (options.compressLevel)
      form.append('compressLevel', options.compressLevel);

    if (options.format)
      form.append('format', options.format);

    if (options.order)
      form.append('order', JSON.stringify(options.order));


    const xhr = new XMLHttpRequest();

    xhr.open('POST', `${API_BASE}/api/process`);

    const token = getToken();

    if (token)
      xhr.setRequestHeader(
        'Authorization',
        `Bearer ${token}`
      );


    xhr.upload.onprogress = (e) => {

      if (e.lengthComputable) {

        const percent =
          Math.round((e.loaded / e.total) * 100);

        onProgress(percent);

      }

    };


    xhr.onload = () => {

      const data =
        safeJsonParse(xhr.responseText);

      if (xhr.status === 200 && data.success) {

        resolve(data);

      }
      else {

        reject(
          new Error(
            data.message ||
            'Process failed'
          )
        );

      }

    };


    xhr.onerror = () =>
      reject(new Error('Network error'));


    xhr.send(form);

  });

};




// ================= HISTORY =================


export const getHistory = (page = 1) =>

  fetch(`${API_BASE}/api/history?page=${page}`, {

    headers: authHeaders()

  })

  .then(handleResponse);




// ================= DOWNLOAD =================


export const downloadFile = (filename) => {

  const token = getToken();

  let url =
    `${API_BASE}/api/download/${filename}`;

  if (token)
    url += `?token=${token}`;

  window.open(url, '_blank');

};




// ================= HEALTH =================


export const checkHealth = () =>

  fetch(`${API_BASE}/api/health`)
  .then(handleResponse);




// ================= EXPORT =================


export default {

  login,

  register,

  logout,

  isLoggedIn,

  fetchProfile,

  updateProfile,

  processFiles,

  getHistory,

  downloadFile,

  checkHealth

};
