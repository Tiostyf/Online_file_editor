// vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'https://online-file-editor-backend.onrender.com', // your backend
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
