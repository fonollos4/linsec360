import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Temporary config used only for local visual checks with a demo API.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      '/api': 'http://127.0.0.1:8091',
    },
  },
})
