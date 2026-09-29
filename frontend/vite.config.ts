import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('@sentry')) return 'vendor-sentry';
          if (id.includes('ckeditor5') || id.includes('@ckeditor')) return 'vendor-editor';
          if (id.includes('echarts')) return 'vendor-charts';
          if (id.includes('antd') || id.includes('@ant-design') || id.includes('rc-')) return 'vendor-antd';
          if (id.includes('react')) return 'vendor-react';
          return undefined;
        },
      },
    },
  },
  server: {
    host: '0.0.0.0',
    port: 8001,
    allowedHosts: ['ncesnext.com', 'dev.ncesnext.com', 'localhost', '127.0.0.1'],
    proxy: {
      '/api': {
        target: process.env.VITE_DEV_API_ORIGIN || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/uploads': {
        target: process.env.VITE_DEV_API_ORIGIN || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/feed.xml': {
        target: process.env.VITE_DEV_API_ORIGIN || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/robots.txt': {
        target: process.env.VITE_DEV_API_ORIGIN || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/ads.txt': {
        target: process.env.VITE_DEV_API_ORIGIN || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/sitemap.xml': {
        target: process.env.VITE_DEV_API_ORIGIN || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
