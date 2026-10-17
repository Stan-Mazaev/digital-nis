import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        proxy: {
            // Все запросы на /api и /healthz проксируются на узел (порт 8080).
            // Это избавляет от CORS и позволяет дашборду работать с API узла
            // без дополнительной настройки.
            '/api': {
                target: 'http://localhost:8080',
                changeOrigin: true,
            },
            '/healthz': {
                target: 'http://localhost:8080',
                changeOrigin: true,
            },
        },
    },
});
