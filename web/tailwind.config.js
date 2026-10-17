/** @type {import('tailwindcss').Config} */
export default {
    content: ['./index.html', './src/**/*.{ts,tsx}'],
    theme: {
        extend: {
            colors: {
                'nis-bg': '#0f172a',
                'nis-panel': '#1e293b',
                'nis-border': '#334155',
                'nis-accent': '#10b981',
                'nis-warn': '#f59e0b',
                'nis-error': '#ef4444',
            },
            fontFamily: {
                mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
            },
        },
    },
    plugins: [],
};
