/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        governance: {
          allowed: '#10b981', // green-500
          allowedDark: '#059669',
          blocked: '#ef4444', // red-500
          blockedDark: '#dc2626',
          pending: '#f59e0b', // amber-500
          pendingDark: '#d97706',
          frozen: '#3b82f6',  // blue-500
          frozenDark: '#2563eb',
          accent: '#06b6d4',  // cyan-500
          accentViolet: '#8b5cf6',
        },
        surface: {
          bgDark: '#090d16',
          cardDark: '#0f172a',
          cardHoverDark: '#1e293b',
          borderDark: '#334155',
          bgLight: '#f8fafc',
          cardLight: '#ffffff',
          cardHoverLight: '#f1f5f9',
          borderLight: '#e2e8f0',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
      },
      animation: {
        'pulse-fast': 'pulse 1.2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'shimmer': 'shimmer 2.5s infinite',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        }
      }
    },
  },
  plugins: [],
}
