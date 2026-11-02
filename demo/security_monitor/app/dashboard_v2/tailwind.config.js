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
        bg: '#0B0E14',
        sidebar: '#0E121A',
        card: '#11151D',
        border: {
          DEFAULT: '#1F2633',
          subtle: '#1F2633',
          strong: '#2A3344',
        },
        text: {
          DEFAULT: '#E6E9EF',
          primary: '#E6E9EF',
          secondary: '#A7B0C0',
          muted: '#8B95A7',
        },
        accent: {
          DEFAULT: '#3B82F6',
          blue: '#3B82F6',
        },
        meaning: {
          allowed: '#22C55E',
          waiting: '#F59E0B',
          stopped: '#EF4444',
        },
        role: {
          developer: '#60A5FA',
          team_lead: '#A78BFA',
          security_reviewer: '#FBBF24',
          admin: '#34D399',
          auditor: '#F472B6',
        },
        governance: {
          allowed: '#22C55E',
          stopped: '#EF4444',
          waiting: '#F59E0B',
          accent: '#3B82F6',
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
