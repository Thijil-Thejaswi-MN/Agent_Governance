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
        // Design tokens (role-based)
        bg: 'rgb(var(--bg-rgb) / <alpha-value>)',
        surface: {
          DEFAULT: 'rgb(var(--surface-2-rgb) / <alpha-value>)',
          1: 'rgb(var(--surface-1-rgb) / <alpha-value>)',
          2: 'rgb(var(--surface-2-rgb) / <alpha-value>)',
          3: 'rgb(var(--surface-3-rgb) / <alpha-value>)',
          hover: 'rgb(var(--surface-hover-rgb) / <alpha-value>)',
          active: 'rgb(var(--surface-active-rgb) / <alpha-value>)',
          terminal: 'rgb(var(--surface-terminal-rgb) / <alpha-value>)',
          terminalAlt: 'var(--surface-terminal-alt)',
          navHover: 'var(--surface-nav-hover)',
          tableHover: 'var(--surface-table-hover)',
          darkAlt: 'var(--surface-dark-alt)',
          darkSlate: 'var(--surface-dark-slate)',
          slate800: 'var(--surface-slate-800)',
          slate900: 'var(--surface-slate-900)',
        },
        line: {
          DEFAULT: 'rgb(var(--line-rgb) / <alpha-value>)',
          strong: 'rgb(var(--line-strong-rgb) / <alpha-value>)',
          slate: 'var(--line-slate)',
        },
        fg: {
          DEFAULT: 'rgb(var(--text-rgb) / <alpha-value>)',
          primary: 'rgb(var(--text-rgb) / <alpha-value>)',
          2: 'rgb(var(--text-2-rgb) / <alpha-value>)',
          3: 'rgb(var(--text-3-rgb) / <alpha-value>)',
          dim: 'rgb(var(--text-dim-rgb) / <alpha-value>)',
          soft: 'rgb(var(--text-soft-rgb) / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'rgb(var(--accent-rgb) / <alpha-value>)',
          blue: 'rgb(var(--accent-rgb) / <alpha-value>)',
          strong: 'rgb(var(--accent-strong-rgb) / <alpha-value>)',
          deep: 'rgb(var(--accent-deep-rgb) / <alpha-value>)',
          tint: 'var(--accent-tint)',
        },
        ok: {
          DEFAULT: 'rgb(var(--ok-rgb) / <alpha-value>)',
          text: 'rgb(var(--ok-text-rgb) / <alpha-value>)',
          light: 'rgb(var(--ok-light-rgb) / <alpha-value>)',
          lighter: 'rgb(var(--ok-lighter-rgb) / <alpha-value>)',
          verdict: 'rgb(var(--ok-verdict-rgb) / <alpha-value>)',
          strong: 'rgb(var(--ok-strong-rgb) / <alpha-value>)',
          tint: 'var(--ok-tint)',
        },
        bad: {
          DEFAULT: 'rgb(var(--bad-rgb) / <alpha-value>)',
          text: 'rgb(var(--bad-text-rgb) / <alpha-value>)',
          light: 'rgb(var(--bad-light-rgb) / <alpha-value>)',
          lighter: 'rgb(var(--bad-lighter-rgb) / <alpha-value>)',
          verdict: 'rgb(var(--bad-verdict-rgb) / <alpha-value>)',
          strong: 'rgb(var(--bad-strong-rgb) / <alpha-value>)',
          tint: 'var(--bad-tint)',
        },
        wait: {
          DEFAULT: 'rgb(var(--wait-rgb) / <alpha-value>)',
          text: 'rgb(var(--wait-text-rgb) / <alpha-value>)',
          kpi: 'rgb(var(--wait-kpi-rgb) / <alpha-value>)',
          lighter: 'rgb(var(--wait-lighter-rgb) / <alpha-value>)',
          line: 'rgb(var(--wait-line-rgb) / <alpha-value>)',
          badge: 'var(--wait-badge-text)',
          tint: 'var(--wait-tint)',
        },
        info: {
          DEFAULT: 'rgb(var(--info-rgb) / <alpha-value>)',
          text: 'rgb(var(--info-text-rgb) / <alpha-value>)',
          lighter: 'rgb(var(--info-lighter-rgb) / <alpha-value>)',
          tint: 'var(--info-tint)',
        },
        tint: {
          ok: 'var(--ok-tint)',
          bad: 'var(--bad-tint)',
          wait: 'var(--wait-tint)',
          info: 'var(--info-tint)',
          accent: 'var(--accent-tint)',
        },

        // Backward compatibility aliases
        sidebar: 'rgb(var(--surface-1-rgb) / <alpha-value>)',
        card: 'rgb(var(--surface-2-rgb) / <alpha-value>)',
        border: {
          DEFAULT: 'rgb(var(--line-rgb) / <alpha-value>)',
          subtle: 'rgb(var(--line-rgb) / <alpha-value>)',
          strong: 'rgb(var(--line-strong-rgb) / <alpha-value>)',
        },
        text: {
          DEFAULT: 'rgb(var(--text-rgb) / <alpha-value>)',
          primary: 'rgb(var(--text-rgb) / <alpha-value>)',
          secondary: 'rgb(var(--text-2-rgb) / <alpha-value>)',
          muted: 'rgb(var(--text-3-rgb) / <alpha-value>)',
        },
        meaning: {
          allowed: 'rgb(var(--ok-rgb) / <alpha-value>)',
          waiting: 'rgb(var(--wait-rgb) / <alpha-value>)',
          stopped: 'rgb(var(--bad-rgb) / <alpha-value>)',
        },
        role: {
          developer: 'rgb(var(--role-developer-rgb) / <alpha-value>)',
          team_lead: 'rgb(var(--role-team-lead-rgb) / <alpha-value>)',
          security_reviewer: 'rgb(var(--role-security-reviewer-rgb) / <alpha-value>)',
          admin: 'rgb(var(--role-admin-rgb) / <alpha-value>)',
          auditor: 'rgb(var(--role-auditor-rgb) / <alpha-value>)',
        },
        governance: {
          allowed: 'rgb(var(--ok-rgb) / <alpha-value>)',
          stopped: 'rgb(var(--bad-rgb) / <alpha-value>)',
          waiting: 'rgb(var(--wait-rgb) / <alpha-value>)',
          accent: 'rgb(var(--accent-rgb) / <alpha-value>)',
        },
        ruleAction: 'var(--rule-action)',
        ruleActionHover: 'var(--rule-action-hover)',
        indigoLight: 'var(--indigo-light)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
        serif: ['"Instrument Serif"', 'serif'],
      },
      backgroundImage: {
        'accent-grad': 'var(--accent-grad)',
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
