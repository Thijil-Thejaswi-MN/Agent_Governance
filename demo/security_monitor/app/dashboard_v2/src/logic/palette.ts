// Design token palette (single source of truth for console v4 colours)

export const PALETTE = {
  // Surfaces
  bg: '#0B0E14',
  surface1: '#0E121A',
  surface2: '#11151D',
  surface3: '#161B26',
  surfaceHover: '#1A2232',
  surfaceActive: '#161F30',
  surfaceTerminal: '#0B0F17',
  surfaceTerminalAlt: '#0B0F16',
  surfaceNavHover: '#141A24',
  surfaceTableHover: '#121826',
  surfaceDarkAlt: '#0F1520',
  surfaceDarkSlate: '#111827',
  surfaceSlate800: '#1E293B',
  surfaceSlate900: '#0F172A',

  // Lines & Borders
  line: '#1F2633',
  lineStrong: '#2A3344',
  lineSlate: '#334155',

  // Foreground / Text
  text: '#E6E9EF',
  text2: '#A7B0C0',
  text3: '#8B95A7',
  textDim: '#6B7487',
  textSoft: '#CBD5E1',

  // Accents
  accent: '#3B82F6',
  accentStrong: '#2563EB',
  accentDeep: '#1D4ED8',

  // Status: OK / Allowed
  ok: '#22C55E',
  okText: '#86EFAC',
  okLight: '#4ADE80',
  okLighter: '#BBF7D0',
  okVerdict: '#6EE7B7',
  okStrong: '#16A34A',

  // Status: Bad / Blocked
  bad: '#EF4444',
  badText: '#FCA5A5',
  badLight: '#F87171',
  badLighter: '#FECACA',
  badVerdict: '#FDA4AF',
  badStrong: '#DC2626',

  // Status: Wait / Warning
  wait: '#F59E0B',
  waitText: '#FCD34D',
  waitKpi: '#FBBF24',
  waitLighter: '#FDE68A',
  waitLine: '#3A2E12',
  waitBadgeText: '#1A1203',

  // Status: Info
  info: '#60A5FA',
  infoText: '#93C5FD',
  infoLighter: '#BFDBFE',
  sourceText: '#A5F3FC',

  // Tints (translucent overlays)
  okTint: 'rgba(34, 197, 94, 0.12)',
  badTint: 'rgba(239, 68, 68, 0.12)',
  waitTint: 'rgba(245, 158, 11, 0.12)',
  infoTint: 'rgba(96, 165, 250, 0.12)',
  accentTint: 'rgba(59, 130, 246, 0.12)',

  // Roles
  roleDeveloper: '#60A5FA',
  roleTeamLead: '#A78BFA',
  roleSecurityReviewer: '#FBBF24',
  roleAdmin: '#34D399',
  roleAdminContrast: '#04130F',
  roleAuditor: '#F472B6',

  // Actions & Specialized Elements
  ruleAction: '#7C3AED',
  ruleActionHover: '#6D28D9',
  blocked: '#FB7185',
  blockedText: '#FECDD3',

  // Legacy & Specific Art Colours
  cyan: '#22D3EE',
  slate500: '#64748B',
  indigoLight: '#C7D2FE',
} as const;

export type PaletteKey = keyof typeof PALETTE;
