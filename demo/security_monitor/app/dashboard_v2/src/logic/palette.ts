// Design token palette (single source of truth for console v4 colours)

export const PALETTE = {
  // Surfaces
  bg: '#0A0A0B',
  surface1: '#111113',
  surface2: '#17171A',
  surface3: '#1E1E22',
  surfaceHover: '#17171A',
  surfaceActive: '#1E1E22',
  surfaceTerminal: '#0A0A0B',
  surfaceTerminalAlt: '#0E0E10',
  surfaceNavHover: '#17171A',
  surfaceTableHover: '#17171A',
  surfaceDarkAlt: '#111113',
  surfaceDarkSlate: '#111113',
  surfaceSlate800: '#17171A',
  surfaceSlate900: '#111113',

  // Lines & Borders
  line: '#26262B',
  lineStrong: '#34343B',
  lineSlate: '#34343B',

  // Foreground / Text
  text: '#F4F4F5',
  text2: '#A1A1AA',
  text3: '#8B8B94',
  textDim: '#71717A',
  textSoft: '#D4D4D8',

  // Accents
  accent: '#818CF8',
  accentStrong: '#6366F1',
  accentDeep: '#4F46E5',
  accentGrad: 'linear-gradient(90deg, #4338CA, #BE185D, #B45309)',

  // Status: OK / Allowed
  ok: '#34D399',
  okText: '#34D399',
  okLight: '#6EE7B7',
  okLighter: '#A7F3D0',
  okVerdict: '#6EE7B7',
  okStrong: '#10B981',

  // Status: Bad / Blocked
  bad: '#F87171',
  badText: '#F87171',
  badLight: '#FCA5A5',
  badLighter: '#FECACA',
  badVerdict: '#FDA4AF',
  badStrong: '#EF4444',

  // Status: Wait / Warning
  wait: '#FBBF24',
  waitText: '#FBBF24',
  waitKpi: '#FBBF24',
  waitLighter: '#FDE68A',
  waitLine: '#34343B',
  waitBadgeText: '#1A1203',

  // Status: Info
  info: '#818CF8',
  infoText: '#818CF8',
  infoLighter: '#C7D2FE',
  sourceText: '#A5F3FC',

  // Tints (translucent overlays at 10%)
  okTint: 'rgba(52, 211, 153, 0.10)',
  badTint: 'rgba(248, 113, 113, 0.10)',
  waitTint: 'rgba(251, 191, 36, 0.10)',
  infoTint: 'rgba(129, 140, 248, 0.10)',
  accentTint: 'rgba(129, 140, 248, 0.10)',

  // Roles
  roleDeveloper: '#818CF8',
  roleTeamLead: '#A78BFA',
  roleSecurityReviewer: '#FBBF24',
  roleAdmin: '#34D399',
  roleAdminContrast: '#04130F',
  roleAuditor: '#F472B6',

  // Actions & Specialized Elements
  ruleAction: '#7C3AED',
  ruleActionHover: '#6D28D9',
  blocked: '#F87171',
  blockedText: '#FCA5A5',

  // Legacy & Specific Art Colours
  cyan: '#22D3EE',
  slate500: '#64748B',
  indigoLight: '#C7D2FE',
} as const;

export type PaletteKey = keyof typeof PALETTE;
