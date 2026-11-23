// Six distinct identity colors (never green/red/amber):
// 0: indigo/accent (rgb(129, 140, 248)), 1: purple (rgb(168, 85, 247)), 2: sky/cyan (rgb(56, 189, 248)),
// 3: pink (rgb(244, 114, 182)), 4: fuchsia (rgb(217, 70, 239)), 5: blue (rgb(96, 165, 250))
export const AGENT_COLOUR_CLASSES = [
  { text: 'text-accent', border: 'border-accent', bg: 'bg-accent/10', color: 'rgb(var(--accent-rgb))' },
  { text: 'text-purple-400', border: 'border-purple-400', bg: 'bg-purple-400/10', color: 'rgb(192 132 252)' },
  { text: 'text-sky-400', border: 'border-sky-400', bg: 'bg-sky-400/10', color: 'rgb(56 189 248)' },
  { text: 'text-pink-400', border: 'border-pink-400', bg: 'bg-pink-400/10', color: 'rgb(244 114 182)' },
  { text: 'text-fuchsia-400', border: 'border-fuchsia-400', bg: 'bg-fuchsia-400/10', color: 'rgb(232 121 249)' },
  { text: 'text-blue-400', border: 'border-blue-400', bg: 'bg-blue-400/10', color: 'rgb(96 165 250)' },
];

export function getAgentColorStyle(agentId: string, colourIndex?: number) {
  if (colourIndex !== undefined && colourIndex >= 0 && colourIndex < AGENT_COLOUR_CLASSES.length) {
    return AGENT_COLOUR_CLASSES[colourIndex];
  }
  let hash = 0;
  for (let i = 0; i < agentId.length; i++) {
    hash = (hash << 5) - hash + agentId.charCodeAt(i);
    hash |= 0;
  }
  const idx = Math.abs(hash) % AGENT_COLOUR_CLASSES.length;
  return AGENT_COLOUR_CLASSES[idx];
}

export function getAgentInitials(nameOrId: string): string {
  if (!nameOrId) return 'AG';
  const clean = nameOrId.replace(/^host:/, '').replace(/_/g, ' ').trim();
  const parts = clean.split(/\s+/);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return clean.slice(0, 2).toUpperCase();
}
