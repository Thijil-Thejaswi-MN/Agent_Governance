// Text contrast of the v3 palette: every text colour on every surface it is used on is
// at least 4.5:1 (WCAG AA for body text). Tinted surfaces are the tint over the page.
import { describe, expect, it } from 'vitest';

type RGB = [number, number, number];

const hex = (h: string): RGB => {
  const v = h.replace('#', '');
  return [0, 2, 4].map(i => parseInt(v.slice(i, i + 2), 16)) as RGB;
};

const lin = (c: number) => {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const lum = ([r, g, b]: RGB) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
const ratio = (a: RGB, b: RGB) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};
// A translucent tint over a base colour.
const over = (tint: string, alpha: number, base: string): RGB => {
  const t = hex(tint);
  const b = hex(base);
  return t.map((c, i) => Math.round(c * alpha + b[i] * (1 - alpha))) as RGB;
};

const BG = '#070B14';
const CARD = '#0F1526';
const CARD2 = '#121829';
const FIELD = '#0B1120';

const surfaces: Record<string, RGB> = {
  bg: hex(BG),
  card: hex(CARD),
  card2: hex(CARD2),
  field: hex(FIELD),
};

describe('text contrast >= 4.5:1', () => {
  const textOnSurfaces: Record<string, string[]> = {
    '#E6EAF2': ['bg', 'card', 'card2', 'field'], // text
    '#CBD5E1': ['bg'], // decision lead
    '#A9B4C7': ['bg', 'card', 'card2', 'field'], // secondary
    '#9AA4B8': ['bg', 'card', 'card2', 'field'], // tertiary
    '#67E8F9': ['bg', 'card', 'card2'], // links
    '#A5F3FC': ['bg', 'card'], // active nav, labels
    '#FDA4AF': ['bg', 'card'], // blocked numbers
    '#6EE7B7': ['bg', 'card'], // allowed numbers
    '#FDE68A': ['bg', 'card'], // waiting text
    '#FCD34D': ['bg'], // "need you"
  };
  for (const [fg, on] of Object.entries(textOnSurfaces)) {
    for (const s of on) {
      it(`${fg} on ${s}`, () => {
        expect(ratio(hex(fg), surfaces[s])).toBeGreaterThanOrEqual(4.5);
      });
    }
  }

  it('meaning text on its tinted chip or panel', () => {
    const pairs: Array<[string, RGB]> = [
      ['#A7F3D0', over('#34D399', 0.14, BG)], // allowed chip
      ['#FECDD3', over('#FB7185', 0.14, BG)], // blocked chip
      ['#FDE68A', over('#FBBF24', 0.14, BG)], // waiting chip
      ['#FECDD3', over('#FB7185', 0.08, BG)], // warning panel
      ['#E6EAF2', over('#FBBF24', 0.08, BG)], // needs-you row
      ['#A9B4C7', over('#FBBF24', 0.08, BG)],
      ['#A5F3FC', over('#22D3EE', 0.14, BG)], // active nav pill
      ['#A7F3D0', over('#34D399', 0.12, BG)], // record checked
    ];
    for (const [fg, bg] of pairs) expect(ratio(hex(fg), bg), fg).toBeGreaterThanOrEqual(4.5);
  });

  it('button text on both ends of its gradient', () => {
    for (const end of ['#22D3EE', '#A78BFA']) expect(ratio(hex('#070B14'), hex(end))).toBeGreaterThanOrEqual(4.5);
    for (const end of ['#34D399', '#22D3EE']) expect(ratio(hex('#04130F'), hex(end))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(hex('#1A1203'), hex('#FBBF24'))).toBeGreaterThanOrEqual(4.5);
  });
});
