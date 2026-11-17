// Text contrast of the design token palette: every text colour on every surface it is used on is
// at least 4.5:1 (WCAG AA for body text). Tinted surfaces are the tint over the page.
import { describe, expect, it } from 'vitest';
import { PALETTE } from './palette';

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

const surfaces: Record<string, RGB> = {
  bg: hex(PALETTE.bg),
  surface1: hex(PALETTE.surface1),
  surface2: hex(PALETTE.surface2),
  surface3: hex(PALETTE.surface3),
};

describe('text contrast >= 4.5:1', () => {
  const testedColors = Array.from(new Set([
    PALETTE.text,
    PALETTE.text2,
    PALETTE.text3,
    PALETTE.okText,
    PALETTE.badText,
    PALETTE.waitText,
    PALETTE.waitKpi,
    PALETTE.info,
    PALETTE.infoText,
  ]));
  for (const fg of testedColors) {
    for (const s of ['bg', 'surface1', 'surface2', 'surface3']) {
      it(`${fg} on ${s}`, () => {
        expect(ratio(hex(fg), surfaces[s])).toBeGreaterThanOrEqual(4.5);
      });
    }
  }

  it('meaning text on its tinted chip or panel', () => {
    const pairs: Array<[string, RGB]> = [
      [PALETTE.okText, over(PALETTE.ok, 0.14, PALETTE.bg)],
      [PALETTE.badText, over(PALETTE.bad, 0.14, PALETTE.bg)],
      [PALETTE.waitText, over(PALETTE.wait, 0.14, PALETTE.bg)],
      [PALETTE.waitKpi, over(PALETTE.wait, 0.14, PALETTE.bg)],
      [PALETTE.infoText, over(PALETTE.info, 0.14, PALETTE.bg)],
      [PALETTE.text, over(PALETTE.wait, 0.08, PALETTE.bg)],
      [PALETTE.text2, over(PALETTE.wait, 0.08, PALETTE.bg)],
    ];
    for (const [fg, bg] of pairs) expect(ratio(hex(fg), bg), fg).toBeGreaterThanOrEqual(4.5);
  });

  it('button text on both ends of its gradient', () => {
    expect(ratio(hex(PALETTE.bg), hex(PALETTE.cyan))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(hex(PALETTE.bg), hex(PALETTE.roleTeamLead))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(hex('#04130F'), hex(PALETTE.roleAdmin))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(hex(PALETTE.waitBadgeText), hex(PALETTE.waitKpi))).toBeGreaterThanOrEqual(4.5);
  });

  it('white text on --accent-grad is >= 5:1 on every stop', () => {
    const stops = ['#4338CA', '#BE185D', '#B45309'];
    for (const stop of stops) {
      expect(ratio(hex('#FFFFFF'), hex(stop))).toBeGreaterThanOrEqual(5.0);
    }
  });

  it('keeps PALETTE values in sync with index.css', () => {
    // Read index.css
    // @ts-ignore
    const fs = require('node:fs');
    // @ts-ignore
    const path = require('node:path');
    // @ts-ignore
    const cssPath = typeof __dirname !== 'undefined' ? path.resolve(__dirname, '../index.css') : '';
    const css = fs.readFileSync(cssPath, 'utf-8');

    expect(css).toContain(`--bg: ${PALETTE.bg}`);
    expect(css).toContain(`--surface-1: ${PALETTE.surface1}`);
    expect(css).toContain(`--surface-2: ${PALETTE.surface2}`);
    expect(css).toContain(`--surface-3: ${PALETTE.surface3}`);
    expect(css).toContain(`--line: ${PALETTE.line}`);
    expect(css).toContain(`--line-strong: ${PALETTE.lineStrong}`);
    expect(css).toContain(`--text: ${PALETTE.text}`);
    expect(css).toContain(`--text-2: ${PALETTE.text2}`);
    expect(css).toContain(`--text-3: ${PALETTE.text3}`);
    expect(css).toContain(`--accent: ${PALETTE.accent}`);
    expect(css).toContain(`--accent-grad: ${PALETTE.accentGrad}`);
    expect(css).toContain(`--ok: ${PALETTE.ok}`);
    expect(css).toContain(`--bad: ${PALETTE.bad}`);
    expect(css).toContain(`--wait: ${PALETTE.wait}`);
    expect(css).toContain(`--info: ${PALETTE.info}`);
  });
});
