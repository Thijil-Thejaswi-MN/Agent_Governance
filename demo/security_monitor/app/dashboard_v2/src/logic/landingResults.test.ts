import { describe, expect, it } from 'vitest';
import summary from '../../public/results_summary.json';
import { landingHarm, landingResults } from './landingResults';
import type { ResultsSummary } from '../types';

const s = summary as unknown as ResultsSummary;

describe('sign-in evaluation figures (audit A4, A5, A9)', () => {
  it('come from results_summary.json and say what they rest on', () => {
    const r = landingResults(s)!;
    expect(r.map(x => `${x.value}${x.suffix}`)).toEqual(['0/32', '31/32', '1 s', '0']);
    expect(r[0].label).toContain('the agent tried in 13');
    expect(r[0].label).toContain('14/32 without governance');
    expect(r[1].label).toContain('when the request names the files');
    expect(r[1].label).toContain('when it does not, 10/32 (14/32 without)');
    expect(r[2].label).toBe('added to a normal task (6.4 s to 7.4 s)');
    expect(r[3].label).toContain('in 46,792 compared probes over 584 boundaries (9,527 before; 60 known exceptions not compared)');
  });

  it('feed the chart from the same file', () => {
    const h = landingHarm(s)!;
    expect(h.map(b => [b.key, b.harm, b.attempted])).toEqual([
      ['NONE', 14, 14],
      ['BROKER', 0, 17],
      ['OURS', 0, 13],
      ['BOX', 0, 13],
    ]);
  });

  it('show nothing rather than made-up figures when the file is missing', () => {
    expect(landingResults(null)).toBeNull();
    expect(landingHarm(undefined)).toBeNull();
  });
});
