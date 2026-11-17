// The evaluation figures on the sign-in page, read from results_summary.json (which
// scripts/build_results_summary.py recomputes from the raw trial files). Nothing here is a
// live number, and each label says what the figure rests on (independent audit A4, A5, A9).

import type { ResultsSummary } from '../types';

export interface LandingResult {
  glyph: string;
  value: number;
  suffix: string;
  decimals?: number;
  label: string;
}

/** Broker/kernel disagreements before and after the single resolved boundary
 *  (docs/M7_SINGLE_SOURCE_FINDINGS.md; not part of results_summary.json). */
export const M7 = { before: 9091, after: 0, boundaries: 552, compared: 43352, probes: 60624, residuals: 60 };

export function landingResults(s: ResultsSummary | null | undefined): LandingResult[] | null {
  const hA = s?.harm_injected?.A;
  const hC = s?.harm_injected?.C;
  const uA = s?.utility_anticipated_correct?.A;
  const uC = s?.utility_anticipated_correct?.C;
  const t = s?.utility_timings_anticipated;
  if (!hA || !hC || !uA || !uC || !t?.A || !t?.C) return null;
  const tried = hC.attempted != null ? `; the agent tried in ${hC.attempted}` : '';
  const unC = s?.utility_unanticipated_correct?.C;
  const unA = s?.utility_unanticipated_correct?.A;
  return [
    {
      glyph: '!',
      value: hC.exposed,
      suffix: `/${hC.total}`,
      label: `injected tasks caused harm with broker + kernel${tried} (${hA.ratio} without governance)`,
    },
    {
      glyph: '%',
      value: uC.correct,
      suffix: `/${uC.total}`,
      label:
        `normal tasks done correctly when the request names the files (${uA.ratio} without)` +
        (unC ? `; when it does not, ${unC.ratio}${unA ? ` (${unA.ratio} without)` : ''}` : ''),
    },
    {
      glyph: '+',
      value: Math.round((t.C.mean_s - t.A.mean_s) * 10) / 10,
      suffix: ' s',
      decimals: 1,
      label: `added to a normal task (${t.A.mean_s} s to ${t.C.mean_s} s)`,
    },
    {
      glyph: '=',
      value: M7.after,
      suffix: '',
      label:
        `broker and kernel disagreements in ${M7.compared.toLocaleString('en-US')} compared probes over ` +
        `${M7.boundaries} boundaries (${M7.before.toLocaleString('en-US')} before; ` +
        `${M7.residuals} known exceptions not compared)`,
    },
  ];
}

export interface HarmBar {
  key: string;
  label: string;
  harm: number;
  attempted?: number;
  ours?: boolean;
}

/** The "How it works" chart: harm per setup, from the same file. */
export function landingHarm(s: ResultsSummary | null | undefined): HarmBar[] | null {
  const h = s?.harm_injected;
  if (!h?.A || !h?.B || !h?.C || !h?.D) return null;
  return [
    { key: 'NONE', label: 'No governance', harm: h.A.exposed, attempted: h.A.attempted },
    { key: 'BROKER', label: 'Tool broker only', harm: h.B.exposed, attempted: h.B.attempted },
    { key: 'OURS', label: 'Broker + kernel (ours)', harm: h.C.exposed, attempted: h.C.attempted, ours: true },
    { key: 'BOX', label: 'Per-task container', harm: h.D.exposed, attempted: h.D.attempted },
  ];
}
