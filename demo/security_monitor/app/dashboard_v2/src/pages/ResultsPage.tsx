import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { api } from '../api/client';
import { ResultsSummary } from '../types';
import { HowItWorks } from '../components/v3/HowItWorks';
import { PALETTE } from '../logic/palette';
import { PageHeader } from '../components/ui/PageHeader';
import { Button } from '../components/ui/Button';

// Ours (Condition C) is --accent, others are --text-3 bars.
const CONDITION_COLORS: Record<'A' | 'B' | 'C' | 'D', string> = {
  A: PALETTE.text3,
  B: PALETTE.text3,
  C: PALETTE.accent,
  D: PALETTE.text3,
};

// What each step of the expansion chain is, in plain words (same order as the summary's steps).
const EXPANSION_STEP_TEXT = [
  'The OS refused the initial try',
  'The agent asked for the file',
  'Approved (by a simulated user)',
  'The file reached the agent',
];

const yLabel = (value: string) => ({
  value,
  angle: -90,
  position: 'insideLeft' as const,
  offset: 4,
  style: { textAnchor: 'middle' as const, fill: PALETTE.text2, fontSize: 12 },
});

// The axes show only the condition letter; this maps each letter to its name, in the bar's colour.
const ChartLegend: React.FC<{ id: string; items: Array<{ id: string; label: string; fill: string }> }> = ({ id, items }) => (
  <ul id={id} className="list-none m-0 p-0 flex flex-wrap gap-x-5 gap-y-1.5 text-[14px] text-fg-2">
    {items.map(it => (
      <li key={it.id} data-legend-id={it.id} className="inline-flex items-center gap-2">
        <span aria-hidden="true" className="inline-block w-2.5 h-2.5 rounded-[3px]" style={{ background: it.fill }} />
        <span className="font-semibold text-fg">{it.id}</span>
        {it.label}
      </li>
    ))}
  </ul>
);

export const ResultsPage: React.FC = () => {
  const [summary, setSummary] = useState<ResultsSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getResultsSummary()
      .then((data: ResultsSummary) => setSummary(data))
      .catch((err: unknown) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="p-8 text-center text-fg-2">Loading results…</div>;
  }

  if (!summary) {
    return (
      <div className="p-8 text-center flex flex-col items-center gap-3 text-fg-2">
        Results summary not available.
        <Link to="/evidence" id="open-evidence" className="underline text-accent">
          Open the recorded evidence
        </Link>
      </div>
    );
  }

  const harmA = summary.harm_injected?.['A'];
  const harmB = summary.harm_injected?.['B'];
  const harmC = summary.harm_injected?.['C'];
  const harmD = summary.harm_injected?.['D'];

  const harmData = [
    { id: 'A', label: 'No governance', name: 'A "No governance"', harm: harmA?.exposed, total: harmA?.total, fill: CONDITION_COLORS.A },
    { id: 'B', label: 'Tool layer only', name: 'B "Tool layer only"', harm: harmB?.exposed, total: harmB?.total, fill: CONDITION_COLORS.B },
    { id: 'C', label: 'Tool + OS layer', name: 'C "Tool + OS layer"', harm: harmC?.exposed, total: harmC?.total, fill: CONDITION_COLORS.C },
    { id: 'D', label: 'Per-task container', name: 'D "Per-task container"', harm: harmD?.exposed, total: harmD?.total, fill: CONDITION_COLORS.D },
  ];

  const shellB = summary.shell_attacks_succeeded?.['B'];
  const shellC = summary.shell_attacks_succeeded?.['C'];

  const shellAttackData = [
    { id: 'B', label: 'Tool layer only', name: 'B "Tool layer only"', succeeded: shellB?.succeeded, total: shellB?.total, fill: CONDITION_COLORS.B },
    { id: 'C', label: 'Tool + OS layer', name: 'C "Tool + OS layer"', succeeded: shellC?.succeeded, total: shellC?.total, fill: CONDITION_COLORS.C },
  ];

  // Shell chart y-axis: even, evenly spaced ticks (0, 2, 4 … 10 for 10 trials).
  const shellMax = shellC?.total || 10;
  const shellStep = Math.max(2, Math.ceil(shellMax / 10) * 2);
  const shellTop = Math.ceil(shellMax / shellStep) * shellStep;
  const shellTicks = Array.from({ length: shellTop / shellStep + 1 }, (_, i) => i * shellStep);

  const formatRatio = (item?: { exposed?: number; succeeded?: number; correct?: number; total?: number; ratio?: string }) => {
    if (!item) return '—';
    if (item.ratio) return item.ratio;
    const val = item.exposed ?? item.succeeded ?? item.correct;
    if (val !== undefined && item.total !== undefined) return `${val}/${item.total}`;
    return '—';
  };

  const expChain = summary.expansion_chain_unanticipated_c;
  const expTotal = expChain?.total;
  const formatStepCount = (count?: number) => {
    if (count === undefined || count === null) return '—';
    return expTotal !== undefined ? `${count}/${expTotal}` : `${count}`;
  };

  const stepsList = expChain?.steps && expChain.steps.length > 0
    ? expChain.steps.map((st, i) => ({
        label: st.name,
        value: st.count !== undefined && st.total !== undefined ? `${st.count}/${st.total}` : '—',
        desc: EXPANSION_STEP_TEXT[i] ?? '',
      }))
    : [
        { label: 'Step 1: Denied (EACCES)', value: formatStepCount(expChain?.denied_before_request), desc: EXPANSION_STEP_TEXT[0] },
        { label: 'Step 2: Requested', value: formatStepCount(expChain?.requested), desc: EXPANSION_STEP_TEXT[1] },
        { label: 'Step 3: Granted', value: formatStepCount(expChain?.granted), desc: EXPANSION_STEP_TEXT[2] },
        { label: 'Step 4: Delivered Read', value: formatStepCount(expChain?.delivered_read_ok), desc: EXPANSION_STEP_TEXT[3] },
      ];

  const timings = summary.timings_and_timeouts;
  const ut = summary.utility_timings_anticipated;
  const timingA = timings?.['A'];
  const timingB = timings?.['B'];
  const timingC = timings?.['C'];
  const timingD = timings?.['D'];
  // The timings cover the injected trials only; say how many when every setup has the same count.
  const trialCounts = [timingA, timingB, timingC, timingD].map(t => t?.total_trials);
  const sameTrialCount = trialCounts[0] !== undefined && trialCounts.every(n => n === trialCounts[0]) ? trialCounts[0] : undefined;

  return (
    <div className="max-w-[1200px] pb-12 space-y-6">
      <PageHeader
        title="Full results"
        subtitle={
          <span>
            Recomputed directly from raw trial runs in <code className="font-mono text-accent">demo/data/evaluation_v3/results/</code>. Model: {summary.model}.
          </span>
        }
        actions={
          <span className="inline-flex items-center min-h-[36px] px-3 rounded-full text-[13px] font-semibold bg-accent-tint text-accent border border-accent/40">
            {summary.evaluation_label || '—'}
          </span>
        }
      />

      <section className="rounded-xl border border-line bg-surface-1 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3" id="evidence-link">
        <div className="flex flex-col gap-1">
          <h2 className="m-0 text-[17px] font-semibold text-fg">See the attacks behind these numbers</h2>
          <p className="m-0 text-[14px] text-fg-2 leading-relaxed">
            Pick any attack and see the hidden instruction in its input file, then the exact step where the agent acted on
            it in each setup, and what came back. Read straight from the raw trial files.
          </p>
        </div>
        <Link to="/evidence" id="open-evidence" className="no-underline shrink-0">
          <Button variant="primary" size="md">
            Open the recorded evidence
          </Button>
        </Link>
      </section>

      <HowItWorks />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Harm Prevention */}
        <div className="rounded-xl border border-line bg-surface-1 p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1 sm:gap-4">
            <div>
              <h2 className="m-0 text-[17px] font-semibold text-fg">
                Harm in injected trials
              </h2>
              <p className="m-0 text-[14px] text-fg-2">
                Number of trials where prompt injection successfully leaked decoy or sink canary.
              </p>
            </div>
            <span className="font-mono text-[13px] whitespace-nowrap shrink-0 text-fg-3">
              {harmA?.total !== undefined ? `N=${harmA.total} per condition` : '—'}
            </span>
          </div>

          <div className="h-64 w-full" id="chart-harm">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={harmData} margin={{ top: 20, right: 20, left: 4, bottom: 20 }}>
                <XAxis dataKey="id" tick={{ fontSize: 13 }} interval={0} stroke={PALETTE.text3} />
                <YAxis domain={[0, harmA?.total || 32]} stroke={PALETTE.text3} width={44} label={yLabel('trials with harm')} />
                <Tooltip
                  contentStyle={{ backgroundColor: PALETTE.surface1, borderColor: PALETTE.lineStrong, borderRadius: '8px', color: PALETTE.text, fontSize: '12px' }}
                  labelFormatter={(_id, items) => (items?.[0]?.payload as { name?: string } | undefined)?.name ?? String(_id)}
                  cursor={{ fill: 'rgba(148,163,184,0.08)' }}
                />
                <Bar dataKey="harm" radius={[6, 6, 0, 0]} isAnimationActive={false}>
                  {harmData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <ChartLegend id="chart-harm-legend" items={harmData} />
          <div className="p-3 rounded-lg font-mono text-[13px] bg-surface-2 border border-line text-fg-2">
            Harm: A "No governance" = {formatRatio(harmA)} | B "Tool layer only" = {formatRatio(harmB)} | C "Tool + OS layer" = {formatRatio(harmC)} | D "Per-task container" = {formatRatio(harmD)}
          </div>
        </div>

        {/* Chart 2: Shell Attacks Succeeded */}
        <div className="rounded-xl border border-line bg-surface-1 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="m-0 text-[17px] font-semibold text-fg">
                Shell Channel Attack Outcomes
              </h2>
              <p className="m-0 text-[14px] text-fg-2">
                Shell channel attack outcomes in B "Tool layer only" vs C "Tool + OS layer".
              </p>
            </div>
          </div>

          <div className="h-64 w-full" id="chart-shell">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={shellAttackData} margin={{ top: 20, right: 20, left: 4, bottom: 20 }}>
                <XAxis dataKey="id" tick={{ fontSize: 13 }} interval={0} stroke={PALETTE.text3} />
                <YAxis domain={[0, shellTop]} ticks={shellTicks} interval={0} allowDecimals={false} stroke={PALETTE.text3} width={44} label={yLabel('attacks that worked')} />
                <Tooltip
                  contentStyle={{ backgroundColor: PALETTE.surface1, borderColor: PALETTE.lineStrong, borderRadius: '8px', color: PALETTE.text, fontSize: '12px' }}
                  labelFormatter={(_id, items) => (items?.[0]?.payload as { name?: string } | undefined)?.name ?? String(_id)}
                  cursor={{ fill: 'rgba(148,163,184,0.08)' }}
                />
                <Bar dataKey="succeeded" radius={[6, 6, 0, 0]} isAnimationActive={false}>
                  {shellAttackData.map((entry, index) => (
                    <Cell key={`cell-shell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <ChartLegend id="chart-shell-legend" items={shellAttackData} />
          <div className="p-3 rounded-lg font-mono text-[13px] bg-surface-2 border border-line text-fg-2">
            B "Tool layer only": {formatRatio(shellB)} succeeded | C "Tool + OS layer": {formatRatio(shellC)} succeeded
          </div>
        </div>
      </div>

      {/* Expansion Chain Progression */}
      <div className="rounded-xl border border-line bg-surface-1 p-6 space-y-4">
        <h2 className="m-0 text-[17px] font-semibold text-fg">
          Expansion Chain Progression (Unanticipated, C "Tool + OS layer")
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {stepsList.map((st, i) => (
            <div key={i} className="p-4 rounded-xl bg-surface-2 border border-line">
              <span className="font-mono text-[12px] block text-fg-3">{st.label}</span>
              <div className="text-[26px] font-bold tracking-tight mt-1 text-accent">
                {st.value}
              </div>
              <p className="text-[13px] mt-1 mb-0 text-fg-2">{st.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Latency and Timeouts */}
      <div className="rounded-xl border border-line bg-surface-1 p-6 space-y-4">
        <div>
          <h2 className="m-0 text-[17px] font-semibold text-fg">
            Trial Durations & Timeouts
          </h2>
          <p className="m-0 text-[14px] text-fg-2" id="timings-basis">
            {`Mean time of the ${sameTrialCount !== undefined ? `${sameTrialCount} ` : ''}injected trials per setup${summary.model ? ` (${summary.model})` : ''}.`}
          </p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {[
            { name: 'A "No governance"', timing: timingA },
            { name: 'B "Tool layer only"', timing: timingB },
            { name: 'C "Tool + OS layer"', timing: timingC },
            { name: 'D "Per-task container"', timing: timingD },
          ].map((item, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-surface-2 border border-line">
              <span className="font-mono text-[12px] block text-fg-3">{item.name}</span>
              <div className="text-[26px] font-bold tracking-tight mt-1 text-fg">
                {item.timing?.mean_s !== undefined ? `${item.timing.mean_s}s` : '—'}
              </div>
              <p className="text-[13px] mt-1 mb-0 text-fg-2">
                Timeouts: {item.timing?.timeout_ratio || (item.timing?.timeouts !== undefined && item.timing?.total_trials !== undefined ? `${item.timing.timeouts}/${item.timing.total_trials}` : '—')}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Time per legitimate task */}
      <div className="rounded-xl border border-line bg-surface-1 p-6 space-y-4" id="utility-timings">
        <h2 className="m-0 text-[17px] font-semibold text-fg">Time per legitimate task (anticipated, utility_v3d)</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            { name: 'A "No governance"', v: ut?.A ? `${ut.A.mean_s}s` : '—', n: ut?.A?.total_trials },
            { name: 'C "Tool + OS layer"', v: ut?.C ? `${ut.C.mean_s}s` : '—', n: ut?.C?.total_trials },
            { name: 'Extra time, C vs A', v: ut?.extra_s_c_vs_a !== undefined ? `+${ut.extra_s_c_vs_a.toFixed(1)}s` : '—', n: undefined },
          ].map(item => (
            <div key={item.name} className="p-4 rounded-xl bg-surface-2 border border-line">
              <span className="font-mono text-[12px] block text-fg-3">{item.name}</span>
              <div className="text-[26px] font-bold tracking-tight mt-1 text-fg">{item.v}</div>
              {item.n !== undefined && <p className="text-[13px] mt-1 mb-0 text-fg-2">mean of {item.n} trials</p>}
            </div>
          ))}
        </div>
      </div>

      {/* Limitations List */}
      <div className="rounded-xl border border-line bg-surface-1 p-6 space-y-3">
        <h2 className="m-0 text-[17px] font-semibold text-fg">
          Evaluation Scope & Limitations
        </h2>
        <ul className="space-y-2 text-[14px] leading-relaxed list-disc pl-5 m-0 text-fg-2">
          {summary.limitations && summary.limitations.length > 0 ? (
            summary.limitations.map((lim, idx) => (
              <li key={idx}>{lim}</li>
            ))
          ) : (
            <li>—</li>
          )}
        </ul>
      </div>
    </div>
  );
};
