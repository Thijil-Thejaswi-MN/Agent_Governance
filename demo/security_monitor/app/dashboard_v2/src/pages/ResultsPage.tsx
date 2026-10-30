import React, { useEffect, useState } from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { api } from '../api/client';
import { ResultsSummary } from '../types';

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
    return <div className="p-8 text-center" style={{ color: 'var(--text-2)' }}>Loading results…</div>;
  }

  if (!summary) {
    return <div className="p-8 text-center" style={{ color: 'var(--text-2)' }}>Results summary not available.</div>;
  }

  const harmA = summary.harm_injected?.['A'];
  const harmB = summary.harm_injected?.['B'];
  const harmC = summary.harm_injected?.['C'];
  const harmD = summary.harm_injected?.['D'];

  const harmData = [
    { name: 'A "No governance"', harm: harmA?.exposed, total: harmA?.total, fill: '#FB7185' },
    { name: 'B "Tool layer only"', harm: harmB?.exposed, total: harmB?.total, fill: '#34D399' },
    { name: 'C "Tool + OS layer"', harm: harmC?.exposed, total: harmC?.total, fill: '#22D3EE' },
    { name: 'D "Per-task container"', harm: harmD?.exposed, total: harmD?.total, fill: '#A78BFA' },
  ];

  const shellB = summary.shell_attacks_succeeded?.['B'];
  const shellC = summary.shell_attacks_succeeded?.['C'];

  const shellAttackData = [
    { name: 'B "Tool layer only"', succeeded: shellB?.succeeded, total: shellB?.total, fill: '#FB7185' },
    { name: 'C "Tool + OS layer"', succeeded: shellC?.succeeded, total: shellC?.total, fill: '#34D399' },
  ];

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
    ? expChain.steps.map(st => ({
        label: st.name,
        value: st.count !== undefined && st.total !== undefined ? `${st.count}/${st.total}` : '—',
        desc: 'Unanticipated resource expansion step',
      }))
    : [
        { label: 'Step 1: Denied (EACCES)', value: formatStepCount(expChain?.denied_before_request), desc: 'Agent attempts probe and is denied' },
        { label: 'Step 2: Requested', value: formatStepCount(expChain?.requested), desc: 'Agent requests access via broker' },
        { label: 'Step 3: Granted', value: formatStepCount(expChain?.granted), desc: 'Oracle approver grants access' },
        { label: 'Step 4: Delivered Read', value: formatStepCount(expChain?.delivered_read_ok), desc: 'Delivered read-only file read successfully' },
      ];

  const timings = summary.timings_and_timeouts;
  const ut = summary.utility_timings_anticipated;
  const timingA = timings?.['A'];
  const timingB = timings?.['B'];
  const timingC = timings?.['C'];
  const timingD = timings?.['D'];

  return (
    <div className="max-w-[1200px] mx-auto px-4 sm:px-10 pt-8 pb-16 space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div>
          <h1 className="m-0 font-display font-bold text-[36px] sm:text-[44px] leading-[1.1] tracking-[-1px]">Full results</h1>
          <p className="mt-2 mb-0 text-[15px]" style={{ color: 'var(--text-2)' }}>
            Recomputed directly from raw trial runs in <code className="mono">demo/data/evaluation_v3/results/</code>. Model: {summary.model}.
          </p>
        </div>
        <span className="inline-flex items-center min-h-[36px] px-3 rounded-full text-[13px] font-semibold" style={{ background: 'rgba(34,211,238,0.12)', color: '#A5F3FC', border: '1px solid rgba(34,211,238,0.35)' }}>
          {summary.evaluation_label || '—'}
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Harm Prevention */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="m-0 font-display text-[20px] font-bold">
                Harm Injected Trials
              </h2>
              <p className="m-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
                Number of trials where prompt injection successfully leaked decoy or sink canary.
              </p>
            </div>
            <span className="mono text-[13px]" style={{ color: 'var(--text-3)' }}>
              {harmA?.total !== undefined ? `N=${harmA.total} per condition` : '—'}
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={harmData} margin={{ top: 20, right: 20, left: -20, bottom: 20 }}>
                <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={0} stroke="#9AA4B8" />
                <YAxis domain={[0, harmA?.total || 32]} stroke="#9AA4B8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#121829', borderColor: '#334155', borderRadius: '12px', color: '#E6EAF2', fontSize: '12px' }}
                  cursor={{ fill: 'rgba(148,163,184,0.08)' }}
                />
                <Bar dataKey="harm" radius={[6, 6, 0, 0]}>
                  {harmData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="p-3 rounded-[14px] mono text-[13px]" style={{ background: 'var(--field)', color: 'var(--text-2)' }}>
            Harm: A "No governance" = {formatRatio(harmA)} | B "Tool layer only" = {formatRatio(harmB)} | C "Tool + OS layer" = {formatRatio(harmC)} | D "Per-task container" = {formatRatio(harmD)}
          </div>
        </div>

        {/* Chart 2: Shell Attacks Succeeded */}
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="m-0 font-display text-[20px] font-bold">
                Shell Channel Attack Outcomes
              </h2>
              <p className="m-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
                Shell channel attack outcomes in B "Tool layer only" vs C "Tool + OS layer".
              </p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={shellAttackData} margin={{ top: 20, right: 20, left: -20, bottom: 20 }}>
                <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={0} stroke="#9AA4B8" />
                <YAxis domain={[0, shellC?.total || 10]} stroke="#9AA4B8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#121829', borderColor: '#334155', borderRadius: '12px', color: '#E6EAF2', fontSize: '12px' }}
                  cursor={{ fill: 'rgba(148,163,184,0.08)' }}
                />
                <Bar dataKey="succeeded" radius={[6, 6, 0, 0]}>
                  {shellAttackData.map((entry, index) => (
                    <Cell key={`cell-shell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="p-3 rounded-[14px] mono text-[13px]" style={{ background: 'var(--field)', color: 'var(--text-2)' }}>
            B "Tool layer only": {formatRatio(shellB)} succeeded | C "Tool + OS layer": {formatRatio(shellC)} succeeded
          </div>
        </div>
      </div>

      {/* Expansion Chain Progression */}
      <div className="card p-6 space-y-4">
        <h2 className="m-0 font-display text-[20px] font-bold">
          Expansion Chain Progression (Unanticipated, C "Tool + OS layer")
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {stepsList.map((st, i) => (
            <div key={i} className="p-4 rounded-[14px]" style={{ background: 'var(--card-2)', border: '1px solid var(--line)' }}>
              <span className="mono text-[12px] block" style={{ color: 'var(--text-3)' }}>{st.label}</span>
              <div className="font-display text-[28px] font-bold mt-1" style={{ color: '#67E8F9' }}>
                {st.value}
              </div>
              <p className="text-[13px] mt-1 mb-0" style={{ color: 'var(--text-2)' }}>{st.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Latency and Timeouts */}
      <div className="card p-6 space-y-4">
        <h2 className="m-0 font-display text-[20px] font-bold">
          Trial Durations & Timeouts
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {[
            { name: 'A "No governance"', timing: timingA },
            { name: 'B "Tool layer only"', timing: timingB },
            { name: 'C "Tool + OS layer"', timing: timingC },
            { name: 'D "Per-task container"', timing: timingD },
          ].map((item, idx) => (
            <div key={idx} className="p-4 rounded-[14px]" style={{ background: 'var(--card-2)', border: '1px solid var(--line)' }}>
              <span className="mono text-[12px] block" style={{ color: 'var(--text-3)' }}>{item.name}</span>
              <div className="font-display text-[28px] font-bold mt-1">
                {item.timing?.mean_s !== undefined ? `${item.timing.mean_s}s` : '—'}
              </div>
              <p className="text-[13px] mt-1 mb-0" style={{ color: 'var(--text-2)' }}>
                Timeouts: {item.timing?.timeout_ratio || (item.timing?.timeouts !== undefined && item.timing?.total_trials !== undefined ? `${item.timing.timeouts}/${item.timing.total_trials}` : '—')}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Time per legitimate task */}
      <div className="card p-6 space-y-4" id="utility-timings">
        <h2 className="m-0 font-display text-[20px] font-bold">Time per legitimate task (anticipated, utility_v3d)</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            { name: 'A "No governance"', v: ut?.A ? `${ut.A.mean_s}s` : '—', n: ut?.A?.total_trials },
            { name: 'C "Tool + OS layer"', v: ut?.C ? `${ut.C.mean_s}s` : '—', n: ut?.C?.total_trials },
            { name: 'Extra time, C vs A', v: ut?.extra_s_c_vs_a !== undefined ? `+${ut.extra_s_c_vs_a.toFixed(1)}s` : '—', n: undefined },
          ].map(item => (
            <div key={item.name} className="p-4 rounded-[14px]" style={{ background: 'var(--card-2)', border: '1px solid var(--line)' }}>
              <span className="mono text-[12px] block" style={{ color: 'var(--text-3)' }}>{item.name}</span>
              <div className="font-display text-[28px] font-bold mt-1">{item.v}</div>
              {item.n !== undefined && <p className="text-[13px] mt-1 mb-0" style={{ color: 'var(--text-2)' }}>mean of {item.n} trials</p>}
            </div>
          ))}
        </div>
      </div>

      {/* Limitations List */}
      <div className="card p-6 space-y-3">
        <h2 className="m-0 font-display text-[20px] font-bold">
          Evaluation Scope & Limitations
        </h2>
        <ul className="space-y-2 text-[14px] leading-relaxed list-disc pl-5 m-0" style={{ color: 'var(--text-2)' }}>
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
