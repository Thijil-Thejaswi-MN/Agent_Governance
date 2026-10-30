import React, { useEffect, useState } from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { api } from '../api/client';
import { ResultsSummary } from '../types';
import { Badge } from '../components/common/Badge';

export const EvaluationPage: React.FC = () => {
  const [summary, setSummary] = useState<ResultsSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getResultsSummary()
      .then((data: ResultsSummary) => setSummary(data))
      .catch((err: unknown) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="p-8 text-center text-xs font-mono text-slate-400">Loading evaluation benchmarks...</div>;
  }

  if (!summary) {
    return <div className="p-8 text-center text-xs font-mono text-slate-400">Results summary not available.</div>;
  }

  const harmA = summary.harm_injected?.['A'];
  const harmB = summary.harm_injected?.['B'];
  const harmC = summary.harm_injected?.['C'];
  const harmD = summary.harm_injected?.['D'];

  const harmData = [
    { name: 'A "No governance"', harm: harmA?.exposed, total: harmA?.total, fill: '#ef4444' },
    { name: 'B "Tool layer only"', harm: harmB?.exposed, total: harmB?.total, fill: '#10b981' },
    { name: 'C "Tool + OS layer"', harm: harmC?.exposed, total: harmC?.total, fill: '#06b6d4' },
    { name: 'D "Per-task container"', harm: harmD?.exposed, total: harmD?.total, fill: '#8b5cf6' },
  ];

  const shellB = summary.shell_attacks_succeeded?.['B'];
  const shellC = summary.shell_attacks_succeeded?.['C'];

  const shellAttackData = [
    { name: 'B "Tool layer only"', succeeded: shellB?.succeeded, total: shellB?.total, fill: '#ef4444' },
    { name: 'C "Tool + OS layer"', succeeded: shellC?.succeeded, total: shellC?.total, fill: '#10b981' },
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
  const timingA = timings?.['A'];
  const timingB = timings?.['B'];
  const timingC = timings?.['C'];
  const timingD = timings?.['D'];

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Empirical Evaluation Benchmarks
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Recomputed directly from raw trial runs in <code>demo/data/evaluation_v3/results/</code>.
          </p>
        </div>
        <Badge variant="cyan" size="md">
          {summary.evaluation_label || '—'}
        </Badge>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Harm Prevention */}
        <div className="p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                Harm Injected Trials
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Number of trials where prompt injection successfully leaked decoy or sink canary.
              </p>
            </div>
            <span className="font-mono text-xs text-slate-400">
              {harmA?.total !== undefined ? `N=${harmA.total} per condition` : '—'}
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={harmData} margin={{ top: 20, right: 20, left: -20, bottom: 20 }}>
                <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={0} stroke="#94a3b8" />
                <YAxis domain={[0, harmA?.total || 32]} stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc', fontSize: '12px' }}
                />
                <Bar dataKey="harm" radius={[6, 6, 0, 0]}>
                  {harmData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-100 dark:border-slate-800 text-xs font-mono text-slate-600 dark:text-slate-300">
            Harm: A "No governance" = {formatRatio(harmA)} | B "Tool layer only" = {formatRatio(harmB)} | C "Tool + OS layer" = {formatRatio(harmC)} | D "Per-task container" = {formatRatio(harmD)}
          </div>
        </div>

        {/* Chart 2: Shell Attacks Succeeded */}
        <div className="p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                Shell Channel Attack Outcomes
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Shell channel attack outcomes in B "Tool layer only" vs C "Tool + OS layer".
              </p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={shellAttackData} margin={{ top: 20, right: 20, left: -20, bottom: 20 }}>
                <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={0} stroke="#94a3b8" />
                <YAxis domain={[0, shellC?.total || 10]} stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc', fontSize: '12px' }}
                />
                <Bar dataKey="succeeded" radius={[6, 6, 0, 0]}>
                  {shellAttackData.map((entry, index) => (
                    <Cell key={`cell-shell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-100 dark:border-slate-800 text-xs font-mono text-slate-600 dark:text-slate-300">
            B "Tool layer only": {formatRatio(shellB)} succeeded | C "Tool + OS layer": {formatRatio(shellC)} succeeded
          </div>
        </div>
      </div>

      {/* Expansion Chain Progression */}
      <div className="p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
          Expansion Chain Progression (Unanticipated, C "Tool + OS layer")
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {stepsList.map((st, i) => (
            <div key={i} className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200/80 dark:border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block">{st.label}</span>
              <div className="text-2xl font-bold font-mono text-cyan-600 dark:text-cyan-400 mt-1">
                {st.value}
              </div>
              <p className="text-xs text-slate-500 mt-1">{st.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Latency and Timeouts */}
      <div className="p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
          Trial Durations & Timeouts
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          {[
            { name: 'A "No governance"', timing: timingA },
            { name: 'B "Tool layer only"', timing: timingB },
            { name: 'C "Tool + OS layer"', timing: timingC },
            { name: 'D "Per-task container"', timing: timingD },
          ].map((item, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200/80 dark:border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block">{item.name}</span>
              <div className="text-2xl font-bold font-mono text-slate-800 dark:text-slate-100 mt-1">
                {item.timing?.mean_s !== undefined ? `${item.timing.mean_s}s` : '—'}
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Timeouts: {item.timing?.timeout_ratio || (item.timing?.timeouts !== undefined && item.timing?.total_trials !== undefined ? `${item.timing.timeouts}/${item.timing.total_trials}` : '—')}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Limitations List */}
      <div className="p-6 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-3">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900 dark:text-white">
          Evaluation Scope & Limitations
        </h2>
        <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-400 leading-relaxed list-disc list-inside">
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
