import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { ResultsSummary } from '../types';
import { MetricCard } from '../components/ui/MetricCard';
import { buttonClasses } from '../components/ui/Button';

const STEPS = [
  { title: '1. You ask', body: '“Summarise sales_data.csv”' },
  { title: '2. We fence it in', body: 'It can open that file, nothing else.' },
  { title: '3. You decide extras', body: 'Anything more needs your OK.' },
];

export const HomePage: React.FC = () => {
  const [summary, setSummary] = useState<ResultsSummary | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    api
      .getResultsSummary()
      .then(setSummary)
      .catch(() => setFailed(true));
  }, []);

  // Injected runs with harm: no governance (A) vs tool + OS layer (C).
  const harmA = summary?.harm_injected?.A;
  const harmC = summary?.harm_injected?.C;
  const ut = summary?.utility_timings_anticipated;
  const extra = ut?.extra_s_c_vs_a;

  return (
    <div className="max-w-[1080px] mx-auto pt-6 sm:pt-12 pb-12 flex flex-col items-center gap-10 sm:gap-12 text-center font-sans">
      <div className="flex flex-col items-center gap-5">
        <h1 className="m-0 font-display font-bold text-[34px] sm:text-[52px] leading-[1.08] max-w-[860px] text-fg">
          AI agents should only touch{' '}
          <span className="text-info">what you asked for.</span>
        </h1>
        <p className="m-0 text-[17px] sm:text-[18px] max-w-[620px] text-fg-2">
          We put a fence around the agent for each request. If it needs something more, it has to ask you.
        </p>
        <Link id="try-it" to="/run" className={buttonClasses('primary', 'lg', 'min-h-[44px] px-7 text-[15px]')}>
          Try it
        </Link>
      </div>

      <div className="relative w-full" aria-label="How it works">
        <ol className="relative grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4 list-none p-0 m-0">
          {STEPS.map(s => (
            <li key={s.title} className="p-5 rounded-xl border border-line bg-surface-1 text-left">
              <div className="text-[17px] font-semibold text-fg">{s.title}</div>
              <div className="mt-1.5 text-[15px] text-fg-2">{s.body}</div>
            </li>
          ))}
        </ol>
      </div>

      <div className="w-full flex flex-col items-center gap-3">
        <div className="w-full grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4 max-w-[640px]">
          <MetricCard
            id="metric-harm"
            label="Tricked agents that caused harm"
            value={
              harmA && harmC ? (
                <span>
                  <span className="text-bad">{harmA.exposed}</span> <span className="text-fg-3">→</span>{' '}
                  <span className="text-ok">{harmC.exposed}</span>
                </span>
              ) : (
                '—'
              )
            }
            note={harmA ? `out of ${harmA.total} attack trials` : undefined}
            tone="default"
          />
          <MetricCard
            id="metric-time"
            label="Extra per everyday task"
            value={extra !== undefined ? `+${extra.toFixed(1)} s` : '—'}
            note={ut?.A && ut?.C ? `${ut.A.mean_s} s → ${ut.C.mean_s} s` : undefined}
            tone="default"
          />
        </div>
        <p className="m-0 text-[14px] text-fg-3">
          {failed ? 'The results file could not be loaded. ' : ''}In our tests with local AI models.{' '}
          <Link id="see-results" to="/results" className="inline-flex items-center text-info hover:underline min-h-[44px]">
            See the full results
          </Link>
        </p>
      </div>
    </div>
  );
};
