import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { ResultsSummary } from '../types';

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
    <div className="max-w-[1080px] mx-auto pt-6 sm:pt-12 pb-12 flex flex-col items-center gap-10 sm:gap-12 text-center">
      <div className="flex flex-col items-center gap-5">
        <h1 className="m-0 font-display font-bold text-[34px] sm:text-[52px] leading-[1.08] max-w-[860px] text-[#E6E9EF]">
          AI agents should only touch{' '}
          <span className="text-[#60A5FA]">what you asked for.</span>
        </h1>
        <p className="m-0 text-[17px] sm:text-[18px] max-w-[620px] text-[#A7B0C0]">
          We put a fence around the agent for each request. If it needs something more, it has to ask you.
        </p>
        <Link id="try-it" to="/run" className="btn-primary" style={{ minHeight: 44, padding: '0 28px', fontSize: 15 }}>
          Try it
        </Link>
      </div>

      <div className="relative w-full" aria-label="How it works">
        <ol className="relative grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4 list-none p-0 m-0">
          {STEPS.map(s => (
            <li key={s.title} className="card px-5 py-5 text-left">
              <div className="text-[17px] font-semibold text-[#E6E9EF]">{s.title}</div>
              <div className="mt-1.5 text-[15px] text-[#A7B0C0]">{s.body}</div>
            </li>
          ))}
        </ol>
      </div>

      <div className="w-full flex flex-col items-center gap-3">
        <div className="w-full grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4 max-w-[640px]">
          <div className="card px-5 py-5 text-left" id="metric-harm">
            <div className="text-[34px] font-bold tracking-tight leading-tight">
              {harmA && harmC ? (
                <>
                  <span className="text-[#F87171]">{harmA.exposed}</span> <span className="text-[#8B95A7]">→</span>{' '}
                  <span className="text-[#4ADE80]">{harmC.exposed}</span>
                </>
              ) : (
                '—'
              )}
            </div>
            <div className="mt-1 text-[14px] text-[#A7B0C0]">
              tricked agents that caused harm{harmA ? `, out of ${harmA.total}` : ''}
            </div>
          </div>
          <div className="card px-5 py-5 text-left" id="metric-time">
            <div className="text-[34px] font-bold tracking-tight leading-tight text-[#60A5FA]">
              {extra !== undefined ? `+${extra.toFixed(1)} s` : '—'}
            </div>
            <div className="mt-1 text-[14px] text-[#A7B0C0]">
              {ut?.A && ut?.C ? `extra per everyday task (${ut.A.mean_s} s → ${ut.C.mean_s} s)` : 'extra per everyday task'}
            </div>
          </div>
        </div>
        <p className="m-0 text-[14px] text-[#8B95A7]">
          {failed ? 'The results file could not be loaded. ' : ''}In our tests with local AI models.{' '}
          <Link id="see-results" to="/results" className="inline-flex items-center min-h-[44px]">
            See the full results
          </Link>
        </p>
      </div>
    </div>
  );
};
