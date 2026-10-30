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
    <div className="relative" style={{ overflow: 'clip', minHeight: 'calc(100vh - 88px)' }}>
      <div
        aria-hidden="true"
        className="absolute rounded-full pointer-events-none"
        style={{ width: 760, height: 760, left: '30%', top: -420, background: 'radial-gradient(circle, rgba(34,211,238,0.25), rgba(167,139,250,0.12) 45%, transparent 70%)', animation: 'drift 18s ease-in-out infinite' }}
      />
      <div className="relative max-w-[1080px] mx-auto px-4 sm:px-6 pt-12 sm:pt-[72px] pb-16 flex flex-col items-center gap-12 sm:gap-14 text-center">
        <div className="flex flex-col items-center gap-5">
          <h1 className="m-0 font-display font-bold text-[40px] sm:text-[60px] leading-[1.05] tracking-[-1.5px] max-w-[900px]">
            AI agents should only touch{' '}
            <span style={{ background: 'linear-gradient(90deg, #67E8F9, #C4B5FD)', WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent' }}>
              what you asked for.
            </span>
          </h1>
          <p className="m-0 text-[19px] max-w-[620px]" style={{ color: 'var(--text-2)' }}>
            We put a fence around the agent for each request. If it needs something more, it has to ask you.
          </p>
          <Link id="try-it" to="/run" className="btn-primary" style={{ minHeight: 52, padding: '0 30px', boxShadow: '0 12px 40px rgba(34,211,238,0.3)' }}>
            Try it
          </Link>
        </div>

        <div className="relative w-full" aria-label="How it works">
          <div aria-hidden="true" className="hidden sm:block absolute overflow-hidden" style={{ left: '8%', right: '8%', top: '50%', height: 2, background: 'rgba(148,163,184,0.18)' }}>
            <span className="absolute top-0" style={{ width: '20%', height: 2, background: 'linear-gradient(90deg, transparent, #22D3EE, transparent)', animation: 'flow 6s linear infinite' }} />
          </div>
          <ol className="relative grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6 list-none p-0 m-0">
            {STEPS.map((s, i) => (
              <li key={s.title} className="card px-[22px] py-7" style={{ animation: `lit 6s ease-in-out ${i * 2}s infinite` }}>
                <div className="font-display text-[22px] font-bold">{s.title}</div>
                <div className="mt-2 text-[15px]" style={{ color: 'var(--text-2)' }}>
                  {s.body}
                </div>
              </li>
            ))}
          </ol>
        </div>

        <div className="flex flex-col items-center gap-3">
          <div className="w-full flex flex-col sm:flex-row sm:flex-wrap justify-center gap-4 sm:gap-6">
            <div className="card sm:min-w-[260px] px-7 py-6" id="metric-harm">
              <div className="font-display text-[40px] font-bold">
                {harmA && harmC ? (
                  <>
                    <span style={{ color: '#FDA4AF' }}>{harmA.exposed}</span> → <span style={{ color: '#6EE7B7' }}>{harmC.exposed}</span>
                  </>
                ) : (
                  '—'
                )}
              </div>
              <div className="mt-1.5 text-[15px]" style={{ color: 'var(--text-2)' }}>
                tricked agents that caused harm{harmA ? `, out of ${harmA.total}` : ''}
              </div>
            </div>
            <div className="card sm:min-w-[260px] px-7 py-6" id="metric-time">
              <div className="font-display text-[40px] font-bold" style={{ color: '#67E8F9' }}>
                {extra !== undefined ? `+${extra.toFixed(1)} s` : '—'}
              </div>
              <div className="mt-1.5 text-[15px]" style={{ color: 'var(--text-2)' }}>
                {ut?.A && ut?.C ? `extra per everyday task (${ut.A.mean_s} s → ${ut.C.mean_s} s)` : 'extra per everyday task'}
              </div>
            </div>
          </div>
          <p className="m-0 text-[14px]" style={{ color: 'var(--text-3)' }}>
            {failed ? 'The results file could not be loaded. ' : ''}In our tests with local AI models.{' '}
            <Link id="see-results" to="/results">
              See the full results
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};
