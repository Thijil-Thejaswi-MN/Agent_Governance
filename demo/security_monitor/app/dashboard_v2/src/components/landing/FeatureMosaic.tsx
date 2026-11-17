import React, { useEffect, useRef, useState } from 'react';
import { FileText, Pencil, Globe, Bot, Terminal, Hand } from 'lucide-react';
import './FeatureMosaic.css';
import type { HarmBar } from '../../logic/landingResults';

// "What it does" on the sign-in page, after the "Task Engine" mosaic on motionsites.
// Same five-card layout and entrance; our own content. Nothing here is a live number:
// the chart is our evaluation (Review 2), labelled as such, and the toast and windows are
// pictures of the product, not data.

const VERIFY_CMD = 'python scripts/verify_receipt.py receipts/<task_id>.json';

const MAX = 32;

const Check: React.FC = () => (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M5 12.5l4.2 4.2L19 7" stroke="#161616" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const Sparkles: React.FC = () => (
  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M7 3.5l1.3 3.2 3.2 1.3-3.2 1.3L7 12.5 5.7 9.3 2.5 8l3.2-1.3z" fill="#eff4e6" stroke="#4f7433" strokeWidth="2.2" strokeLinejoin="round" />
    <path d="M15.5 9l1.9 4.6 4.6 1.9-4.6 1.9-1.9 4.6-1.9-4.6-4.6-1.9 4.6-1.9z" fill="#eff4e6" stroke="#4f7433" strokeWidth="2.25" strokeLinejoin="round" />
  </svg>
);

export const FeatureMosaic: React.FC<{ harm?: HarmBar[] | null }> = ({ harm }) => {
  const ref = useRef<HTMLDivElement | null>(null);
  const [inView, setInView] = useState<boolean | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const el = ref.current;
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (!el || reduce || typeof IntersectionObserver === 'undefined') return;
    setInView(false);
    const obs = new IntersectionObserver(
      entries => {
        if (entries.some(e => e.isIntersecting)) {
          setInView(true);
          obs.disconnect();
        }
      },
      { threshold: 0.2 },
    );
    obs.observe(el);
    // Fail-safe: never leave the cards hidden.
    const t = window.setTimeout(() => setInView(v => (v === false ? true : v)), 6000);
    return () => {
      obs.disconnect();
      window.clearTimeout(t);
    };
  }, []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(VERIFY_CMD);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div ref={ref} className="fm" id="features" data-in={inView == null ? undefined : String(inView)}>
      <div className="fm-stage" role="region" aria-label="What Agent Governance does">
        {/* 1. A request for more access */}
        <section className="fm-card fm-notif" aria-label="An access request">
          <div className="fm-toast-wrap">
            <div className="fm-toast-ledge" />
            <div className="fm-toast">
              <span className="fm-toast-icon" aria-hidden="true">
                <Hand />
              </span>
              <div className="fm-toast-text">
                <div className="fm-toast-title">An agent asks for more</div>
                <div className="fm-toast-sub">
                  <code>finance_bot</code> wants <code>input/targets.csv</code>. You decide.
                </div>
              </div>
              <span className="fm-toast-time">example</span>
            </div>
          </div>
        </section>

        {/* 2. The governed tools */}
        <section className="fm-card fm-connect" aria-label="Governed tools">
          <h2 className="fm-h2">
            Every tool call,
            <br />
            checked.
          </h2>
          <p className="fm-sub">Six governed tools, one boundary</p>
          <div className="fm-chips">
            <div className="fm-chip-row r1">
              <span className="fm-chip">read_file <FileText /></span>
            </div>
            <div className="fm-chip-row r2">
              <span className="fm-chip">write_file <Pencil /></span>
              <span className="fm-chip">http_get <Globe /></span>
            </div>
            <div className="fm-chip-row r3">
              <span className="fm-chip">call_agent <Bot /></span>
              <span className="fm-chip">run_command <Terminal /></span>
            </div>
          </div>
          <span className="fm-chip fm-chip-float">request_access <Hand /></span>
        </section>

        {/* 3. The idea */}
        <section className="fm-card fm-automate" aria-label="Govern your agents">
          <div className="fm-copy">
            <h2 className="fm-h2">
              <span className="fm-g">Govern</span> your agents.
              <br />
              Touch only what matters.
            </h2>
            <p className="fm-sub">One boundary, enforced by the tool broker and the Linux kernel.</p>
          </div>
          <div className="fm-illo" aria-hidden="true">
            <div className="fm-win fm-win-back">
              <div className="fm-win-bar">
                <i />
                <i />
                <i />
              </div>
              <div className="fm-win-body">
                <div className="fm-win-strip" />
              </div>
            </div>
            <div className="fm-win fm-win-front">
              <div className="fm-win-bar">
                <i />
                <i />
                <i />
              </div>
              <div className="fm-win-body">
                <div className="fm-win-strip" />
                <div className="fm-win-lines">
                  <span className="fm-line"><b className="ok">read</b> input/sales.csv</span>
                  <span className="fm-line"><b className="ok">write</b> output/summary.txt</span>
                  <span className="fm-line"><b className="no">blocked</b> ~/.ssh/id_rsa</span>
                </div>
              </div>
            </div>
            <div className="fm-pill fm-pill-wf">
              <span className="fm-tick">
                <Check />
              </span>
              Boundary enforced
            </div>
            <div className="fm-pill fm-pill-ai">
              <Sparkles />
              <span className="fm-skel">
                <i />
                <i />
              </span>
            </div>
            <svg className="fm-cursor" viewBox="0 0 24 28">
              <path d="M3 2.5v19.2l5.1-4.6 3.4 7.6 3.3-1.5-3.3-7.4 6.9-.4z" fill="#fff" stroke="#2b2b2b" strokeWidth="1.3" strokeLinejoin="round" />
            </svg>
          </div>
        </section>

        {/* 4. What it changed, in our evaluation */}
        <section className="fm-card fm-insights" aria-label="Evaluation result">
          <span className="fm-tag">Evaluation results</span>
          {harm && harm.length ? (
            <>
              <h2 className="fm-h2">
                {harm[0].harm} → {harm.find(h => h.ours)?.harm ?? 0}
              </h2>
              <p className="fm-sub">injected tasks that caused harm, of {MAX}</p>
              <div
                className="fm-chart"
                role="img"
                aria-label={`Injected tasks that caused harm, of ${MAX}: ${harm.map(h => `${h.label} ${h.harm}`).join(', ')}`}
              >
                {harm.map(h => (
                  <div className="fm-col" key={h.key} data-setup={h.key}>
                    <div
                      className={`fm-bar${h.ours ? ' ours' : ''}`}
                      style={{ height: `calc(${h.harm ? Math.round((h.harm / Math.max(1, ...harm.map(x => x.harm))) * 240) : 36} * var(--u))` }}
                      title={h.attempted != null ? `${h.label}: the agent tried in ${h.attempted} of ${MAX}` : h.label}
                    >
                      {h.harm}
                    </div>
                    <div className={`fm-day${h.ours ? ' ours' : ''}`}>{h.key}</div>
                  </div>
                ))}
              </div>
              <p className="fm-note">
                qwen2.5:7b, {MAX} injected tasks per setup, one machine; the agent tried the attack in{' '}
                {harm.map(h => h.attempted).filter(a => a != null).join(', ')} of them
              </p>
            </>
          ) : (
            <p className="fm-sub">The evaluation results are not available on this install.</p>
          )}
        </section>

        {/* 5. Check a record */}
        <section className="fm-card fm-search" aria-label="Check a record">
          <h2 className="fm-h2">
            Check any record
            <br />
            yourself
          </h2>
          <div className="fm-bar-search">
            <span className="fm-mag" aria-hidden="true">
              <Terminal />
            </span>
            <code className="fm-cmd" title={VERIFY_CMD}>
              {VERIFY_CMD}
            </code>
            <button type="button" className="fm-copybtn" onClick={copy} aria-live="polite">
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </section>
      </div>
    </div>
  );
};
