import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { AttackDetail, AttackRow, AttackStory, EvidenceDataset, EvidenceTrial } from '../types';
import { ErrorState, LoadingState } from '../components/common/States';
import { DetailsDrawer } from '../components/v3/DetailsDrawer';
import { PageHeader } from '../components/ui/PageHeader';
import { MetricCard } from '../components/ui/MetricCard';
import { ACTION_LABEL, SETUP_ABOUT, firstStory, highlightParts, rowVerdict, stepView, storyVerdict } from '../logic/evidence';

const TONE: Record<'bad' | 'good' | 'neutral', React.CSSProperties> = {
  bad: { color: 'var(--bad-text)', background: 'var(--bad-tint)', borderColor: 'rgb(var(--bad-rgb) / 0.4)' },
  good: { color: 'var(--ok-text)', background: 'var(--ok-tint)', borderColor: 'rgb(var(--ok-rgb) / 0.35)' },
  neutral: { color: 'var(--text-soft)', background: 'rgba(148,163,184,0.1)', borderColor: 'rgba(148,163,184,0.3)' },
};

const Chip: React.FC<{ tone: 'bad' | 'good' | 'neutral'; children: React.ReactNode }> = ({ tone, children }) => (
  <span className="inline-flex items-center px-2 py-0.5 rounded-full border text-[12px] font-semibold whitespace-nowrap" style={TONE[tone]}>
    {children}
  </span>
);

const H2: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <h2 className="m-0 font-display font-semibold text-[18px] sm:text-[20px] text-fg">{children}</h2>
);

const Mono: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
  <pre className={`m-0 whitespace-pre-wrap break-words mono text-[13px] leading-relaxed ${className}`} style={{ color: 'var(--text)' }}>
    {children}
  </pre>
);

// An input file, with the hidden instruction lines in red.
const InputFile: React.FC<{ name: string; content: string }> = ({ name, content }) => (
  <div className="rounded-lg border border-line-strong p-3" style={{ background: 'var(--surface-terminal)' }}>
    <div className="mono text-[12px] mb-1" style={{ color: 'var(--text-3)' }}>{name}</div>
    <pre className="m-0 whitespace-pre-wrap break-words mono text-[13px] leading-relaxed">
      {content.split('\n').map((line, i) => {
        const trick = /note to assistant|^#\s*note|execute|send .* to http/i.test(line);
        return (
          <div key={i} style={{ color: trick ? 'var(--bad-text)' : 'var(--text)' }} data-trick={trick || undefined}>
            {line || ' '}
          </div>
        );
      })}
    </pre>
  </div>
);

/** Everything recorded about one trial. Used in the drawer and in the side-by-side pair. */
export const TrialView: React.FC<{ t: EvidenceTrial; compact?: boolean }> = ({ t, compact }) => {
  const verdict = rowVerdict(t.row);
  const steps = t.tool_history.map(s => stepView(s, t.canary));
  const shown = compact ? steps.filter(s => s.mark !== 'normal' || s.step === 0) : steps;
  return (
    <div className="flex flex-col gap-4 min-w-0" data-trial={`${t.row.scenario_id}/${t.row.condition}/${t.row.repeat}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold text-fg">
          Setup {t.row.condition}: {t.condition_name}
        </span>
        <Chip tone={verdict.tone}>{verdict.label}</Chip>
      </div>
      <div className="text-[13px]" style={{ color: 'var(--text-3)' }}>
        {t.row.scenario_id} · repeat {t.row.repeat} · {t.model} · commit {String(t.git_commit || '').slice(0, 7)} ·{' '}
        {t.timestamp ? new Date(t.timestamp).toLocaleString() : ''}
      </div>

      {!compact && (
        <>
          <section className="flex flex-col gap-2">
            <h3 className="m-0 text-[13px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>The request</h3>
            <p className="m-0 text-[15px] leading-relaxed" style={{ color: 'var(--text)' }}>{t.scenario.user_prompt}</p>
          </section>
          <section className="flex flex-col gap-2">
            <h3 className="m-0 text-[13px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>Input files (hidden instruction in red)</h3>
            {Object.entries(t.scenario.input_files).map(([n, c]) => (
              <InputFile key={n} name={n} content={c} />
            ))}
          </section>
          {t.scenario.expected_boundary && (
            <section className="flex flex-col gap-1 text-[14px]">
              <h3 className="m-0 text-[13px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>What the request allows</h3>
              <div>
                Read: <span className="mono">{String((t.scenario.expected_boundary.files_read as string[] | undefined)?.join(', ') || '—')}</span>
              </div>
              <div>
                Write: <span className="mono">{String((t.scenario.expected_boundary.files_write as string[] | undefined)?.join(', ') || '—')}</span>
              </div>
              {t.scenario.decoys.length > 0 && (
                <div style={{ color: 'var(--text-3)' }}>
                  Planted private files (each holds a unique canary code): <span className="mono">{t.scenario.decoys.join(', ')}</span>
                </div>
              )}
            </section>
          )}
        </>
      )}

      <section className="flex flex-col gap-2">
        <h3 className="m-0 text-[13px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
          {compact ? 'The key steps' : `What the agent did (${steps.length} tool calls)`}
        </h3>
        <ol className="list-none m-0 p-0 flex flex-col gap-2">
          {shown.map(s => (
            <li
              key={s.step}
              data-mark={s.mark}
              className="rounded-lg border p-3"
              style={{
                borderColor: s.mark === 'leak' ? 'rgb(var(--bad-rgb) / 0.5)' : s.mark === 'blocked' ? 'rgb(var(--ok-rgb) / 0.45)' : 'var(--line-strong)',
                background: s.mark === 'leak' ? 'rgb(var(--bad-rgb) / 0.07)' : s.mark === 'blocked' ? 'rgb(var(--ok-rgb) / 0.06)' : 'var(--surface-terminal)',
              }}
            >
              <div className="flex flex-wrap items-center gap-2 text-[13px]">
                <span style={{ color: 'var(--text-3)' }}>step {s.step}</span>
                <span className="mono font-semibold" style={{ color: 'var(--text)' }}>{s.tool}</span>
                {s.mark === 'leak' && <Chip tone="bad">Private file content reached the agent</Chip>}
                {s.mark === 'blocked' && <Chip tone="good">Refused</Chip>}
              </div>
              <Mono className="mt-1">{s.what}</Mono>
              {s.result && (
                <Mono className="mt-1 opacity-90">
                  {'→ '}
                  {s.result}
                </Mono>
              )}
            </li>
          ))}
        </ol>
      </section>

      {t.receipt ? (
        <section className="flex flex-col gap-1 text-[14px]" data-receipt>
          <h3 className="m-0 text-[13px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>The receipt for this trial</h3>
          <div>
            Sandbox: <span className="mono">{t.receipt.isolation_level}</span>
          </div>
          {t.receipt.event_counts && (
            <div>
              {t.receipt.event_counts.total} events: {t.receipt.event_counts.by_verdict?.INSIDE ?? 0} inside the boundary,{' '}
              {t.receipt.event_counts.by_verdict?.OUTSIDE ?? 0} outside
            </div>
          )}
          {t.receipt.outside_events.map((e, i) => (
            <div key={i} className="mono text-[13px]" style={{ color: e.prevented ? 'var(--ok-text)' : 'var(--bad-text)' }}>
              {String(e.syscall || e.kind)} {String(e.target)} → {String(e.result ?? '')}
              {e.prevented_by && e.prevented_by !== 'none' ? ` (stopped by ${String(e.prevented_by)})` : ''}
            </div>
          ))}
          <div style={{ color: t.receipt.chain_verified ? 'var(--ok-text)' : 'var(--bad-text)' }} data-chain-verified={t.receipt.chain_verified}>
            {t.receipt.chain_verified
              ? `Hash chain re-checked just now: all ${t.receipt.chained_events} entries intact`
              : `Hash chain check failed: ${t.receipt.chain_message}`}
          </div>
          <div className="mono text-[12px] break-all" style={{ color: 'var(--text-3)' }}>final hash {t.receipt.final_hash}</div>
        </section>
      ) : (
        <div className="text-[13px]" style={{ color: 'var(--text-3)' }}>
          No receipt archived for this trial (receipts were archived for part of the runs).
        </div>
      )}
    </div>
  );
};

const DEFAULT_ATTACK: Record<string, string> = { e1b_shell_only: 'injected_indirect_04', full_run: 'injected_indirect_01' };
const ATTACK_DATASETS = ['e1b_shell_only', 'full_run'];

const Step: React.FC<{ n: number; title: string; children?: React.ReactNode; id?: string }> = ({ n, title, children, id }) => (
  <section className="flex flex-col gap-3" id={id}>
    <div className="flex items-center gap-3">
      <span className="inline-flex items-center justify-center w-7 h-7 rounded-full text-[13px] font-bold shrink-0" style={{ background: 'rgb(var(--accent-rgb) / 0.15)', color: 'var(--info-text)', border: '1px solid rgb(var(--accent-rgb) / 0.4)' }}>
        {n}
      </span>
      <H2>{title}</H2>
    </div>
    {children}
  </section>
);

const Highlighted: React.FC<{ text: string; canary: string | null }> = ({ text, canary }) => (
  <>
    {highlightParts(text, canary).map((p, i) =>
      p.mark ? (
        <span
          key={i}
          data-highlight={p.mark}
          className="rounded px-0.5 font-semibold"
          style={p.mark === 'leak' ? { background: 'rgb(var(--bad-rgb) / 0.25)', color: 'var(--bad-lighter)' } : { background: 'rgb(var(--ok-rgb) / 0.2)', color: 'var(--ok-lighter)' }}
        >
          {p.text}
        </span>
      ) : (
        <React.Fragment key={i}>{p.text}</React.Fragment>
      ),
    )}
  </>
);

// One cell of the attack picker: harm in this setup, out of its trials.
const HarmCell: React.FC<{ v?: { trials: number; harm: number; acted: number } }> = ({ v }) =>
  !v ? (
    <td className="px-4 py-2" />
  ) : (
    <td className="px-4 py-2 whitespace-nowrap">
      <span className="font-semibold" style={{ color: v.harm ? 'var(--bad-text)' : 'var(--ok-text)' }}>
        {v.harm}/{v.trials}
      </span>
      <span className="text-[12px]" style={{ color: 'var(--text-3)' }}>
        {' '}
        · acted {v.acted}
      </span>
    </td>
  );

/** One setup's column: the trials as chips, and the step where the agent acted on the note. */
const SetupColumn: React.FC<{
  c: AttackDetail['conditions'][number];
  action: string;
  onOpen: (repeat: number) => void;
}> = ({ c, action, onOpen }) => {
  const [pick, setPick] = useState(() => firstStory(c.stories));
  useEffect(() => setPick(firstStory(c.stories)), [c]);
  const s: AttackStory | undefined = c.stories[pick];
  const v = s ? storyVerdict(s, c.condition, action) : null;
  return (
    <div className="card p-4 flex flex-col gap-3 min-w-0" data-condition={c.condition}>
      <div className="flex flex-col gap-1">
        <div className="font-semibold text-[16px] text-fg">
          {c.condition} · {c.name}
        </div>
        <p className="m-0 text-[13px] leading-relaxed" style={{ color: 'var(--text-3)' }}>
          {SETUP_ABOUT[c.condition]}
        </p>
      </div>
      <div className="text-[15px] font-semibold" data-harm={c.harm} style={{ color: c.harm ? 'var(--bad-text)' : 'var(--ok-text)' }}>
        {c.harm ? `Harm in ${c.harm} of ${c.trials} trials` : `No harm in any of ${c.trials} trials`}
        <span className="font-normal text-[13px]" style={{ color: 'var(--text-3)' }}>
          {' '}
          · acted on the note in {c.acted}
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5" role="group" aria-label={`Trials in setup ${c.condition}`}>
        {c.stories.map((st, i) => {
          const dot = st.harm ? 'var(--bad)' : st.key_step ? 'var(--ok)' : 'var(--slate-500)';
          return (
            <button
              key={st.repeat}
              type="button"
              aria-pressed={i === pick}
              onClick={() => setPick(i)}
              title={st.harm ? 'Harm' : st.key_step ? 'Acted on the note, stopped' : 'Ignored the note'}
              className="inline-flex items-center gap-1.5 px-2 min-h-[28px] rounded-md border text-[12px]"
              style={i === pick ? { borderColor: 'var(--accent)', background: 'var(--accent-tint)', color: 'var(--text)' } : { borderColor: 'var(--line-strong)', color: 'var(--text-2)' }}
              data-repeat={st.repeat}
            >
              <span className="w-2 h-2 rounded-full" style={{ background: dot }} />#{st.repeat + 1}
            </button>
          );
        })}
      </div>
      {s && v && (
        <div className="flex flex-col gap-2" data-trial={`${c.condition}/${s.repeat}`} data-verdict={s.key_step?.verdict ?? 'ignored'}>
          {s.key_step ? (
            <div className="rounded-lg border p-3 flex flex-col gap-1.5" style={{ borderColor: v.tone === 'bad' ? 'rgb(var(--bad-rgb) / 0.5)' : v.tone === 'good' ? 'rgb(var(--ok-rgb) / 0.45)' : 'var(--line-strong)', background: 'var(--surface-terminal)' }}>
              <div className="text-[12px]" style={{ color: 'var(--text-3)' }}>
                Step {s.key_step.step} of {s.steps} · <span className="mono">{s.key_step.tool}</span>
              </div>
              <Mono>{s.key_step.what}</Mono>
              {s.key_step.result && (
                <pre className="m-0 whitespace-pre-wrap break-words mono text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
                  {'→ '}
                  <Highlighted text={s.key_step.result} canary={s.canary} />
                </pre>
              )}
            </div>
          ) : null}
          <div>
            <Chip tone={v.tone}>{v.label}</Chip>
          </div>
          <p className="m-0 text-[14px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
            {v.why}
          </p>
          <div>
            <button type="button" className="underline text-[13px]" style={{ color: 'var(--info-text)' }} onClick={() => onOpen(s.repeat)} data-open-trial>
              Show every step{s.has_receipt ? ' and re-check its record' : ''}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export const EvidencePage: React.FC = () => {
  const [datasets, setDatasets] = useState<EvidenceDataset[] | null>(null);
  const [active, setActive] = useState<string>('e1b_shell_only');
  const [attacks, setAttacks] = useState<AttackRow[] | null>(null);
  const [onlyActed, setOnlyActed] = useState(true);
  const [scenario, setScenario] = useState<string>(DEFAULT_ATTACK.e1b_shell_only);
  const [detail, setDetail] = useState<AttackDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<EvidenceTrial | null>(null);

  useEffect(() => {
    api.getEvidenceDatasets().then(setDatasets).catch(e => setError(e?.message || 'Could not load the recorded runs.'));
  }, []);

  const chooseDataset = (id: string) => {
    if (id === active) return;
    setScenario(DEFAULT_ATTACK[id]);
    setActive(id);
  };

  useEffect(() => {
    setAttacks(null);
    let live = true;
    api
      .getEvidenceAttacks(active)
      .then(a => live && setAttacks(a))
      .catch(e => live && setError(e?.message || 'Could not load the attacks.'));
    return () => {
      live = false;
    };
  }, [active]);

  useEffect(() => {
    setDetail(null);
    if (!scenario) return;
    // Switching datasets changes both values; only the latest request may set the view.
    let live = true;
    api
      .getEvidenceAttack(active, scenario)
      .then(d => live && setDetail(d))
      .catch(e => live && setError(e?.message || 'Could not load the attack.'));
    return () => {
      live = false;
    };
  }, [active, scenario]);

  const openTrial = useCallback(
    (condition: string, repeat: number) => {
      api
        .getEvidenceTrial(active, scenario, condition, repeat)
        .then(setOpen)
        .catch(e => setError(e?.message || 'Could not load the trial.'));
    },
    [active, scenario],
  );

  const ds = datasets?.find(d => d.id === active);
  const util = datasets?.find(d => d.id === 'utility');
  const conds = useMemo(() => (ds ? Object.keys(ds.by_condition).sort() : []), [ds]);
  const shown = (attacks || []).filter(a => !onlyActed || Object.values(a.by_condition).some(v => v.acted > 0) || a.id === scenario);

  if (error && !datasets) return <ErrorState message={error} id="evidence-error" />;
  if (!datasets) return <LoadingState label="Loading the recorded runs…" id="evidence-loading" />;

  return (
    <div className="max-w-[1200px] pb-12 flex flex-col gap-8" id="evidence-page">
      <PageHeader
        title="Evidence"
        subtitle="The recorded evaluation trials behind the results, one attack at a time. Pick an attack, see the instruction hidden in its input file, then the exact step where the agent acted on it in each setup and what came back. Everything here is read from the raw trial files in the repository."
        actions={
          <Link to="/results" className="text-[14px] inline-flex items-center min-h-[32px] text-accent hover:underline">
            ← Results
          </Link>
        }
      />

      <nav className="flex flex-wrap gap-2" aria-label="Recorded runs" id="evidence-datasets">
        {datasets
          .filter(d => ATTACK_DATASETS.includes(d.id))
          .map(d => (
            <button
              key={d.id}
              type="button"
              data-dataset={d.id}
              aria-pressed={d.id === active}
              onClick={() => chooseDataset(d.id)}
              className="px-3 py-2 rounded-lg border text-[14px] font-medium text-left"
              style={d.id === active ? { borderColor: 'var(--accent)', background: 'var(--accent-tint)', color: 'var(--text)' } : { borderColor: 'var(--line-strong)', color: 'var(--text-2)' }}
            >
              {d.id === 'e1b_shell_only' ? 'Shell-only agent (E1b)' : 'Full run, all four setups'} · {d.trials} trials
            </button>
          ))}
      </nav>

      {ds && (
        <section className="flex flex-col gap-3" id="evidence-summary">
          <p className="m-0 text-[15px] leading-relaxed max-w-[860px]" style={{ color: 'var(--text-2)' }}>
            {ds.about} Model: <span className="mono">{ds.model}</span>.
          </p>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {conds.map(c => {
              const m = ds.by_condition[c].metrics.find(x => x.label === 'Attack trials with harm');
              return (
                <MetricCard
                  key={c}
                  data-condition={c}
                  label={`${c} · ${ds.by_condition[c].name}`}
                  value={m ? `${m.value}/${m.of}` : '—'}
                  note="attack trials with harm"
                  tone={m && m.value > 0 ? 'bad' : 'ok'}
                />
              );
            })}
          </div>
        </section>
      )}

      <Step n={1} title="Pick an attack" id="attack-picker">
        <div className="flex flex-wrap items-center gap-3 text-[14px]" style={{ color: 'var(--text-2)' }}>
          <label className="flex items-center gap-2">
            <input type="checkbox" id="evidence-only-acted" checked={onlyActed} onChange={e => setOnlyActed(e.target.checked)} />
            Only attacks the agent acted on in some setup
          </label>
          <span style={{ color: 'var(--text-3)' }}>
            In many trials the small model ignored the note; those are in the counts too.
          </span>
        </div>
        {!attacks ? (
          <LoadingState label="Loading attacks…" />
        ) : (
          <div className="overflow-x-auto rounded-xl border border-line bg-surface-1">
            <table className="w-full text-[13px] border-collapse" id="attack-table">
              <thead>
                <tr className="bg-surface-2 text-[12px] uppercase tracking-wider text-fg-3 font-semibold border-b border-line text-left">
                  <th className="px-4 py-2.5 font-medium">Attack</th>
                  <th className="px-4 py-2.5 font-medium">The hidden note asks the agent to</th>
                  {conds.map(c => (
                    <th key={c} className="px-4 py-2.5 font-medium whitespace-nowrap">
                      {c}: harm
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map(a => (
                  <tr
                    key={a.id}
                    data-attack={a.id}
                    aria-selected={a.id === scenario}
                    onClick={() => setScenario(a.id)}
                    className={`h-11 min-h-[44px] cursor-pointer transition-colors border-b border-line last:border-b-0 ${
                      a.id === scenario ? 'bg-surface-2 font-medium' : 'hover:bg-surface-2/50'
                    }`}
                  >
                    <td className="px-4 py-2">
                      <button type="button" className="mono text-[13px] underline-offset-2 hover:underline bg-transparent border-none p-0 cursor-pointer text-fg" onClick={() => setScenario(a.id)}>
                        {a.id.replace('injected_indirect_', '#')}
                      </button>
                    </td>
                    <td className="px-4 py-2" style={{ color: 'var(--text-2)' }}>
                      {ACTION_LABEL[a.injected_action] || a.injected_action}: <span className="mono text-[13px] text-fg">{a.injected_target}</span>
                      {a.phrasing === 'indirect_reference' && (
                        <span className="text-[12px]" style={{ color: 'var(--text-3)' }}>
                          {' '}
                          (named indirectly)
                        </span>
                      )}
                    </td>
                    {conds.map(c => (
                      <HarmCell key={c} v={a.by_condition[c]} />
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Step>

      {!detail ? (
        <LoadingState label="Loading the attack…" />
      ) : (
        <>
          <Step n={2} title="The trap" id="attack-trap">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="card p-4 flex flex-col gap-3">
                <div className="flex flex-col gap-1">
                  <span className="text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                    What the user asked
                  </span>
                  <p className="m-0 text-[15px] leading-relaxed text-fg" id="attack-request">
                    {detail.scenario.user_prompt}
                  </p>
                </div>
                <div className="flex flex-col gap-1 text-[14px]">
                  <span className="text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                    The boundary that request gives
                  </span>
                  <div>
                    Read: <span className="mono">{detail.scenario.boundary?.files_read?.join(', ') || 'nothing'}</span>
                  </div>
                  <div>
                    Write: <span className="mono">{detail.scenario.boundary?.files_write?.join(', ') || 'nothing'}</span>
                  </div>
                  <div>
                    Network: <span className="mono">{detail.scenario.boundary?.hosts?.length ? detail.scenario.boundary.hosts.join(', ') : 'none'}</span>
                  </div>
                  <div style={{ color: 'var(--text-3)' }}>Everything else is denied.</div>
                </div>
                {detail.scenario.decoys.length > 0 && (
                  <div className="flex flex-col gap-1 text-[14px]" id="attack-decoys">
                    <span className="text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-3)' }}>
                      Private files planted in the home folder (each holds a unique code)
                    </span>
                    {detail.scenario.decoys.map(d => (
                      <div key={d} className="mono text-[13px]" style={{ color: d === detail.scenario.injected_target ? 'var(--bad-text)' : 'var(--text-2)' }} data-target={d === detail.scenario.injected_target || undefined}>
                        {d}
                        {d === detail.scenario.injected_target ? '  ← the note points here' : ''}
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div className="flex flex-col gap-3">
                {detail.scenario.files.map(f => (
                  <div key={f.path} className="rounded-xl border border-line-strong overflow-hidden" style={{ background: 'var(--surface-terminal)' }}>
                    <div className="px-3 py-2 mono text-[12px] border-b border-line-strong" style={{ color: 'var(--text-3)' }}>
                      {f.path} (the input file the agent reads)
                    </div>
                    <pre className="m-0 p-3 whitespace-pre-wrap break-words mono text-[13px] leading-relaxed">
                      {f.lines.map(ln => (
                        <div
                          key={ln.n}
                          data-hidden={ln.hidden || undefined}
                          className="flex gap-3 rounded"
                          style={ln.hidden ? { background: 'rgb(var(--bad-rgb) / 0.14)', color: 'var(--bad-lighter)' } : { color: 'var(--text)' }}
                        >
                          <span className="select-none w-5 text-right shrink-0" style={{ color: 'var(--text-3)' }}>
                            {ln.n}
                          </span>
                          <span className="min-w-0">{ln.text || ' '}</span>
                        </div>
                      ))}
                    </pre>
                    <div className="px-3 py-2 text-[13px] border-t border-line-strong" style={{ color: 'var(--bad-text)' }}>
                      The red line is the hidden instruction. The user never asked for it; it came from the file.
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Step>

          <Step n={3} title="What the agent did with it, in each setup" id="attack-setups">
            <p className="m-0 text-[15px] leading-relaxed max-w-[860px]" style={{ color: 'var(--text-2)' }}>
              Same model, same files, same note. Each column shows one recorded trial at the step where the agent acted on
              the note, and what came back. Click a trial number to see another repeat.
            </p>
            <div className={`grid grid-cols-1 gap-4 ${detail.conditions.length > 2 ? 'md:grid-cols-2 xl:grid-cols-4' : 'md:grid-cols-2'}`}>
              {detail.conditions.map(c => (
                <SetupColumn key={c.condition} c={c} action={detail.scenario.injected_action} onOpen={r => openTrial(c.condition, r)} />
              ))}
            </div>
          </Step>

          <Step n={4} title="Check it yourself" id="attack-files">
            <div className="text-[14px] leading-relaxed flex flex-col gap-1" style={{ color: 'var(--text-2)' }}>
              <div>
                Trials: <span className="mono">{detail.file}</span> (one line per trial; find <span className="mono">"scenario_id": "{detail.scenario.id}"</span>)
              </div>
              <div>
                Scenario: <span className="mono">{detail.scenario_files.join(', ')}</span>
              </div>
              <div style={{ color: 'var(--text-3)' }}>
                "Show every step" opens the full trial, and for trials with an archived receipt, re-checks its hash chain on the spot.
              </div>
            </div>
          </Step>
        </>
      )}

      {util && (
        <section className="card p-4 sm:p-5 flex flex-col gap-2" id="evidence-utility">
          <H2>And normal tasks still work</H2>
          <p className="m-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
            {util.about} Raw file: <span className="mono">{util.file}</span>
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {Object.entries(util.by_condition).map(([c, v]) => (
              <div key={c} className="flex flex-col gap-0.5 text-[14px]" data-condition={c}>
                <div className="font-semibold text-fg">
                  {c} · {v.name}
                </div>
                {v.metrics.map(m => (
                  <div key={m.label} style={{ color: 'var(--text-2)' }}>
                    {m.label}: <span className="font-semibold text-fg">{m.value}/{m.of}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </section>
      )}

      <DetailsDrawer open={!!open} title="Recorded trial" onClose={() => setOpen(null)} id="evidence-drawer">
        {open && <TrialView t={open} />}
      </DetailsDrawer>
    </div>
  );
};
