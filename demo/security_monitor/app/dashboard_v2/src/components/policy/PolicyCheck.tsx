import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import { TaskRecord } from '../../types';
import { RuleDraft } from '../../logic/rules';
import {
  OUTCOME_LABEL,
  SIM_CHOICES,
  SimResult,
  buildSimRequest,
  choiceFor,
  draftApplies,
  layerLabel,
  shownSteps,
  stepTone,
} from '../../logic/policySim';

const fieldCls =
  'w-full min-w-0 min-h-[44px] px-3 rounded-lg bg-[#0E121A] border border-[#2A3344] text-[15px] text-[#E6E9EF] focus:outline-none focus:border-[#3B82F6]';

const OUTCOME_STYLE: Record<string, React.CSSProperties> = {
  allow: { color: '#86EFAC', background: 'rgba(34,197,94,0.10)', borderColor: 'rgba(34,197,94,0.35)' },
  deny: { color: '#FCA5A5', background: 'rgba(239,68,68,0.10)', borderColor: 'rgba(239,68,68,0.35)' },
  ask: { color: '#FCD34D', background: 'rgba(245,158,11,0.10)', borderColor: 'rgba(245,158,11,0.35)' },
};

const TONE_COLOR = { ok: '#86EFAC', bad: '#FCA5A5', ask: '#FCD34D', info: 'var(--text-3)' } as const;

/** "Check a decision": asks the server what the broker would do with one action of a run. */
export const PolicyCheck: React.FC<{ draft: RuleDraft }> = ({ draft }) => {
  const [tasks, setTasks] = useState<TaskRecord[] | null>(null);
  const [taskId, setTaskId] = useState('');
  const [choiceValue, setChoiceValue] = useState('read_file');
  const [target, setTarget] = useState('');
  const [useDraft, setUseDraft] = useState(true);
  const [result, setResult] = useState<SimResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .getTasks()
      .then(ts => {
        const sorted = [...(ts || [])].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
        setTasks(sorted.slice(0, 50));
        if (sorted[0]) setTaskId(sorted[0].task_id);
      })
      .catch(() => setTasks([]));
  }, []);

  const choice = choiceFor(choiceValue);
  const canTestDraft = draftApplies(choice, draft);

  const check = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!taskId || !target.trim()) {
      setError('Choose a run and give what the agent would use.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setResult(await api.simulatePolicy(buildSimRequest(taskId, choice, target, useDraft ? draft : null)));
    } catch (err: any) {
      setResult(null);
      setError(err?.message || 'Could not check this decision.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section id="policy-check" aria-labelledby="policy-check-heading" className="card p-5 flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h2 id="policy-check-heading" className="m-0 text-[17px] font-semibold text-[#E6E9EF]">
          Check a decision
        </h2>
        <p className="m-0 text-[14px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
          See what would happen if a run's agent did this now, and which check decides it. Nothing is run and nothing
          changes.
        </p>
      </div>

      <form onSubmit={check} noValidate className="flex flex-col gap-4" aria-label="Check a decision">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <label className="flex flex-col gap-1.5 text-[13px] sm:col-span-2" style={{ color: 'var(--text-2)' }}>
            Run
            <select id="sim-task" className={fieldCls} value={taskId} onChange={e => setTaskId(e.target.value)}>
              {!tasks && <option value="">Loading runs…</option>}
              {tasks && tasks.length === 0 && <option value="">No runs yet</option>}
              {(tasks || []).map(t => (
                <option key={t.task_id} value={t.task_id}>
                  {t.agent_id}: {t.request_text.slice(0, 70)}
                  {t.request_text.length > 70 ? '…' : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1.5 text-[13px]" style={{ color: 'var(--text-2)' }}>
            The agent tries to
            <select id="sim-action" className={fieldCls} value={choiceValue} onChange={e => setChoiceValue(e.target.value)}>
              {SIM_CHOICES.map(c => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1.5 text-[13px]" style={{ color: 'var(--text-2)' }}>
            {choice.tool === 'run_command' ? 'Command' : 'Exact name'}
            <input
              id="sim-target"
              className={`${fieldCls} font-mono`}
              placeholder={choice.placeholder}
              value={target}
              onChange={e => setTarget(e.target.value)}
              autoComplete="off"
            />
          </label>
        </div>
        {canTestDraft && (
          <label className="inline-flex items-center gap-2 text-[14px]" style={{ color: 'var(--text-2)' }}>
            <input
              id="sim-use-draft"
              type="checkbox"
              checked={useDraft}
              onChange={e => setUseDraft(e.target.checked)}
              className="accent-[#3B82F6]"
            />
            Include the rule in the form above, as if it were saved and rules were on
          </label>
        )}
        <div>
          <button id="sim-check-btn" type="submit" className="btn-primary min-h-[44px] px-6" disabled={busy || !taskId}>
            {busy ? 'Checking…' : 'Check'}
          </button>
        </div>
      </form>

      {error && (
        <p id="sim-error" role="alert" className="m-0 text-[14px]" style={{ color: '#FCA5A5' }}>
          {error}
        </p>
      )}

      {result && (
        <div id="sim-result" data-outcome={result.outcome} data-decided-by={result.decided_by} className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className="inline-flex items-center px-3 py-1 rounded-full border text-[13px] font-semibold"
              style={OUTCOME_STYLE[result.outcome]}
            >
              {OUTCOME_LABEL[result.outcome] || result.outcome}
            </span>
            <span className="text-[14px]" style={{ color: 'var(--text-2)' }}>
              decided by <strong className="text-[#E6E9EF]">{layerLabel(result.decided_by)}</strong>
              {result.draft_rule && result.rule_id === 'rule_draft' ? ' (your draft rule)' : ''}
            </span>
          </div>
          <p className="m-0 text-[14px] text-[#E6E9EF] [overflow-wrap:anywhere]">{result.reason}</p>
          <ol id="sim-steps" className="m-0 pl-5 flex flex-col gap-1.5 text-[14px]">
            {shownSteps(result).map((s, i) => (
              <li key={`${s.layer}-${i}`} data-layer={s.layer} data-result={s.result}>
                <span className="font-semibold" style={{ color: TONE_COLOR[stepTone(s)] }}>
                  {layerLabel(s.layer)}
                </span>
                <span style={{ color: 'var(--text-3)' }}> · {s.result}</span>
                <span className="block [overflow-wrap:anywhere]" style={{ color: 'var(--text-2)' }}>
                  {s.reason}
                </span>
              </li>
            ))}
          </ol>
          <p className="m-0 text-[12px] font-mono" style={{ color: 'var(--text-3)' }}>
            policy {result.policy_version}
            {result.policy_version !== result.current_policy_version ? ` (the run's own: ${result.current_policy_version})` : ''}
            {' · '}
            {result.precedence}
          </p>
        </div>
      )}
    </section>
  );
};
