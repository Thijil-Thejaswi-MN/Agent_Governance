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
import { StatusPill } from '../ui/StatusPill';
import { Button } from '../ui/Button';
import { Tone } from '../../logic/tones';

const fieldCls =
  'w-full min-w-0 min-h-[44px] px-3 rounded-lg bg-surface-2 border border-line-strong text-[14px] text-fg focus:outline-none focus:border-accent';

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

  const outcomeTone = (outcome: string): Tone => {
    if (outcome === 'allow') return 'ok';
    if (outcome === 'deny') return 'bad';
    return 'wait';
  };

  return (
    <section id="policy-check" aria-labelledby="policy-check-heading" className="rounded-xl border border-line bg-surface-1 p-5 flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h2 id="policy-check-heading" className="m-0 text-[17px] font-semibold text-fg">
          Check a decision
        </h2>
        <p className="m-0 text-[14px] text-fg-2 leading-relaxed">
          See what would happen if a run's agent did this now, and which check decides it. Nothing is run and nothing
          changes.
        </p>
      </div>

      <form onSubmit={check} noValidate className="flex flex-col gap-4" aria-label="Check a decision">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <label className="flex flex-col gap-1.5 text-[13px] text-fg-2 sm:col-span-2">
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
          <label className="flex flex-col gap-1.5 text-[13px] text-fg-2">
            The agent tries to
            <select id="sim-action" className={fieldCls} value={choiceValue} onChange={e => setChoiceValue(e.target.value)}>
              {SIM_CHOICES.map(c => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1.5 text-[13px] text-fg-2">
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
          <label className="inline-flex items-center gap-2 text-[14px] text-fg-2">
            <input
              id="sim-use-draft"
              type="checkbox"
              checked={useDraft}
              onChange={e => setUseDraft(e.target.checked)}
              className="accent-accent"
            />
            Include the rule in the form above, as if it were saved and rules were on
          </label>
        )}
        <div>
          <Button id="sim-check-btn" type="submit" variant="primary" size="md" disabled={busy || !taskId} className="min-h-[44px] px-6">
            {busy ? 'Checking…' : 'Check'}
          </Button>
        </div>
      </form>

      {error && (
        <p id="sim-error" role="alert" className="m-0 text-[14px] text-bad">
          {error}
        </p>
      )}

      {result && (
        <div id="sim-result" data-outcome={result.outcome} data-decided-by={result.decided_by} className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <StatusPill
              tone={outcomeTone(result.outcome)}
              label={OUTCOME_LABEL[result.outcome] || result.outcome}
            />
            <span className="text-[14px] text-fg-2">
              decided by <strong className="text-fg">{layerLabel(result.decided_by)}</strong>
              {result.draft_rule && result.rule_id === 'rule_draft' ? ' (your draft rule)' : ''}
            </span>
          </div>
          <p className="m-0 text-[14px] text-fg [overflow-wrap:anywhere]">{result.reason}</p>
          <ol id="sim-steps" className="m-0 p-0 list-none flex flex-col gap-2">
            {shownSteps(result).map((s, i) => {
              const tone = stepTone(s);
              const pillTone: Tone = tone === 'ask' ? 'wait' : tone;
              return (
                <li
                  key={`${s.layer}-${i}`}
                  data-layer={s.layer}
                  data-result={s.result}
                  className="p-3 rounded-lg bg-surface-2 border border-line flex flex-col gap-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-fg text-[13px]">{layerLabel(s.layer)}</span>
                    <StatusPill tone={pillTone} label={s.result} />
                  </div>
                  <span className="text-[13px] text-fg-2 [overflow-wrap:anywhere]">{s.reason}</span>
                </li>
              );
            })}
          </ol>
          <p className="m-0 text-[12px] font-mono text-fg-3">
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
