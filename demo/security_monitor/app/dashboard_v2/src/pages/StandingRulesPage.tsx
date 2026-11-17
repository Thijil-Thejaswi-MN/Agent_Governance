import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { StandingRule } from '../types';
import { useAuth } from '../context/AuthContext';
import { EmptyState, ErrorState, LoadingState } from '../components/common/States';
import { ResponseChip, RuleSentence } from '../components/policy/RuleBits';
import { PolicyCheck } from '../components/policy/PolicyCheck';
import { ACTIONS, RESPONSES, RuleDraft, draftFromParams, draftProblems, ruleState, sortRules } from '../logic/rules';

const EMPTY_DRAFT: RuleDraft = { agent_or_profile: '*', action: 'file_read', target: '', response: 'allow', expiry_days: 30 };

const STATE_LABEL = { active: 'Active', expired: 'Expired', switched_off: 'Switched off' } as const;

const fieldCls =
  'w-full min-w-0 min-h-[44px] px-3 rounded-lg bg-surface-1 border border-line-strong text-[15px] text-fg focus:outline-none focus:border-accent';

export const StandingRulesPage: React.FC = () => {
  const { role } = useAuth();
  const [rules, setRules] = useState<StandingRule[] | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [params] = useSearchParams();
  // "Make this a rule" (Incidents) opens this page with the form filled in.
  const [draft, setDraft] = useState<RuleDraft>(() => draftFromParams(params, EMPTY_DRAFT));
  const prefilled = !!params.get('target');
  const [saving, setSaving] = useState(false);
  const [touched, setTouched] = useState(false);

  const fetchRules = useCallback(async () => {
    try {
      const res = await api.getStandingRules();
      setRules(res.rules || []);
      setEnabled(!!res.enabled);
      setCanManage(!!res.can_manage);
      setLoadError(null);
    } catch (err: any) {
      setLoadError(err?.message || 'Could not load the rules.');
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const problems = draftProblems(draft);
  const manage = canManage || role === 'admin' || role === 'security_reviewer';
  const action = ACTIONS.find(a => a.value === draft.action)!;

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (problems.length) return;
    setSaving(true);
    setActionError(null);
    try {
      await api.createStandingRule({ ...draft, target: draft.target.trim(), agent_or_profile: draft.agent_or_profile.trim() });
      setDraft({ ...EMPTY_DRAFT });
      setTouched(false);
      await fetchRules();
    } catch (err: any) {
      setActionError(err?.message || 'Could not save the rule.');
    } finally {
      setSaving(false);
    }
  };

  const expire = async (ruleId: string) => {
    setActionError(null);
    try {
      await api.expireStandingRule(ruleId);
      await fetchRules();
    } catch (err: any) {
      setActionError(err?.message || 'Could not switch the rule off.');
    }
  };

  const shown = rules ? sortRules(rules) : [];
  const activeCount = shown.filter(r => ruleState(r) === 'active').length;

  return (
    <div className="max-w-[960px] pb-12 flex flex-col gap-6">
      <header className="flex flex-col gap-2">
        <h1 className="m-0 font-display font-bold text-[28px] sm:text-[32px] leading-[1.15] text-fg">Policies</h1>
        <p className="m-0 text-[16px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
          Standing rules decide requests that would otherwise wait for a person. High-risk requests, and requests
          that a file the agent read may have prompted, always go to a person.
        </p>
      </header>

      <div
        id="rules-status"
        data-enabled={enabled ? 'true' : 'false'}
        className="rounded-xl px-4 py-3 text-[14px] leading-relaxed"
        style={
          enabled
            ? { background: 'rgb(var(--ok-rgb) / 0.08)', border: '1px solid rgb(var(--ok-rgb) / 0.3)', color: 'var(--ok-lighter)' }
            : { background: 'rgb(var(--wait-rgb) / 0.08)', border: '1px solid rgb(var(--wait-rgb) / 0.3)', color: 'var(--wait-lighter)' }
        }
      >
        {enabled
          ? 'Rules are on. Every decision a rule makes is written in the record with the rule and its owner.'
          : 'Rules are off on this server, so none of them decide anything yet. Start the server with GOVERNANCE_STANDING_RULES=1 to switch them on.'}
      </div>

      {actionError && <ErrorState message={actionError} id="rules-action-error" />}

      {manage && (
        <form
          id="rule-form"
          onSubmit={save}
          noValidate
          aria-label="Add a rule"
          className="card p-5 flex flex-col gap-4"
        >
          <h2 className="m-0 text-[17px] font-semibold text-fg">Add a rule</h2>
          {prefilled && (
            <p id="rule-prefilled" className="m-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
              Filled in from a blocked action. Check it, then save.
            </p>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <label className="flex flex-col gap-1.5 text-[13px]" style={{ color: 'var(--text-2)' }}>
              Agent (* for every agent)
              <input
                id="rule-agent"
                className={`${fieldCls} font-mono`}
                value={draft.agent_or_profile}
                onChange={e => setDraft({ ...draft, agent_or_profile: e.target.value })}
                autoComplete="off"
              />
            </label>
            <label className="flex flex-col gap-1.5 text-[13px]" style={{ color: 'var(--text-2)' }}>
              When it asks to
              <select
                id="rule-action"
                className={fieldCls}
                value={draft.action}
                onChange={e => setDraft({ ...draft, action: e.target.value as RuleDraft['action'] })}
              >
                {ACTIONS.map(a => (
                  <option key={a.value} value={a.value}>
                    {a.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1.5 text-[13px] sm:col-span-2" style={{ color: 'var(--text-2)' }}>
              Exact name
              <input
                id="rule-target"
                className={`${fieldCls} font-mono`}
                placeholder={action.placeholder}
                value={draft.target}
                onChange={e => setDraft({ ...draft, target: e.target.value })}
                autoComplete="off"
              />
            </label>
          </div>

          <fieldset className="m-0 p-0 border-0 flex flex-col gap-2">
            <legend className="text-[13px] mb-1.5" style={{ color: 'var(--text-2)' }}>
              Response
            </legend>
            <div role="radiogroup" className="flex flex-wrap gap-2">
              {RESPONSES.map(r => (
                <label
                  key={r.value}
                  className={`inline-flex items-center gap-2 min-h-[44px] px-4 rounded-lg border cursor-pointer text-[14px] font-medium ${
                    draft.response === r.value ? 'border-accent bg-accent/10 text-fg' : 'border-line-strong text-fg-2'
                  }`}
                  title={r.hint}
                >
                  <input
                    type="radio"
                    name="rule-response"
                    value={r.value}
                    checked={draft.response === r.value}
                    onChange={() => setDraft({ ...draft, response: r.value })}
                    className="accent-accent"
                  />
                  {r.label}
                </label>
              ))}
            </div>
            <p className="m-0 text-[13px]" style={{ color: 'var(--text-3)' }}>
              {RESPONSES.find(r => r.value === draft.response)?.hint}
            </p>
          </fieldset>

          <label className="flex flex-col gap-1.5 text-[13px] w-full sm:w-[220px]" style={{ color: 'var(--text-2)' }}>
            Lasts (days, up to 90)
            <input
              id="rule-days"
              type="number"
              min={1}
              max={90}
              className={fieldCls}
              value={Number.isFinite(draft.expiry_days) ? draft.expiry_days : ''}
              onChange={e => setDraft({ ...draft, expiry_days: parseInt(e.target.value, 10) })}
            />
          </label>

          <div className="rounded-lg px-4 py-3 bg-surface-1 border border-line" id="rule-preview">
            <RuleSentence rule={draft} />
          </div>

          {touched && problems.length > 0 && (
            <ul id="rule-problems" className="m-0 pl-5 text-[14px]" style={{ color: 'var(--bad-text)' }}>
              {problems.map(p => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}

          <div>
            <button id="rule-save-btn" type="submit" className="btn-primary min-h-[44px] px-6" disabled={saving}>
              {saving ? 'Saving…' : 'Save rule'}
            </button>
          </div>
        </form>
      )}

      <PolicyCheck draft={draft} />

      <section aria-labelledby="rules-heading" className="flex flex-col gap-3">
        <h2 id="rules-heading" className="m-0 text-[17px] font-semibold text-fg">
          Standing rules {rules ? `(${activeCount} active)` : ''}
        </h2>
        {loadError ? (
          <ErrorState message={loadError} onRetry={fetchRules} id="rules-load-error" />
        ) : !rules ? (
          <LoadingState label="Loading rules…" id="rules-loading" />
        ) : shown.length === 0 ? (
          <EmptyState
            id="rules-empty"
            title="No rules yet."
            body={
              manage
                ? 'Add one above, or choose “Always for this agent” on a waiting request.'
                : 'A security reviewer or an admin can add rules.'
            }
          />
        ) : (
          <ul id="rules-list" className="list-none m-0 p-0 flex flex-col gap-3">
            {shown.map(r => {
              const state = ruleState(r);
              return (
                <li
                  key={r.rule_id}
                  data-rule-id={r.rule_id}
                  data-state={state}
                  className="card p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center gap-3"
                  style={state === 'active' ? undefined : { opacity: 0.72 }}
                >
                  <div className="flex-1 min-w-0 flex flex-col gap-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <ResponseChip response={r.response} />
                      {state !== 'active' && (
                        <span className="text-[12px] font-semibold" style={{ color: 'var(--text-3)' }}>
                          {STATE_LABEL[state]}
                        </span>
                      )}
                    </div>
                    <RuleSentence rule={r} />
                    <p className="m-0 text-[13px]" style={{ color: 'var(--text-3)' }}>
                      <span className="font-mono">{r.rule_id}</span> · owner {r.owner}
                      {r.team ? ` · team ${r.team}` : ''} · {state === 'active' ? 'until' : 'was until'}{' '}
                      {new Date(r.expires_at).toLocaleDateString()}
                    </p>
                  </div>
                  {manage && state === 'active' && (
                    <button
                      type="button"
                      onClick={() => expire(r.rule_id)}
                      className="btn-ghost min-h-[44px] sm:min-h-[36px] self-start sm:self-center"
                      aria-label={`Switch off rule ${r.rule_id}`}
                    >
                      Switch off
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
};
