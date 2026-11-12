import React, { useEffect, useState } from 'react';
import { Bot, FileText, Globe } from 'lucide-react';
import { ExpansionItem } from '../../types';
import { api } from '../../api/client';
import { decisionLead, decisionWarning, formatCountdown, secondsLeft } from '../../logic/plain';
import { fileName } from '../../logic/runView';
import {
  ApprovalScope,
  ExpansionPreview,
  ONCE_HOVER,
  alwaysBlockedReason,
  onceBlockedReason,
  previewFacts,
  riskLabel,
} from '../../logic/approval';

const TIER_STYLE: Record<string, React.CSSProperties> = {
  LOW: { color: '#86EFAC', background: 'rgba(34,197,94,0.12)', borderColor: 'rgba(34,197,94,0.35)' },
  MEDIUM: { color: '#FCD34D', background: 'rgba(245,158,11,0.12)', borderColor: 'rgba(245,158,11,0.35)' },
  HIGH: { color: '#FCA5A5', background: 'rgba(239,68,68,0.12)', borderColor: 'rgba(239,68,68,0.35)' },
};

/** What is being asked for: name, folder, size and risk. No effects, so tests can render it. */
export const RequestPreview: React.FC<{ exp: ExpansionItem; preview: ExpansionPreview | null }> = ({ exp, preview }) => {
  const kind =
    preview?.kind ?? (exp.resource_type === 'network' ? 'address' : exp.resource_type === 'peer_agent' ? 'agent' : 'file');
  const Icon = kind === 'address' ? Globe : kind === 'agent' ? Bot : FileText;
  const tier = String(preview?.risk_tier || exp.effective_risk_tier || '').toUpperCase();
  const risk = riskLabel(tier);
  return (
    <div id="decision-preview" className="rounded-2xl px-4 py-3.5 flex flex-wrap items-start gap-x-3 gap-y-2 bg-[#0E121A] border border-[#1F2633]">
      <Icon aria-hidden="true" className="w-5 h-5 mt-0.5 shrink-0" style={{ color: '#93C5FD' }} />
      <div className="min-w-[200px] flex-1 flex flex-col gap-1">
        <span className="font-mono text-[15px] text-[#E6E9EF] [overflow-wrap:anywhere]">
          {preview?.name || fileName(exp.resource_target)}
        </span>
        <span id="decision-facts" className="text-[14px]" style={{ color: 'var(--text-2)' }}>
          {preview ? previewFacts(preview).join(' · ') : 'Looking up the details…'}
        </span>
      </div>
      <span
        id="decision-risk"
        data-tier={tier || 'UNKNOWN'}
        title={risk.hint}
        className="shrink-0 inline-flex items-center px-2.5 py-0.5 rounded-full border text-[12px] font-semibold whitespace-nowrap"
        style={TIER_STYLE[tier] ?? { color: 'var(--text-2)', borderColor: '#2A3344' }}
      >
        {risk.label}
      </span>
    </div>
  );
};

export const DecisionCard: React.FC<{
  exp: ExpansionItem;
  triedBefore: boolean;
  deciding: boolean;
  onAllow: (scope: ApprovalScope) => void;
  onDeny: (reason: string) => void;
  readOnly?: boolean;
  canManageRules?: boolean;
}> = ({ exp, triedBefore, deciding, onAllow, onDeny, readOnly, canManageRules = false }) => {
  const [now, setNow] = useState(Date.now());
  const [denying, setDenying] = useState(false);
  const [reason, setReason] = useState('');
  const [preview, setPreview] = useState<ExpansionPreview | null>(null);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let live = true;
    api
      .getExpansionPreview(exp.request_id)
      .then(p => {
        if (live) setPreview(p);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [exp.request_id]);

  const name = fileName(exp.resource_target);
  const warning = decisionWarning(exp);
  const left = secondsLeft(exp, now);
  const alwaysWhyNot = alwaysBlockedReason({
    canManageRules,
    rulePossible: preview ? preview.rule_possible : exp.escalated_by_provenance ? false : null,
  });
  const onceWhyNot = onceBlockedReason(preview);

  return (
    <div id={`inline-approval-card-${exp.request_id}`} className="flex flex-col gap-5" data-state="waiting">
      <p className="m-0 text-[18px] leading-relaxed" style={{ color: '#CBD5E1' }}>
        {decisionLead(exp, triedBefore)
          .split(name)
          .flatMap((part, i) => (i === 0 ? [part] : [<strong key={i} style={{ color: '#FDE68A' }}>{name}</strong>, part]))}
      </p>
      <RequestPreview exp={exp} preview={preview} />
      {warning && (
        <div
          id="decision-warning"
          className="px-[18px] py-4 rounded-2xl text-[15px] leading-normal"
          style={{ background: 'rgba(251,113,133,0.08)', border: '1px solid rgba(251,113,133,0.35)', color: '#FECDD3' }}
        >
          Be careful: {warning.charAt(0).toLowerCase() + warning.slice(1)}
        </div>
      )}

      {readOnly ? (
        <p className="m-0 text-[15px]" style={{ color: 'var(--text-2)' }}>
          A decision is waiting. Open it from Run to decide.
        </p>
      ) : !denying ? (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-3">
            <button
              id={`inline-approve-btn-${exp.request_id}`}
              type="button"
              disabled={deciding}
              onClick={() => onAllow('run')}
              className="btn-primary pulse-waiting w-full sm:w-auto"
              style={{ minHeight: 52, padding: '0 28px', background: 'linear-gradient(135deg, #34D399, #22D3EE)', color: '#04130F' }}
            >
              Allow for this run
            </button>
            <button
              id={`allow-once-btn-${exp.request_id}`}
              type="button"
              disabled={deciding || !!onceWhyNot}
              onClick={() => onAllow('once')}
              className="btn-ghost flex-1 sm:flex-none disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ minHeight: 52, padding: '0 22px' }}
              title={onceWhyNot ?? ONCE_HOVER}
              aria-describedby={onceWhyNot ? `once-why-${exp.request_id}` : undefined}
            >
              Allow once
            </button>
            <button
              id={`deny-btn-${exp.request_id}`}
              type="button"
              disabled={deciding}
              onClick={() => setDenying(true)}
              className="btn-ghost flex-1 sm:flex-none"
              style={{ minHeight: 52, padding: '0 22px', borderColor: 'rgba(251,113,133,0.45)', color: '#FECDD3' }}
            >
              Block
            </button>
          </div>
          {onceWhyNot && (
            <span id={`once-why-${exp.request_id}`} className="text-[13px] leading-snug" style={{ color: 'var(--text-3)' }}>
              {onceWhyNot}
            </span>
          )}
          <div className="flex flex-col gap-1.5">
            <button
              id={`always-btn-${exp.request_id}`}
              type="button"
              disabled={deciding || !!alwaysWhyNot}
              aria-describedby={`always-why-${exp.request_id}`}
              onClick={() => onAllow('always')}
              className="btn-ghost self-start disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ minHeight: 44, padding: '0 18px' }}
            >
              Always for this agent
            </button>
            <span id={`always-why-${exp.request_id}`} className="text-[13px] leading-snug" style={{ color: 'var(--text-3)' }}>
              {alwaysWhyNot ?? 'Allows it for this run and saves a standing rule for this agent and this exact name.'}
            </span>
          </div>
        </div>
      ) : (
        <form
          className="flex flex-col gap-3"
          onSubmit={e => {
            e.preventDefault();
            if (reason.trim()) onDeny(reason.trim());
          }}
        >
          <label htmlFor="deny-reason-input" className="text-[15px] font-medium">
            Why block it? (a few words, required)
          </label>
          <input
            id="deny-reason-input"
            value={reason}
            onChange={e => setReason(e.target.value)}
            autoFocus
            required
            maxLength={300}
            placeholder="Not needed for this task"
            className="min-h-[48px] px-4 rounded-[14px] text-[16px] outline-none"
            style={{ background: 'var(--field)', border: '1px solid rgba(251,113,133,0.45)', color: 'var(--text)' }}
          />
          <div className="flex flex-wrap gap-3">
            <button
              id="confirm-deny-btn"
              type="submit"
              disabled={deciding || !reason.trim()}
              className="btn-ghost"
              style={{ borderColor: 'rgba(251,113,133,0.6)', color: '#FECDD3' }}
            >
              Block
            </button>
            <button type="button" className="btn-ghost" onClick={() => setDenying(false)} disabled={deciding}>
              Back
            </button>
          </div>
        </form>
      )}

      <span id="decision-countdown" className="text-[14px]" style={{ color: left <= 30 ? '#FDE68A' : 'var(--text-3)' }}>
        {formatCountdown(left)}
      </span>
    </div>
  );
};
