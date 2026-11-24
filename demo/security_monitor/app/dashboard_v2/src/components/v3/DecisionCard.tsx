import React, { useEffect, useState } from 'react';
import { Bot, FileText, Globe } from 'lucide-react';
import { ExpansionItem } from '../../types';
import { api } from '../../api/client';
import { decisionLead, decisionWarning, formatCountdown, secondsLeft } from '../../logic/plain';
import { fileName } from '../../logic/runView';
import { Button } from '../ui/Button';
import {
  ApprovalScope,
  TIMED_MINUTES,
  ExpansionPreview,
  StagedSnapshot,
  formatBytes,
  ONCE_HOVER,
  alwaysBlockedReason,
  onceBlockedReason,
  previewFacts,
  riskLabel,
} from '../../logic/approval';

const TIER_STYLE: Record<string, React.CSSProperties> = {
  LOW: { color: 'var(--ok-text)', background: 'var(--ok-tint)', borderColor: 'rgb(var(--ok-rgb) / 0.35)' },
  MEDIUM: { color: 'var(--wait-text)', background: 'var(--wait-tint)', borderColor: 'rgb(var(--wait-rgb) / 0.35)' },
  HIGH: { color: 'var(--bad-text)', background: 'var(--bad-tint)', borderColor: 'rgb(var(--bad-rgb) / 0.35)' },
};

/** What is being asked for: name, folder, size and risk. No effects, so tests can render it. */
export const RequestPreview: React.FC<{ exp: ExpansionItem; preview: ExpansionPreview | null }> = ({ exp, preview }) => {
  const kind =
    preview?.kind ?? (exp.resource_type === 'network' ? 'address' : exp.resource_type === 'peer_agent' ? 'agent' : 'file');
  const Icon = kind === 'address' ? Globe : kind === 'agent' ? Bot : FileText;
  const tier = String(preview?.risk_tier || exp.effective_risk_tier || '').toUpperCase();
  const risk = riskLabel(tier);
  return (
    <div id="decision-preview" className="rounded-2xl px-4 py-3.5 flex flex-wrap items-start gap-x-3 gap-y-2 bg-surface-2 border border-line">
      <Icon aria-hidden="true" className="w-5 h-5 mt-0.5 shrink-0" style={{ color: 'var(--info-text)' }} />
      <div className="min-w-[200px] flex-1 flex flex-col gap-1">
        <span className="font-mono text-[15px] text-fg [overflow-wrap:anywhere]">
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
        style={TIER_STYLE[tier] ?? { color: 'var(--text-2)', borderColor: 'var(--line-strong)' }}
      >
        {risk.label}
      </span>
    </div>
  );
};

/** For a write request: the exact content that will be saved if allowed (the snapshot, not the live file). */
export const StagedContent: React.FC<{ staged: StagedSnapshot | null | undefined }> = ({ staged }) => {
  if (!staged) return null;
  return (
    <div id="decision-staged" className="flex flex-col gap-2">
      <span className="text-[14px] font-semibold" style={{ color: 'var(--text-2)' }}>
        Content that will be saved if you allow it (exactly these {formatBytes(staged.size_bytes) ?? 'bytes'}):
      </span>
      {staged.binary ? (
        <p className="m-0 text-[14px]" style={{ color: 'var(--text-2)' }}>
          This is a binary file, so its content is not shown. Block it unless you expected a binary file.
        </p>
      ) : (
        <pre
          id="decision-staged-content"
          className="m-0 max-h-64 overflow-auto rounded-xl px-3 py-2.5 text-[13px] leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere] bg-surface-terminal border border-line"
          style={{ color: 'var(--text)' }}
        >
          {staged.preview}
          {staged.truncated ? '\n… (only the start is shown: 2,000 characters)' : ''}
        </pre>
      )}
      <span className="text-[12px] font-mono" style={{ color: 'var(--text-3)' }} title={staged.content_sha256}>
        SHA-256 {staged.content_sha256.slice(0, 16)}… (recorded in the task record)
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
    <div id={`inline-approval-card-${exp.request_id}`} className="flex flex-col gap-5 rounded-2xl border border-line bg-surface-1 p-5 shadow-sm" data-state="waiting">
      <p className="m-0 text-[18px] leading-relaxed" style={{ color: 'var(--text-soft)' }}>
        {decisionLead(exp, triedBefore)
          .split(name)
          .flatMap((part, i) => (i === 0 ? [part] : [<strong key={i} style={{ color: 'var(--wait-lighter)' }}>{name}</strong>, part]))}
      </p>
      {exp.resource_type !== 'flow' && <RequestPreview exp={exp} preview={preview} />}
      {exp.resource_type !== 'flow' && <StagedContent staged={preview?.staged} />}
      {warning && (
        <div
          id="decision-warning"
          className="px-[18px] py-4 rounded-2xl text-[15px] leading-normal"
          style={{ background: 'rgb(var(--blocked-rgb) / 0.08)', border: '1px solid rgb(var(--blocked-rgb) / 0.35)', color: 'var(--blocked-text)' }}
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
            <Button
              id={`inline-approve-btn-${exp.request_id}`}
              type="button"
              variant="primary"
              size="md"
              disabled={deciding}
              onClick={() => onAllow('run')}
              className="pulse-waiting w-full sm:w-auto min-h-[44px] px-6"
            >
              Allow for this run
            </Button>
            <Button
              id={`allow-once-btn-${exp.request_id}`}
              type="button"
              variant="secondary"
              size="md"
              disabled={deciding || !!onceWhyNot}
              onClick={() => onAllow('once')}
              className="flex-1 sm:flex-none min-h-[44px] px-5 disabled:opacity-50 disabled:cursor-not-allowed"
              title={onceWhyNot ?? ONCE_HOVER}
              aria-describedby={onceWhyNot ? `once-why-${exp.request_id}` : undefined}
            >
              Allow once
            </Button>
            {exp.resource_type !== 'file_write' && (
              <Button
                id={`allow-timed-btn-${exp.request_id}`}
                type="button"
                variant="secondary"
                size="md"
                disabled={deciding}
                onClick={() => onAllow('timed')}
                className="flex-1 sm:flex-none min-h-[44px] px-5"
                title={`The grant ends by itself after ${TIMED_MINUTES} minutes; the agent cannot open it again after that.`}
              >
                Allow for {TIMED_MINUTES} minutes
              </Button>
            )}
            <Button
              id={`deny-btn-${exp.request_id}`}
              type="button"
              variant="danger"
              size="md"
              disabled={deciding}
              onClick={() => setDenying(true)}
              className="flex-1 sm:flex-none min-h-[44px] px-5"
            >
              Block
            </Button>
          </div>
          {onceWhyNot && (
            <span id={`once-why-${exp.request_id}`} className="text-[13px] leading-snug text-fg-3">
              {onceWhyNot}
            </span>
          )}
          <div className="flex flex-col gap-1.5">
            <Button
              id={`always-btn-${exp.request_id}`}
              type="button"
              variant="secondary"
              size="sm"
              disabled={deciding || !!alwaysWhyNot}
              aria-describedby={`always-why-${exp.request_id}`}
              onClick={() => onAllow('always')}
              className="self-start min-h-[40px] px-4 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Always for this agent
            </Button>
            <span id={`always-why-${exp.request_id}`} className="text-[13px] leading-snug text-fg-3">
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
          <label htmlFor="deny-reason-input" className="text-[15px] font-medium text-fg">
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
            className="min-h-[48px] px-4 rounded-[14px] text-[16px] outline-none bg-surface-2 border border-line text-fg focus:border-line-strong"
          />
          <div className="flex flex-wrap gap-3">
            <Button
              id="confirm-deny-btn"
              type="submit"
              variant="danger"
              size="md"
              disabled={deciding || !reason.trim()}
              className="min-h-[44px] px-5"
            >
              Block
            </Button>
            <Button
              type="button"
              variant="secondary"
              size="md"
              onClick={() => setDenying(false)}
              disabled={deciding}
              className="min-h-[44px] px-5"
            >
              Back
            </Button>
          </div>
        </form>
      )}

      <span id="decision-countdown" className="text-[14px]" style={{ color: left <= 30 ? 'var(--wait-lighter)' : 'var(--text-3)' }}>
        {formatCountdown(left)}
      </span>
    </div>
  );
};
