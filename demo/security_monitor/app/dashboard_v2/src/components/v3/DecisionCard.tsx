import React, { useEffect, useState } from 'react';
import { ExpansionItem } from '../../types';
import { decisionLead, decisionWarning, formatCountdown, secondsLeft } from '../../logic/plain';
import { fileName } from '../../logic/runView';

export const DecisionCard: React.FC<{
  exp: ExpansionItem;
  triedBefore: boolean;
  deciding: boolean;
  onAllow: () => void;
  onDeny: (reason: string) => void;
  readOnly?: boolean;
}> = ({ exp, triedBefore, deciding, onAllow, onDeny, readOnly }) => {
  const [now, setNow] = useState(Date.now());
  const [denying, setDenying] = useState(false);
  const [reason, setReason] = useState('');

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const name = fileName(exp.resource_target);
  const warning = decisionWarning(exp);
  const left = secondsLeft(exp, now);

  return (
    <div id={`inline-approval-card-${exp.request_id}`} className="flex flex-col gap-5" data-state="waiting">
      <p className="m-0 text-[18px] leading-relaxed" style={{ color: '#CBD5E1' }}>
        {decisionLead(exp, triedBefore)
          .split(name)
          .flatMap((part, i) => (i === 0 ? [part] : [<strong key={i} style={{ color: '#FDE68A' }}>{name}</strong>, part]))}
      </p>
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
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-3">
            <button
              id={`inline-approve-btn-${exp.request_id}`}
              type="button"
              disabled={deciding}
              onClick={onAllow}
              className="btn-primary pulse-waiting"
              style={{ minHeight: 52, padding: '0 28px', background: 'linear-gradient(135deg, #34D399, #22D3EE)', color: '#04130F' }}
            >
              Allow once
            </button>
            <button
              id={`deny-btn-${exp.request_id}`}
              type="button"
              disabled={deciding}
              onClick={() => setDenying(true)}
              className="btn-ghost"
              style={{ minHeight: 52, padding: '0 28px' }}
            >
              Don't allow
            </button>
          </div>
          <span className="text-[13px]" style={{ color: 'var(--text-3)' }}>
            Allowing applies to this run only.
          </span>
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
            Why not? (a few words, required)
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
            <button id="confirm-deny-btn" type="submit" disabled={deciding || !reason.trim()} className="btn-ghost" style={{ borderColor: 'rgba(251,113,133,0.6)', color: '#FECDD3' }}>
              Don't allow
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
