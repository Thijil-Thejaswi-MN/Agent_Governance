import React, { useState } from 'react';
import { Bot, FileText, Globe } from 'lucide-react';
import { A2APendingApproval } from '../../types';
import { Button } from '../ui/Button';

interface InlineApprovalCardProps {
  approval: A2APendingApproval;
  canDecide: boolean;
  onApprove: (requestId: string) => Promise<void>;
  onDeny: (requestId: string, reason: string) => Promise<void>;
}

export const InlineApprovalCard: React.FC<InlineApprovalCardProps> = ({
  approval,
  canDecide,
  onApprove,
  onDeny,
}) => {
  const [denying, setDenying] = useState(false);
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);

  // A data-flow request (resource_type "flow") asks to let one action through after the
  // agent took in private or untrusted data; its reason says what and why in plain words.
  const isFlow = approval.resource_type === 'flow';
  const kind =
    approval.resource_type === 'network'
      ? 'address'
      : approval.resource_type === 'peer_agent' || isFlow
      ? 'agent'
      : 'file';
  const Icon = kind === 'address' ? Globe : kind === 'agent' ? Bot : FileText;

  const handleApprove = async () => {
    setLoading(true);
    try {
      await onApprove(approval.request_id);
    } finally {
      setLoading(false);
    }
  };

  const handleDenySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reason.trim()) return;
    setLoading(true);
    try {
      await onDeny(approval.request_id, reason.trim());
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      id={`approval-card-${approval.request_id}`}
      className="rounded-2xl border border-wait/40 bg-surface-2 p-4 my-2 flex flex-col gap-3 shadow-sm"
    >
      <div className="flex items-start gap-3">
        <div className="w-8 h-8 rounded-full bg-wait/15 border border-wait/30 flex items-center justify-center shrink-0 text-wait">
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[14px] font-semibold text-fg">
              {isFlow ? 'Your OK is needed' : 'Permission requested'}
            </span>
            <span className="text-[12px] font-mono px-2 py-0.5 rounded-full bg-wait/15 text-wait-text border border-wait/30">
              {isFlow ? 'data rule' : approval.resource_type}
            </span>
          </div>
          <div className="font-mono text-[13px] text-fg mt-1 [overflow-wrap:anywhere]">
            {approval.resource_target}
          </div>
          {approval.justification && (
            <p className="text-[13px] text-fg-2 m-0 mt-1 leading-relaxed">
              {approval.justification}
            </p>
          )}
        </div>
      </div>

      {canDecide ? (
        !denying ? (
          <div className="flex items-center gap-2.5 pt-1 border-t border-line">
            <Button
              id={`approve-btn-${approval.request_id}`}
              type="button"
              variant="primary"
              size="sm"
              disabled={loading}
              onClick={handleApprove}
              className="pulse-waiting min-h-[36px] px-4"
            >
              Approve
            </Button>
            <Button
              id={`deny-btn-${approval.request_id}`}
              type="button"
              variant="danger"
              size="sm"
              disabled={loading}
              onClick={() => setDenying(true)}
              className="min-h-[36px] px-4"
            >
              Deny
            </Button>
          </div>
        ) : (
          <form onSubmit={handleDenySubmit} className="flex flex-col gap-2 pt-1 border-t border-line">
            <label htmlFor={`deny-reason-${approval.request_id}`} className="text-[13px] text-fg">
              Reason for denial:
            </label>
            <input
              id={`deny-reason-${approval.request_id}`}
              type="text"
              required
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="e.g. Access not permitted for this run"
              className="min-h-[38px] px-3 rounded-lg text-[13px] outline-none bg-surface-1 border border-line text-fg focus:border-line-strong"
            />
            <div className="flex items-center gap-2">
              <Button
                id={`confirm-deny-btn-${approval.request_id}`}
                type="submit"
                variant="danger"
                size="sm"
                disabled={loading || !reason.trim()}
                className="min-h-[36px] px-3"
              >
                Confirm Denial
              </Button>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                disabled={loading}
                onClick={() => setDenying(false)}
                className="min-h-[36px] px-3"
              >
                Back
              </Button>
            </div>
          </form>
        )
      ) : (
        <div className="pt-1 border-t border-line text-[13px] text-fg-3 italic">
          Waiting for decision from task owner.
        </div>
      )}
    </div>
  );
};
