import React from 'react';
import { A2AMessage, A2APendingApproval } from '../../types';
import { AgentRingAvatar } from './AgentAvatar';
import { InlineApprovalCard } from './InlineApprovalCard';
import { localClock } from '../v3/TechnicalTimeline';
import { getAgentDisplayName } from '../../logic/conversations';
import { FileText, CornerDownRight } from 'lucide-react';

interface ChatMessagesProps {
  threadId: string;
  messages: A2AMessage[];
  pendingApprovals: A2APendingApproval[];
  agentNames: Record<string, string>;
  agentColourIndexes: Record<string, number>;
  canDecide: boolean;
  onApprove: (requestId: string) => Promise<void>;
  onDeny: (requestId: string, reason: string) => Promise<void>;
}

export const ChatMessages: React.FC<ChatMessagesProps> = ({
  threadId,
  messages,
  pendingApprovals,
  agentNames,
  agentColourIndexes,
  canDecide,
  onApprove,
  onDeny,
}) => {
  const isWholeJob = threadId === 'job';
  const leadSender = messages.length > 0 ? messages[0].from_agent : '';

  if (messages.length === 0 && pendingApprovals.length === 0) {
    return (
      <div className="flex items-center justify-center h-full p-8 text-fg-3 text-[14px]">
        No messages recorded in this chat yet.
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-4 space-y-4">
      {messages.map(m => {
        const isRight = !isWholeJob && m.from_agent === leadSender;
        const senderName = getAgentDisplayName(m.from_agent, agentNames);
        const receiverName = getAgentDisplayName(m.to_agent, agentNames);
        const isRefused = m.verdict === 'refused';
        const isDelivered = m.verdict === 'delivered';
        const hasForwarded =
          Array.isArray(m.forwarded_from) && m.forwarded_from.length > 0;

        return (
          <div
            key={m.message_id}
            id={`msg-${m.message_id}`}
            className={`flex flex-col ${
              isRight ? 'items-end' : 'items-start'
            } max-w-full`}
          >
            {/* Header: Whole job shows "A → B", regular chat shows sender name and time */}
            <div className="flex items-center gap-2 mb-1 px-1 text-[12px] text-fg-3">
              <AgentRingAvatar
                agentId={m.from_agent}
                name={senderName}
                colourIndex={agentColourIndexes[m.from_agent]}
                size="sm"
              />
              {isWholeJob ? (
                <span className="font-medium text-fg">
                  {senderName} → {receiverName}
                </span>
              ) : (
                <span className="font-medium text-fg">{senderName}</span>
              )}
              <span className="text-fg-3">{localClock(m.sent_at)}</span>
            </div>

            {/* Message Bubble */}
            <div
              className={`rounded-2xl p-3.5 max-w-[85%] md:max-w-[75%] border transition-all ${
                isRight
                  ? 'bg-accent/10 border-accent/25 text-fg'
                  : 'bg-surface-2 border-line text-fg'
              } ${isRefused ? 'border-dashed border-bad/50 bg-bad/10' : ''}`}
            >
              {/* Forwarded from source chip: rounded-md, max 3 sources +N more, full list in title */}
              {hasForwarded && (
                <div
                  data-testid="forwarded-chip"
                  title={`Forwarded from: ${m.forwarded_from.join(', ')}`}
                  className="inline-flex items-center flex-wrap gap-1.5 px-2.5 py-1 mb-2 rounded-md text-[12px] font-mono bg-cyan/10 text-cyan border border-cyan/25 max-w-full"
                >
                  <CornerDownRight className="w-3.5 h-3.5 shrink-0" />
                  <span className="shrink-0">Forwarded from</span>
                  {m.forwarded_from.slice(0, 3).map((src, idx) => (
                    <span
                      key={idx}
                      className="truncate max-w-[160px] inline-block align-bottom"
                      title={src}
                    >
                      {src}
                      {idx < Math.min(3, m.forwarded_from.length) - 1 ||
                      m.forwarded_from.length > 3
                        ? ','
                        : ''}
                    </span>
                  ))}
                  {m.forwarded_from.length > 3 && (
                    <span className="shrink-0 font-semibold">
                      +{m.forwarded_from.length - 3} more
                    </span>
                  )}
                </div>
              )}

              {/* Private File chip: contains_private shows file name, content never */}
              {m.contains_private && (
                <div
                  data-testid="private-file-chip"
                  className="inline-flex items-center gap-1.5 px-2.5 py-0.5 mb-2 rounded-md text-[12px] font-mono bg-wait/15 text-wait-text border border-wait/30"
                >
                  <FileText className="w-3.5 h-3.5 shrink-0" />
                  <span>Private file: {m.text || 'Protected resource'}</span>
                </div>
              )}

              {/* Message text */}
              {!m.contains_private ? (
                <p className="m-0 text-[14px] leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere]">
                  {m.text}
                </p>
              ) : (
                <p className="m-0 text-[13px] text-fg-3 italic">
                  Content suppressed by boundary protection.
                </p>
              )}

              {/* Status / Verdict footer */}
              <div className="flex items-center gap-1.5 mt-2 pt-1.5 border-t border-line/60 text-[12px]">
                {isDelivered && (
                  <span className="text-ok font-semibold" title="Delivered">
                    ✓✓
                  </span>
                )}
                {isRefused && (
                  <span className="text-bad font-semibold" title="Refused">
                    ✕
                  </span>
                )}
                <span className={isRefused ? 'text-bad' : 'text-fg-3'}>
                  {isRefused
                    ? m.reason || 'Refused by task boundary'
                    : 'Delivered'}
                </span>
              </div>
            </div>
          </div>
        );
      })}

      {/* Inline Approvals in this chat */}
      {pendingApprovals.map(pa => (
        <InlineApprovalCard
          key={pa.request_id}
          approval={pa}
          canDecide={canDecide}
          onApprove={onApprove}
          onDeny={onDeny}
        />
      ))}
    </div>
  );
};
