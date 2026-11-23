import React from 'react';
import { A2AMessage, A2APendingApproval } from '../../types';
import { AgentRingAvatar } from './AgentAvatar';
import {
  formatArrowLabel,
  formatFanoutTag,
  getArrowSpan,
} from '../../logic/conversations';
import { localClock } from '../v3/TechnicalTimeline';
import { Lock, AlertCircle, Globe } from 'lucide-react';

interface WholeJobTimelineProps {
  agents: string[]; // List of agent IDs (columns), plus 'Web'
  messages: A2AMessage[];
  pendingApprovals: A2APendingApproval[];
  selectedThreadId: string;
  onSelectThreadForMessage: (m: A2AMessage) => void;
  agentNames: Record<string, string>;
  agentColourIndexes: Record<string, number>;
}

export const WholeJobTimeline: React.FC<WholeJobTimelineProps> = ({
  agents,
  messages,
  pendingApprovals,
  selectedThreadId,
  onSelectThreadForMessage,
  agentNames,
  agentColourIndexes,
}) => {
  // Build columns: agents in order, plus 'Web' column at the end
  const columns = [...agents.filter(a => a !== 'Web'), 'Web'];

  // Check if a message belongs to the selected thread
  const isMessageSelected = (m: A2AMessage) => {
    if (selectedThreadId === 'job') return true;
    const parts = selectedThreadId.split('__');
    if (parts.length === 2) {
      const [p1, p2] = parts;
      return (
        (m.from_agent === p1 && m.to_agent === p2) ||
        (m.from_agent === p2 && m.to_agent === p1)
      );
    }
    return false;
  };

  // Group messages into timeline items and detect fan-out headers
  // A fanout group tag is displayed above the first message of each fanout_group
  const renderedFanoutGroups = new Set<string>();

  return (
    <div className="flex flex-col h-full overflow-hidden bg-surface-1">
      {/* Column Headers */}
      <div className="overflow-x-auto border-b border-line bg-surface-2 shrink-0">
        <div
          className="grid gap-2 px-4 py-3 min-w-[640px]"
          style={{
            gridTemplateColumns: `repeat(${columns.length}, minmax(110px, 1fr))`,
          }}
        >
          {columns.map(col => {
            const isWeb = col === 'Web';
            const displayName = isWeb ? 'Web' : agentNames[col] || col;
            return (
              <div
                key={col}
                className="flex flex-col items-center text-center gap-1.5 min-w-0"
              >
                {isWeb ? (
                  <div className="w-8 h-8 rounded-full bg-surface-3 border border-line flex items-center justify-center text-fg-2">
                    <Globe className="w-4 h-4" />
                  </div>
                ) : (
                  <AgentRingAvatar
                    agentId={col}
                    name={displayName}
                    colourIndex={agentColourIndexes[col]}
                    size="md"
                  />
                )}
                <span className="text-[12px] font-medium text-fg truncate w-full">
                  {displayName}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Timeline Rows Area */}
      <div className="flex-1 overflow-x-auto overflow-y-auto p-4 space-y-4 min-w-0">
        <div
          className="min-w-[640px] space-y-3"
          style={{ position: 'relative' }}
        >
          {/* Vertical guideline tracks for each column */}
          <div
            className="absolute inset-0 grid gap-2 pointer-events-none"
            style={{
              gridTemplateColumns: `repeat(${columns.length}, minmax(110px, 1fr))`,
            }}
          >
            {columns.map(col => (
              <div key={col} className="flex justify-center h-full">
                <div className="w-px h-full bg-line/40" />
              </div>
            ))}
          </div>

          {/* Markers for private files and pending approvals */}
          {messages.some(m => m.contains_private) && (
            <div className="relative z-10 flex items-center justify-center gap-2 py-1.5 px-3 rounded-lg bg-surface-2 border border-wait/30 text-wait-text text-[12px] font-mono mx-auto max-w-fit">
              <Lock className="w-3.5 h-3.5" />
              <span>opened private file</span>
            </div>
          )}

          {pendingApprovals.length > 0 && (
            <div className="relative z-10 flex items-center justify-center gap-2 py-1.5 px-3 rounded-lg bg-wait/15 border border-wait/40 text-wait-text text-[12px] font-mono mx-auto max-w-fit">
              <AlertCircle className="w-3.5 h-3.5 animate-pulse" />
              <span>needs your OK</span>
            </div>
          )}

          {/* Render each message as an interactive timeline row */}
          {messages.map((m, index) => {
            const selected = isMessageSelected(m);
            const isRefused = m.verdict === 'refused';
            const label = formatArrowLabel(m);
            const spanInfo = getArrowSpan(columns, m.from_agent, m.to_agent);
            const fanoutGroup = m.fanout_group;
            const showFanoutTag =
              fanoutGroup && !renderedFanoutGroups.has(fanoutGroup);

            if (fanoutGroup) {
              renderedFanoutGroups.add(fanoutGroup);
            }

            const senderName = agentNames[m.from_agent] || m.from_agent;
            const receiverName = m.to_agent.startsWith('host:')
              ? 'Web'
              : agentNames[m.to_agent] || m.to_agent;

            // Compute fanout group count
            const fanoutCount = fanoutGroup
              ? messages.filter(msg => msg.fanout_group === fanoutGroup).length
              : 0;

            const ariaLabel = `${senderName} to ${receiverName} at ${localClock(
              m.sent_at
            )}, ${m.verdict}`;

            return (
              <div key={m.message_id} className="relative z-10 flex flex-col gap-1">
                {/* Fanout header if new group */}
                {showFanoutTag && (
                  <div
                    data-testid="fanout-tag"
                    className="self-center px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-accent/15 text-accent border border-accent/30 my-1"
                  >
                    {formatFanoutTag(senderName, fanoutCount)}
                  </div>
                )}

                <button
                  type="button"
                  id={`timeline-row-${m.message_id}`}
                  data-testid="timeline-row"
                  data-from={m.from_agent}
                  data-to={m.to_agent}
                  data-verdict={m.verdict}
                  aria-label={ariaLabel}
                  onClick={() => onSelectThreadForMessage(m)}
                  className={`group w-full py-2 px-1 text-left rounded-lg transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                    selected
                      ? 'opacity-100 bg-surface-2/60'
                      : 'opacity-40 hover:opacity-75'
                  }`}
                >
                  <div
                    className="grid gap-2 items-center"
                    style={{
                      gridTemplateColumns: `repeat(${columns.length}, minmax(110px, 1fr))`,
                    }}
                  >
                    {/* The arrow graphic stretches across columns from sender to receiver */}
                    <div
                      className="col-span-full relative h-7 flex items-center"
                      style={{
                        paddingLeft: `${(spanInfo.fromIndex / columns.length) * 100}%`,
                        paddingRight: `${
                          ((columns.length - 1 - spanInfo.toIndex) /
                            columns.length) *
                          100
                        }%`,
                      }}
                    >
                      {/* Arrow Container */}
                      <div className="relative w-full flex items-center justify-between">
                        {/* Dot at tail */}
                        <div
                          className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                            isRefused ? 'bg-bad' : 'bg-accent'
                          }`}
                        />

                        {/* Line with label */}
                        <div className="flex-1 relative flex items-center justify-center mx-1">
                          <div
                            className={`w-full h-0.5 ${
                              isRefused
                                ? 'border-b-2 border-dashed border-bad'
                                : 'bg-accent'
                            }`}
                          />
                          <span
                            className={`absolute -top-3.5 px-1.5 py-0.2 rounded text-[10px] font-mono tracking-tight whitespace-nowrap bg-surface-1 border ${
                              isRefused
                                ? 'border-bad/40 text-bad font-semibold'
                                : 'border-line text-fg-3'
                            }`}
                          >
                            {label}
                          </span>
                        </div>

                        {/* Head or ✕ */}
                        {isRefused ? (
                          <div
                            data-testid="refused-x"
                            className="w-4 h-4 rounded-full bg-bad text-surface-1 font-bold text-[11px] flex items-center justify-center shrink-0"
                            title="Refused by boundary"
                          >
                            ✕
                          </div>
                        ) : spanInfo.direction === 'left-to-right' ? (
                          <div className="w-0 h-0 border-y-[4px] border-y-transparent border-l-[6px] border-l-accent shrink-0" />
                        ) : (
                          <div className="w-0 h-0 border-y-[4px] border-y-transparent border-r-[6px] border-r-accent shrink-0" />
                        )}
                      </div>
                    </div>
                  </div>
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
