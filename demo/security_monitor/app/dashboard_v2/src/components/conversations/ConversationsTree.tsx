import React, { useState } from 'react';
import { ConversationTreeNode, getAgentDisplayName } from '../../logic/conversations';
import { AgentRingAvatar } from './AgentAvatar';
import { ChevronDown, ChevronRight, MessageSquare } from 'lucide-react';

import { A2AAgent } from '../../types';

interface ConversationsTreeProps {
  tree: ConversationTreeNode;
  selectedId: string;
  onSelect: (id: string) => void;
  agentNames: Record<string, string>;
  agentColourIndexes: Record<string, number>;
  outsideAgents?: Record<string, A2AAgent>;
}

const statusConfig: Record<
  ConversationTreeNode['status'],
  { dot: string; label: string }
> = {
  working: { dot: 'bg-wait', label: 'working' },
  done: { dot: 'bg-ok', label: 'done' },
  'needs you': { dot: 'bg-wait animate-pulse', label: 'needs you' },
  refused: { dot: 'bg-bad', label: 'refused' },
};

export const ConversationsTree: React.FC<ConversationsTreeProps> = ({
  tree,
  selectedId,
  onSelect,
  agentNames,
  agentColourIndexes,
  outsideAgents = {},
}) => {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const toggle = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setCollapsed(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const renderNode = (node: ConversationTreeNode, depth: number = 0) => {
    const isSelected = selectedId === node.id;
    const isJob = node.id === 'job';
    const hasChildren = node.children.length > 0;
    const isCollapsed = collapsed[node.id];
    const cfg = statusConfig[node.status] || { dot: 'bg-fg-3', label: node.status };

    const nameA = getAgentDisplayName(node.agentA, agentNames);
    const nameB = getAgentDisplayName(node.agentB, agentNames);
    const outsidePeer = !isJob ? (outsideAgents[node.agentB] || outsideAgents[node.agentA]) : undefined;

    return (
      <div key={node.id} className="flex flex-col">
        <button
          type="button"
          id={`thread-${node.id}`}
          data-thread-id={node.id}
          aria-pressed={isSelected}
          onClick={() => onSelect(node.id)}
          className={`flex items-center gap-2.5 w-full text-left px-3 py-2.5 rounded-xl transition-colors cursor-pointer border ${
            isSelected
              ? 'bg-surface-3 border-line-strong text-fg shadow-sm'
              : 'bg-surface-1 border-transparent text-fg-2 hover:bg-surface-2 hover:text-fg'
          }`}
          style={{ paddingLeft: `${Math.max(12, depth * 16 + 12)}px` }}
        >
          {hasChildren ? (
            <span
              onClick={e => toggle(node.id, e)}
              className="p-0.5 rounded hover:bg-surface-2 text-fg-3 shrink-0"
              aria-label={isCollapsed ? 'Expand sub-chats' : 'Collapse sub-chats'}
            >
              {isCollapsed ? (
                <ChevronRight className="w-4 h-4" />
              ) : (
                <ChevronDown className="w-4 h-4" />
              )}
            </span>
          ) : depth > 0 ? (
            <span className="w-4 h-4 shrink-0" />
          ) : null}

          {isJob ? (
            <div className="w-8 h-8 rounded-full bg-accent/15 border border-accent/40 flex items-center justify-center shrink-0 text-accent">
              <MessageSquare className="w-4 h-4" />
            </div>
          ) : (
            <div className="flex items-center -space-x-2 shrink-0">
              <AgentRingAvatar
                agentId={node.agentA}
                name={nameA}
                colourIndex={agentColourIndexes[node.agentA]}
                size="sm"
              />
              <AgentRingAvatar
                agentId={node.agentB}
                name={nameB}
                colourIndex={agentColourIndexes[node.agentB]}
                size="sm"
              />
            </div>
          )}

          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-1">
              <span className="text-[14px] font-medium truncate">
                {isJob ? 'Whole job' : `${nameA} ↔ ${nameB}`}
              </span>
              <span className="text-[12px] font-mono text-fg-3 shrink-0">
                {node.messageCount}
              </span>
            </div>
            <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
              <span className={`w-2 h-2 rounded-full shrink-0 ${cfg.dot}`} />
              <span className="text-[12px] text-fg-3 capitalize">{cfg.label}</span>
              {outsidePeer && (
                <span
                  className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-surface-2 border border-line text-info"
                  data-badge="outside-a2a"
                >
                  outside agent (A2A)
                </span>
              )}
            </div>
          </div>
        </button>

        {hasChildren && !isCollapsed && (
          <div className="flex flex-col mt-0.5 space-y-0.5">
            {node.children.map(child => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-y-auto p-3 space-y-1">
        {renderNode(tree)}
      </div>

      {/* Key at bottom */}
      <div className="p-3 border-t border-line bg-surface-1 shrink-0 text-[12px] text-fg-3">
        <span className="font-semibold uppercase tracking-wider block mb-2 text-[11px]">
          Status key
        </span>
        <div className="grid grid-cols-2 gap-2">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-wait shrink-0" />
            <span>working</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-ok shrink-0" />
            <span>done</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-wait animate-pulse shrink-0" />
            <span>needs you</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-bad shrink-0" />
            <span>refused</span>
          </div>
        </div>
      </div>
    </div>
  );
};
