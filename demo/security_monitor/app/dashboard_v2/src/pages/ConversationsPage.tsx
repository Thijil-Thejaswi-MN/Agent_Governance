import React, { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import {
  A2AJobResponse,
  A2AMessage,
  A2APendingApproval,
} from '../types';
import {
  buildConversationTree,
  canDecideApproval,
} from '../logic/conversations';
import { ConversationsTree } from '../components/conversations/ConversationsTree';
import { ChatMessages } from '../components/conversations/ChatMessages';
import { WholeJobTimeline } from '../components/conversations/WholeJobTimeline';
import { Button } from '../components/ui/Button';
import { MessageSquare, Users, ShieldAlert, AlertCircle, StopCircle, ArrowLeft } from 'lucide-react';

export const ConversationsPage: React.FC = () => {
  const { rootTaskId } = useParams<{ rootTaskId: string }>();
  const navigate = useNavigate();
  const { user, hasToken, openAuthModal } = useAuth();

  const [job, setJob] = useState<A2AJobResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreadId, setSelectedThreadId] = useState<string>('job');
  const [stopping, setStopping] = useState(false);
  const [stopMessage, setStopMessage] = useState<string | null>(null);

  // Responsive active panel for mobile viewport: 'chats' | 'conversation' | 'timeline'
  const [mobileTab, setMobileTab] = useState<'chats' | 'conversation' | 'timeline'>('conversation');

  // Load initial A2A job data
  const loadJob = async () => {
    if (!rootTaskId) return;
    try {
      const data = await api.getA2AJob(rootTaskId);
      setJob(data);
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Could not load conversation data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadJob();
  }, [rootTaskId]);

  // Connect live SSE stream
  useEffect(() => {
    if (!rootTaskId) return;
    const streamUrl = api.getA2AJobStreamUrl(rootTaskId);
    const es = new EventSource(streamUrl);

    es.onmessage = (event) => {
      try {
        const newMsg: A2AMessage = JSON.parse(event.data);
        setJob((prev) => {
          if (!prev) return prev;
          const exists = prev.messages.some((m) => m.message_id === newMsg.message_id);
          if (exists) return prev;
          return {
            ...prev,
            messages: [...prev.messages, newMsg],
          };
        });
      } catch {
        // quiet parse error
      }
    };

    es.addEventListener('end', () => {
      // Re-fetch final job state
      loadJob();
      es.close();
    });

    es.onerror = () => {
      es.close();
    };

    return () => {
      es.close();
    };
  }, [rootTaskId]);

  // Periodic poll while active or awaiting decision
  useEffect(() => {
    if (!rootTaskId) return;
    if (job && job.status !== 'active' && job.status !== 'pending_approval') {
      return;
    }
    const timer = setInterval(() => {
      loadJob();
    }, 1500);
    return () => clearInterval(timer);
  }, [rootTaskId, job?.status]);

  // Compute lookup tables
  const agentNames = useMemo(() => {
    const res: Record<string, string> = {};
    if (job?.agents) {
      for (const a of job.agents) {
        res[a.id] = a.name;
      }
    }
    return res;
  }, [job?.agents]);

  const agentColourIndexes = useMemo(() => {
    const res: Record<string, number> = {};
    if (job?.agents) {
      for (const a of job.agents) {
        res[a.id] = a.colour_index;
      }
    }
    return res;
  }, [job?.agents]);

  // Counts for the header
  const counts = useMemo(() => {
    const agentCount = job?.agents.length || 0;
    const messageCount = job?.messages.length || 0;
    const refusedCount = (job?.messages || []).filter((m) => m.verdict === 'refused').length;
    const needsYouCount = job?.pending_approvals.length || 0;
    return {
      agents: agentCount,
      messages: messageCount,
      refused: refusedCount,
      needsYou: needsYouCount,
    };
  }, [job]);

  // Filter messages for current thread
  const currentMessages = useMemo(() => {
    if (!job) return [];
    if (selectedThreadId === 'job') {
      return job.messages;
    }
    const parts = selectedThreadId.split('__');
    if (parts.length === 2) {
      const [p1, p2] = parts;
      return job.messages.filter(
        (m) =>
          (m.from_agent === p1 && m.to_agent === p2) ||
          (m.from_agent === p2 && m.to_agent === p1)
      );
    }
    return [];
  }, [job, selectedThreadId]);

  // Approvals for current thread
  const currentApprovals = useMemo(() => {
    if (!job) return [];
    if (selectedThreadId === 'job') {
      return job.pending_approvals;
    }
    // Pair chat: filter approvals where the task corresponds to this pair
    return job.pending_approvals.filter((pa) => {
      const isAgentInvolved = !!(
        pa.agent_id && selectedThreadId.split('__').includes(pa.agent_id)
      );
      return (
        isAgentInvolved ||
        currentMessages.some(
          (m) => m.child_task_id === pa.task_id || m.parent_task_id === pa.task_id
        )
      );
    });
  }, [job, selectedThreadId, currentMessages]);

  // Build tree
  const conversationTree = useMemo(() => {
    if (!job) return null;
    const isTerminal = job.status !== 'active' && job.status !== 'pending_approval';
    return buildConversationTree(
      job.threads,
      job.messages,
      job.pending_approvals,
      isTerminal,
      job.task?.agent_id || 'planner'
    );
  }, [job]);

  // Stop job
  const handleStop = async () => {
    if (!rootTaskId) return;
    if (!hasToken) {
      openAuthModal();
      return;
    }
    setStopping(true);
    setStopMessage(null);
    try {
      const res = await api.stopRun(rootTaskId);
      setStopMessage(res.message || 'Job stopped.');
      loadJob();
    } catch (err: any) {
      setStopMessage(err.message || 'Could not stop job.');
    } finally {
      setStopping(false);
    }
  };

  // Inline approval handlers
  const canDecide = canDecideApproval(user, job?.task?.owner);

  const handleApprove = async (requestId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    await api.approveExpansion(requestId, {
      decided_by: user?.name || 'operator',
      scope: 'run',
    });
    await loadJob();
  };

  const handleDeny = async (requestId: string, reason: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    await api.denyExpansion(requestId, {
      decided_by: user?.name || 'operator',
      reason,
    });
    await loadJob();
  };

  const handleSelectThreadForMessage = (m: A2AMessage) => {
    const key = [m.from_agent, m.to_agent].sort().join('__');
    setSelectedThreadId(key);
    setMobileTab('conversation');
  };

  if (loading && !job) {
    return (
      <div className="flex items-center justify-center min-h-[350px] text-[15px] text-fg-3">
        Loading conversations…
      </div>
    );
  }

  if (error || !job) {
    return (
      <div className="max-w-[800px] mx-auto py-12 flex flex-col items-center gap-4 text-center">
        <AlertCircle className="w-10 h-10 text-bad" />
        <h2 className="text-[20px] font-semibold text-fg">Conversation View Unavailable</h2>
        <p className="text-fg-2 text-[15px] max-w-md">{error || 'Job not found.'}</p>
        <Button variant="secondary" onClick={() => navigate('/history')}>
          Back to past runs
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] min-h-[600px] -mx-4 -my-6 md:-m-8">
      {/* 1. Header */}
      <header className="px-6 py-4 border-b border-line bg-surface-1 shrink-0 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0">
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => navigate(-1)}
            aria-label="Back"
            className="mt-1"
          >
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div className="min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-[18px] md:text-[20px] font-serif font-normal m-0 text-fg">
                {agentNames[job.task?.agent_id || ''] || 'Agent'} conversations
              </h1>
              <span className="text-[12px] font-mono px-2 py-0.5 rounded-full bg-surface-2 border border-line text-fg-2">
                {job.root_task_id}
              </span>
            </div>
            <p id="request-text" className="text-[14px] text-fg-2 m-0 mt-1 truncate max-w-2xl" title={job.task?.request_text}>
              {job.task?.request_text || 'No request text recorded.'}
            </p>
          </div>
        </div>

        {/* Counts & Action */}
        <div className="flex items-center gap-4 flex-wrap shrink-0">
          <div className="flex items-center gap-4 text-[13px] font-medium text-fg-2">
            <div className="flex items-center gap-1.5" title="Participating agents">
              <Users className="w-4 h-4 text-accent" />
              <span>{counts.agents} agents</span>
            </div>
            <div className="flex items-center gap-1.5" title="Messages sent">
              <MessageSquare className="w-4 h-4 text-fg-2" />
              <span>{counts.messages} msgs</span>
            </div>
            {counts.refused > 0 && (
              <div className="flex items-center gap-1.5 text-bad font-semibold" title="Refused messages">
                <ShieldAlert className="w-4 h-4" />
                <span>{counts.refused} refused</span>
              </div>
            )}
            {counts.needsYou > 0 && (
              <div className="flex items-center gap-1.5 text-wait font-semibold animate-pulse" title="Decisions waiting">
                <AlertCircle className="w-4 h-4" />
                <span>{counts.needsYou} needs you</span>
              </div>
            )}
          </div>

          <Button
            variant="danger"
            size="md"
            disabled={stopping || job.status === 'finished'}
            onClick={handleStop}
            className="gap-2"
          >
            <StopCircle className="w-4 h-4" />
            <span>Stop job</span>
          </Button>
        </div>
      </header>

      {stopMessage && (
        <div className="px-6 py-2 bg-bad/15 border-b border-bad/30 text-bad text-[13px]">
          {stopMessage}
        </div>
      )}

      {/* Mobile Tab Switcher */}
      <div className="flex md:hidden border-b border-line bg-surface-2 shrink-0">
        <button
          type="button"
          id="mobile-tab-chats"
          onClick={() => setMobileTab('chats')}
          className={`flex-1 py-2.5 text-[14px] font-medium text-center border-b-2 transition-colors ${
            mobileTab === 'chats'
              ? 'border-accent text-fg bg-surface-1'
              : 'border-transparent text-fg-3 hover:text-fg'
          }`}
        >
          Chats
        </button>
        <button
          type="button"
          id="mobile-tab-conversation"
          onClick={() => setMobileTab('conversation')}
          className={`flex-1 py-2.5 text-[14px] font-medium text-center border-b-2 transition-colors ${
            mobileTab === 'conversation'
              ? 'border-accent text-fg bg-surface-1'
              : 'border-transparent text-fg-3 hover:text-fg'
          }`}
        >
          Conversation
        </button>
        <button
          type="button"
          id="mobile-tab-timeline"
          onClick={() => setMobileTab('timeline')}
          className={`flex-1 py-2.5 text-[14px] font-medium text-center border-b-2 transition-colors ${
            mobileTab === 'timeline'
              ? 'border-accent text-fg bg-surface-1'
              : 'border-transparent text-fg-3 hover:text-fg'
          }`}
        >
          Timeline
        </button>
      </div>

      {/* 3-Panel Main Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Panel 1: Left, Conversations Tree */}
        <section
          aria-label="Conversations"
          className={`w-full md:w-72 lg:w-80 border-r border-line bg-surface-1 flex-col shrink-0 ${
            mobileTab === 'chats' ? 'flex' : 'hidden md:flex'
          }`}
        >
          {conversationTree && (
            <ConversationsTree
              tree={conversationTree}
              selectedId={selectedThreadId}
              onSelect={(id) => {
                setSelectedThreadId(id);
                setMobileTab('conversation');
              }}
              agentNames={agentNames}
              agentColourIndexes={agentColourIndexes}
            />
          )}
        </section>

        {/* Panel 2: Middle, Selected Conversation */}
        <section
          aria-label="Selected Conversation"
          className={`w-full md:flex-1 border-r border-line bg-bg flex-col min-w-0 ${
            mobileTab === 'conversation' ? 'flex' : 'hidden md:flex'
          }`}
        >
          {/* Active Chat Header */}
          <div className="px-5 py-3 border-b border-line bg-surface-1 shrink-0 flex items-center justify-between">
            <span className="text-[14px] font-semibold text-fg">
              {selectedThreadId === 'job'
                ? 'Whole job messages'
                : selectedThreadId.replace('__', ' ↔ ')}
            </span>
            <span className="text-[12px] text-fg-3 font-mono">
              {currentMessages.length} {currentMessages.length === 1 ? 'message' : 'messages'}
            </span>
          </div>

          <ChatMessages
            threadId={selectedThreadId}
            messages={currentMessages}
            pendingApprovals={currentApprovals}
            agentNames={agentNames}
            agentColourIndexes={agentColourIndexes}
            canDecide={canDecide}
            onApprove={handleApprove}
            onDeny={handleDeny}
          />
        </section>

        {/* Panel 3: Right, Timeline of the Whole Job */}
        <section
          aria-label="Whole Job Timeline"
          className={`w-full md:w-[380px] lg:w-[480px] xl:w-[540px] bg-surface-1 flex-col shrink-0 ${
            mobileTab === 'timeline' ? 'flex' : 'hidden md:flex'
          }`}
        >
          <div className="px-4 py-3 border-b border-line bg-surface-2 shrink-0 flex items-center justify-between">
            <span className="text-[13px] font-semibold uppercase tracking-wider text-fg-3">
              Job timeline
            </span>
            <span className="text-[12px] text-fg-3">
              Click row to open chat
            </span>
          </div>

          <WholeJobTimeline
            agents={job.agents.map((a) => a.id)}
            messages={job.messages}
            pendingApprovals={job.pending_approvals}
            selectedThreadId={selectedThreadId}
            onSelectThreadForMessage={handleSelectThreadForMessage}
            agentNames={agentNames}
            agentColourIndexes={agentColourIndexes}
          />
        </section>
      </div>
    </div>
  );
};
