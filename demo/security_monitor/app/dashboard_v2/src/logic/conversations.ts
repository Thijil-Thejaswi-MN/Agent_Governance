import { A2AMessage, A2AThread, A2APendingApproval } from '../types';

export interface ConversationTreeNode {
  id: string; // 'job' or 'caller__callee'
  title: string;
  agentA: string; // from_agent or caller
  agentB: string; // to_agent or callee
  status: 'working' | 'done' | 'needs you' | 'refused';
  parentAgentId?: string | null;
  children: ConversationTreeNode[];
  messageCount: number;
}

/** Formats agent or host identifier into human-readable display name. */
export function getAgentDisplayName(
  agentOrHostId: string,
  agentNames: Record<string, string> = {}
): string {
  if (!agentOrHostId) return '';
  if (agentOrHostId === 'Web') return 'Web';
  if (agentOrHostId.startsWith('host:')) {
    const domain = agentOrHostId.slice(5);
    return `${domain} (website)`;
  }
  return agentNames[agentOrHostId] || agentOrHostId;
}

/** Determines thread status from its messages and pending approvals. */
export function getThreadStatus(
  messages: A2AMessage[],
  pendingApprovals: A2APendingApproval[],
  isTerminalJob: boolean
): 'working' | 'done' | 'needs you' | 'refused' {
  if (pendingApprovals.length > 0) {
    return 'needs you';
  }
  if (messages.some(m => m.verdict === 'refused')) {
    return 'refused';
  }
  if (!isTerminalJob) {
    return 'working';
  }
  return 'done';
}

/** Builds a conversation tree where a sub-chat sits under the agent that started it. */
export function buildConversationTree(
  threads: A2AThread[],
  messages: A2AMessage[],
  pendingApprovals: A2APendingApproval[],
  isTerminalJob: boolean,
  rootAgentId: string = 'planner',
  agentNames: Record<string, string> = {}
): ConversationTreeNode {
  // 1. Root job node
  const jobStatus = getThreadStatus(messages, pendingApprovals, isTerminalJob);
  const rootNode: ConversationTreeNode = {
    id: 'job',
    title: 'Whole job',
    agentA: rootAgentId,
    agentB: 'all',
    status: jobStatus,
    parentAgentId: null,
    children: [],
    messageCount: messages.length,
  };

  // 2. Identify pair threads (excluding the 'job' thread)
  const pairThreads = threads.filter(t => t.thread_id !== 'job');

  const pairNodes: Array<{
    node: ConversationTreeNode;
    initiator: string;
    responder: string;
  }> = [];

  for (const t of pairThreads) {
    const p1 = t.participants[0];
    const p2 = t.participants[1];
    const pairMsgs = messages.filter(
      m =>
        (m.from_agent === p1 && m.to_agent === p2) ||
        (m.from_agent === p2 && m.to_agent === p1)
    );

    // Initial message in this pair identifies the initiating agent
    const initialMsg = pairMsgs[0];
    const initiator = initialMsg ? initialMsg.from_agent : p1;
    const responder = initialMsg
      ? initialMsg.to_agent
      : p1 === initiator
      ? p2
      : p1;

    // Check approvals for this pair's participants
    const hasPendingForPair = pendingApprovals.some(pa => {
      return pairMsgs.some(
        m => m.child_task_id === pa.task_id || m.parent_task_id === pa.task_id
      );
    });

    const status = hasPendingForPair
      ? 'needs you'
      : getThreadStatus(pairMsgs, [], isTerminalJob);

    const nameA = getAgentDisplayName(initiator, agentNames);
    const nameB = getAgentDisplayName(responder, agentNames);

    pairNodes.push({
      node: {
        id: t.thread_id,
        title: `${nameA} ↔ ${nameB}`,
        agentA: initiator,
        agentB: responder,
        status,
        parentAgentId: initiator,
        children: [],
        messageCount: pairMsgs.length,
      },
      initiator,
      responder,
    });
  }

  // 3. Assemble tree: attach under initiating parent
  const topLevel: ConversationTreeNode[] = [];
  const byResponder = new Map<string, ConversationTreeNode>();

  for (const item of pairNodes) {
    byResponder.set(item.responder, item.node);
  }

  for (const item of pairNodes) {
    if (item.initiator === rootAgentId) {
      topLevel.push(item.node);
    } else {
      const parentNode = byResponder.get(item.initiator);
      if (parentNode) {
        parentNode.children.push(item.node);
      } else {
        topLevel.push(item.node);
      }
    }
  }

  rootNode.children = topLevel;
  return rootNode;
}

export interface ArrowLayout {
  fromIndex: number;
  toIndex: number;
  direction: 'left-to-right' | 'right-to-left';
  leftPercent: number;
  rightPercent: number;
  widthPercent: number;
}

/** Draws every arrow between the centres of two columns according to exact geometry specs. */
export function getArrowLayout(
  columns: string[],
  fromAgent: string,
  toAgent: string,
  isRefused: boolean = false
): ArrowLayout {
  const n = Math.max(columns.length, 1);
  const fromIndex = columns.indexOf(fromAgent);
  const toCol = toAgent.startsWith('host:') ? 'Web' : toAgent;
  const toIndex = columns.indexOf(toCol);

  const from = fromIndex >= 0 ? fromIndex : 0;
  const to = toIndex >= 0 ? toIndex : 0;

  const direction: 'left-to-right' | 'right-to-left' =
    from <= to ? 'left-to-right' : 'right-to-left';

  const minCol = Math.min(from, to);
  const maxCol = Math.max(from, to);

  // Column centre formulas:
  // left = (min(from,to) + 0.5) / n;
  // right = (n - 1 - max(from,to) + 0.5) / n;
  let leftFraction = (minCol + 0.5) / n;
  let rightFraction = (n - 1 - maxCol + 0.5) / n;

  // Refused arrows stop half a column before receiver centre, with ✕ there:
  if (isRefused) {
    if (direction === 'left-to-right') {
      rightFraction += 0.5 / n;
    } else {
      leftFraction += 0.5 / n;
    }
  }

  const leftPercent = leftFraction * 100;
  const rightPercent = rightFraction * 100;
  const widthPercent = (1 - leftFraction - rightFraction) * 100;

  return {
    fromIndex: from,
    toIndex: to,
    direction,
    leftPercent,
    rightPercent,
    widthPercent,
  };
}

/** Legacy wrapper providing arrow direction and span. */
export function getArrowSpan(
  columns: string[],
  fromAgent: string,
  toAgent: string
): {
  fromIndex: number;
  toIndex: number;
  direction: 'left-to-right' | 'right-to-left';
  span: number;
} {
  const layout = getArrowLayout(columns, fromAgent, toAgent, false);
  return {
    fromIndex: layout.fromIndex,
    toIndex: layout.toIndex,
    direction: layout.direction,
    span: Math.abs(layout.toIndex - layout.fromIndex),
  };
}

/** Computes timeline column order: root agent lead, other agents in order of earliest message, Web last. */
export function computeTimelineColumns(
  rootAgentId: string,
  messages: A2AMessage[],
  allAgents: string[]
): string[] {
  const ordered: string[] = [];
  const seen = new Set<string>();

  const lead = rootAgentId || 'planner';
  ordered.push(lead);
  seen.add(lead);
  seen.add('Web');

  for (const m of messages) {
    for (const a of [m.from_agent, m.to_agent]) {
      if (a && !a.startsWith('host:') && !seen.has(a)) {
        ordered.push(a);
        seen.add(a);
      }
    }
  }

  for (const a of allAgents) {
    if (a && a !== 'Web' && !seen.has(a)) {
      ordered.push(a);
      seen.add(a);
    }
  }

  ordered.push('Web');
  return ordered;
}

/** Counts only kind === "request" messages in the specified fanout group. */
export function countFanoutRequests(
  messages: A2AMessage[],
  fanoutGroup: string
): number {
  if (!fanoutGroup) return 0;
  return messages.filter(
    m => m.fanout_group === fanoutGroup && m.kind === 'request'
  ).length;
}

/** Formats arrow label according to specifications. */
export function formatArrowLabel(m: A2AMessage): string {
  if (m.verdict === 'refused') {
    return 'refused';
  }
  const isForwarded =
    Array.isArray(m.forwarded_from) && m.forwarded_from.length > 0;
  if (m.kind === 'reply') {
    return isForwarded ? 'reply · forwarded' : 'reply';
  }
  return 'request';
}

/** Formats fan-out tag: "⇉ X sent N at once". */
export function formatFanoutTag(agentName: string, count: number): string {
  return `⇉ ${agentName} sent ${count} at once`;
}

/** Checks whether user is the owner of the job or an admin. */
export function canDecideApproval(
  user: { name?: string; role?: string } | null,
  jobOwner: string | null | undefined
): boolean {
  if (!user) return false;
  if (user.role === 'admin') return true;
  if (jobOwner && user.name === jobOwner) return true;
  return false;
}
