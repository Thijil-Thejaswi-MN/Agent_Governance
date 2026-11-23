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
  rootAgentId: string = 'planner'
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

  // To build the hierarchy: for each pair thread, identify who initiated the interaction.
  // The first request message in that pair determines who started it.
  const pairNodes: Array<{
    node: ConversationTreeNode;
    initiator: string;
    responder: string;
  }> = [];

  for (const t of pairThreads) {
    // Filter messages for this pair
    const p1 = t.participants[0];
    const p2 = t.participants[1];
    const pairMsgs = messages.filter(
      m =>
        (m.from_agent === p1 && m.to_agent === p2) ||
        (m.from_agent === p2 && m.to_agent === p1)
    );
    const pairApprovals = pendingApprovals.filter(p => {
      // Find tasks related to pair
      return false; // filtered specifically if task_id matches
    });

    // Check who sent the first message
    const firstMsg = pairMsgs[0];
    const initiator = firstMsg ? firstMsg.from_agent : p1;
    const responder = firstMsg
      ? firstMsg.to_agent
      : p1 === initiator
      ? p2
      : p1;

    // Check approvals for this pair's participants
    const hasPendingForPair = pendingApprovals.some(pa => {
      // If task_id matches child_task_id of any request to/from this pair
      return pairMsgs.some(
        m => m.child_task_id === pa.task_id || m.parent_task_id === pa.task_id
      );
    });

    const status = hasPendingForPair
      ? 'needs you'
      : getThreadStatus(pairMsgs, [], isTerminalJob);

    pairNodes.push({
      node: {
        id: t.thread_id,
        title: `${initiator} ↔ ${responder}`,
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

  // 3. Assemble tree: if initiator is the root agent, it attaches directly to rootNode.
  // If initiator was a child agent called by another agent, nest under that initiator's node.
  const topLevel: ConversationTreeNode[] = [];
  const byResponder = new Map<string, ConversationTreeNode>();

  for (const item of pairNodes) {
    byResponder.set(item.responder, item.node);
  }

  for (const item of pairNodes) {
    if (item.initiator === rootAgentId) {
      topLevel.push(item.node);
    } else {
      // Sub-chat: find parent thread whose responder is this initiator
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

/** Computes arrow direction and span for the timeline visualization. */
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
  const fromIndex = columns.indexOf(fromAgent);
  const toCol = toAgent.startsWith('host:') ? 'Web' : toAgent;
  const toIndex = columns.indexOf(toCol);

  const direction =
    fromIndex <= toIndex ? 'left-to-right' : 'right-to-left';
  const span = Math.abs(toIndex - fromIndex);

  return {
    fromIndex: fromIndex >= 0 ? fromIndex : 0,
    toIndex: toIndex >= 0 ? toIndex : 0,
    direction,
    span,
  };
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
