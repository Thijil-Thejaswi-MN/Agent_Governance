import { describe, it, expect } from 'vitest';
import {
  buildConversationTree,
  getThreadStatus,
  getArrowSpan,
  getArrowLayout,
  computeTimelineColumns,
  countFanoutRequests,
  getAgentDisplayName,
  formatArrowLabel,
  formatFanoutTag,
  canDecideApproval,
} from './conversations';
import { A2AMessage, A2AThread, A2APendingApproval } from '../types';

describe('conversations logic', () => {
  const sampleMessages: A2AMessage[] = [
    {
      message_id: 'm1',
      root_task_id: 'root_1',
      parent_task_id: 'root_1',
      child_task_id: 'child_res',
      from_agent: 'planner',
      to_agent: 'researcher',
      kind: 'request',
      fanout_group: 'grp_fanout_1',
      reply_to: null,
      sent_at: '2026-11-24T00:00:01Z',
      text: 'Research attractions',
      verdict: 'delivered',
      reason: null,
      integrity: 'int_1',
      forwarded_from: [],
      contains_private: false,
    },
    {
      message_id: 'm2',
      root_task_id: 'root_1',
      parent_task_id: 'root_1',
      child_task_id: 'child_bud',
      from_agent: 'planner',
      to_agent: 'budget',
      kind: 'request',
      fanout_group: 'grp_fanout_1',
      reply_to: null,
      sent_at: '2026-11-24T00:00:01Z',
      text: 'Calculate budget',
      verdict: 'delivered',
      reason: null,
      integrity: 'int_2',
      forwarded_from: [],
      contains_private: false,
    },
    {
      message_id: 'm3',
      root_task_id: 'root_1',
      parent_task_id: 'root_1',
      child_task_id: 'child_book',
      from_agent: 'planner',
      to_agent: 'booking',
      kind: 'request',
      fanout_group: 'grp_fanout_1',
      reply_to: null,
      sent_at: '2026-11-24T00:00:01Z',
      text: 'Arrange hotel',
      verdict: 'delivered',
      reason: null,
      integrity: 'int_3',
      forwarded_from: [],
      contains_private: false,
    },
    {
      message_id: 'm4',
      root_task_id: 'root_1',
      parent_task_id: 'child_book',
      child_task_id: null,
      from_agent: 'booking',
      to_agent: 'payment',
      kind: 'request',
      fanout_group: null,
      reply_to: null,
      sent_at: '2026-11-24T00:00:02Z',
      text: 'Process payment',
      verdict: 'refused',
      reason: 'unlisted peer agent: payment',
      integrity: 'int_4',
      forwarded_from: [],
      contains_private: false,
    },
    {
      message_id: 'm5',
      root_task_id: 'root_1',
      parent_task_id: 'child_res',
      child_task_id: null,
      from_agent: 'researcher',
      to_agent: 'planner',
      kind: 'reply',
      fanout_group: 'grp_fanout_1', // Even if reply carries group, only request counts
      reply_to: 'm1',
      sent_at: '2026-11-24T00:00:03Z',
      text: 'Attraction recommendations',
      verdict: 'delivered',
      reason: null,
      integrity: 'int_5',
      forwarded_from: ['host:127.0.0.1:8765'],
      contains_private: false,
    },
  ];

  const sampleThreads: A2AThread[] = [
    {
      thread_id: 'job',
      title: 'Entire Job',
      participants: ['planner', 'researcher', 'budget', 'booking', 'payment'],
      message_count: 5,
      status: 'active',
    },
    {
      thread_id: 'planner__researcher',
      title: 'planner <-> researcher',
      participants: ['planner', 'researcher'],
      message_count: 2,
      status: 'delivered',
    },
    {
      thread_id: 'budget__planner',
      title: 'budget <-> planner',
      participants: ['budget', 'planner'],
      message_count: 1,
      status: 'delivered',
    },
    {
      thread_id: 'booking__planner',
      title: 'booking <-> planner',
      participants: ['booking', 'planner'],
      message_count: 1,
      status: 'delivered',
    },
    {
      thread_id: 'booking__payment',
      title: 'booking <-> payment',
      participants: ['booking', 'payment'],
      message_count: 1,
      status: 'refused',
    },
  ];

  const sampleApprovals: A2APendingApproval[] = [
    {
      request_id: 'exp_req_1',
      task_id: 'child_res',
      agent_id: 'researcher',
      resource_type: 'file_read',
      resource_target: 'input/travel_history.csv',
      justification: 'Travel pattern analysis',
      status: 'PENDING',
    },
  ];

  it('tree building: nests sub-chats under the agent that initiated them', () => {
    const tree = buildConversationTree(
      sampleThreads,
      sampleMessages,
      sampleApprovals,
      false,
      'planner',
      { planner: 'Trip Planner', researcher: 'Researcher Agent', booking: 'Booking Agent' }
    );

    expect(tree.id).toBe('job');
    expect(tree.title).toBe('Whole job');
    expect(tree.status).toBe('needs you');

    const childIds = tree.children.map(c => c.id);
    expect(childIds).toContain('planner__researcher');
    expect(childIds).toContain('budget__planner');
    expect(childIds).toContain('booking__planner');

    const bookingNode = tree.children.find(c => c.id === 'booking__planner');
    expect(bookingNode).toBeDefined();
    expect(bookingNode?.children.map(c => c.id)).toContain('booking__payment');
  });

  it('thread status from verdicts and pending approvals', () => {
    expect(getThreadStatus(sampleMessages, sampleApprovals, false)).toBe('needs you');
    expect(getThreadStatus(sampleMessages, [], false)).toBe('refused');

    const deliveredMsgs = sampleMessages.filter(m => m.verdict === 'delivered');
    expect(getThreadStatus(deliveredMsgs, [], false)).toBe('working');
    expect(getThreadStatus(deliveredMsgs, [], true)).toBe('done');
  });

  it('arrow direction and span computation across columns', () => {
    const columns = ['planner', 'researcher', 'budget', 'booking', 'payment', 'Web'];

    const span1 = getArrowSpan(columns, 'planner', 'booking');
    expect(span1.fromIndex).toBe(0);
    expect(span1.toIndex).toBe(3);
    expect(span1.direction).toBe('left-to-right');
    expect(span1.span).toBe(3);

    const span2 = getArrowSpan(columns, 'researcher', 'planner');
    expect(span2.fromIndex).toBe(1);
    expect(span2.toIndex).toBe(0);
    expect(span2.direction).toBe('right-to-left');
    expect(span2.span).toBe(1);

    const span3 = getArrowSpan(columns, 'planner', 'host:gion-maru-travel.example');
    expect(span3.fromIndex).toBe(0);
    expect(span3.toIndex).toBe(5);
    expect(span3.direction).toBe('left-to-right');
    expect(span3.span).toBe(5);
  });

  it('timeline arrows: right-to-left and left-to-right have equal positive width; adjacent columns too', () => {
    const columns = ['planner', 'researcher', 'budget', 'booking', 'Web'];
    const n = columns.length; // 5

    // Adjacent columns: planner (0) to researcher (1)
    const lrAdjacent = getArrowLayout(columns, 'planner', 'researcher');
    const rlAdjacent = getArrowLayout(columns, 'researcher', 'planner');

    expect(lrAdjacent.widthPercent).toBeGreaterThan(0);
    expect(rlAdjacent.widthPercent).toBeGreaterThan(0);
    expect(lrAdjacent.widthPercent).toBeCloseTo(rlAdjacent.widthPercent, 5);
    // Exact adjacent width: (1 - 0) / 5 = 20%
    expect(lrAdjacent.widthPercent).toBeCloseTo(20, 5);
    expect(lrAdjacent.leftPercent).toBeCloseTo(10, 5); // (0 + 0.5) / 5 * 100 = 10%
    expect(lrAdjacent.rightPercent).toBeCloseTo(70, 5); // (5 - 1 - 1 + 0.5) / 5 * 100 = 70%

    // Multi-column span: planner (0) to booking (3)
    const lrMulti = getArrowLayout(columns, 'planner', 'booking');
    const rlMulti = getArrowLayout(columns, 'booking', 'planner');

    expect(lrMulti.widthPercent).toBeGreaterThan(0);
    expect(rlMulti.widthPercent).toBeGreaterThan(0);
    expect(lrMulti.widthPercent).toBeCloseTo(rlMulti.widthPercent, 5);
    // Span = 3, so width = 3 / 5 = 60%
    expect(lrMulti.widthPercent).toBeCloseTo(60, 5);

    // Refused arrow stops half a column before receiver centre
    const refusedLR = getArrowLayout(columns, 'planner', 'booking', true);
    expect(refusedLR.widthPercent).toBeCloseTo(50, 5); // 60% - 0.5/5*100 = 50%
  });

  it('column order: root task agent lead, then other agents in order of earliest message, Web last', () => {
    const allAgents = ['payment', 'booking', 'budget', 'researcher', 'planner'];
    const ordered = computeTimelineColumns('planner', sampleMessages, allAgents);

    // Planner lead
    expect(ordered[0]).toBe('planner');
    // Web last
    expect(ordered[ordered.length - 1]).toBe('Web');
    // Researcher appeared earliest (m1), then budget (m2), then booking (m3), then payment (m4)
    expect(ordered).toEqual(['planner', 'researcher', 'budget', 'booking', 'payment', 'Web']);
  });

  it('fanout tag counts only kind === "request" messages', () => {
    // sampleMessages has 3 requests and 1 reply with fanout_group = 'grp_fanout_1'
    const count = countFanoutRequests(sampleMessages, 'grp_fanout_1');
    expect(count).toBe(3);
    expect(formatFanoutTag('Planner', count)).toBe('⇉ Planner sent 3 at once');
  });

  it('agent display name formats host names as domain (website)', () => {
    const names = { planner: 'Trip Planner', researcher: 'Research Bot' };
    expect(getAgentDisplayName('planner', names)).toBe('Trip Planner');
    expect(getAgentDisplayName('unknown', names)).toBe('unknown');
    expect(getAgentDisplayName('host:gion-maru.example', names)).toBe('gion-maru.example (website)');
    expect(getAgentDisplayName('Web', names)).toBe('Web');
  });

  it('forwarded and private label determinations', () => {
    const forwardedMsg: A2AMessage = {
      ...sampleMessages[4],
      forwarded_from: ['notes_bot'],
    };
    expect(formatArrowLabel(forwardedMsg)).toBe('reply · forwarded');

    const normalReply: A2AMessage = {
      ...sampleMessages[4],
      forwarded_from: [],
    };
    expect(formatArrowLabel(normalReply)).toBe('reply');
    expect(formatArrowLabel(sampleMessages[0])).toBe('request');
    expect(formatArrowLabel(sampleMessages[3])).toBe('refused');
  });

  it('approval buttons only for the task owner or admin', () => {
    const jobOwner = 'alice';
    expect(canDecideApproval(null, jobOwner)).toBe(false);
    expect(canDecideApproval({ name: 'bob', role: 'developer' }, jobOwner)).toBe(false);
    expect(canDecideApproval({ name: 'alice', role: 'developer' }, jobOwner)).toBe(true);
    expect(canDecideApproval({ name: 'admin_user', role: 'admin' }, jobOwner)).toBe(true);
  });
});
