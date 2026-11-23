import { describe, it, expect } from 'vitest';
import {
  buildConversationTree,
  getThreadStatus,
  getArrowSpan,
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
      fanout_group: null,
      reply_to: 'm1',
      sent_at: '2026-11-24T00:00:03Z',
      text: 'Attraction recommendations',
      verdict: 'delivered',
      reason: null,
      integrity: 'int_5',
      forwarded_from: ['notes_bot'],
      contains_private: false,
    },
  ];

  const sampleThreads: A2AThread[] = [
    {
      thread_id: 'job',
      title: 'Entire Job',
      participants: ['planner', 'researcher', 'budget', 'booking', 'payment'],
      message_count: 5,
      status: 'refused',
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
      request_id: 'appr_1',
      task_id: 'child_res',
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
      'planner'
    );

    expect(tree.id).toBe('job');
    expect(tree.title).toBe('Whole job');
    // Whole job has pending approval, so status is 'needs you'
    expect(tree.status).toBe('needs you');

    // Children under planner: researcher, budget, booking
    const childIds = tree.children.map(c => c.id);
    expect(childIds).toContain('planner__researcher');
    expect(childIds).toContain('budget__planner');
    expect(childIds).toContain('booking__planner');

    // The sub-chat booking__payment should be nested under booking__planner
    const bookingNode = tree.children.find(c => c.id === 'booking__planner');
    expect(bookingNode).toBeDefined();
    expect(bookingNode?.children.map(c => c.id)).toContain('booking__payment');
  });

  it('thread status from verdicts and pending approvals', () => {
    // 1. Thread with pending approvals -> needs you
    expect(getThreadStatus(sampleMessages, sampleApprovals, false)).toBe('needs you');

    // 2. Thread with refusal and no approvals -> refused
    expect(getThreadStatus(sampleMessages, [], false)).toBe('refused');

    // 3. Delivered messages on active job -> working
    const deliveredMsgs = sampleMessages.filter(m => m.verdict === 'delivered');
    expect(getThreadStatus(deliveredMsgs, [], false)).toBe('working');

    // 4. Delivered messages on finished job -> done
    expect(getThreadStatus(deliveredMsgs, [], true)).toBe('done');
  });

  it('arrow direction and span computation across columns', () => {
    const columns = ['planner', 'researcher', 'budget', 'booking', 'payment', 'Web'];

    // Left to right: planner (0) to booking (3)
    const span1 = getArrowSpan(columns, 'planner', 'booking');
    expect(span1.fromIndex).toBe(0);
    expect(span1.toIndex).toBe(3);
    expect(span1.direction).toBe('left-to-right');
    expect(span1.span).toBe(3);

    // Right to left: researcher (1) to planner (0)
    const span2 = getArrowSpan(columns, 'researcher', 'planner');
    expect(span2.fromIndex).toBe(1);
    expect(span2.toIndex).toBe(0);
    expect(span2.direction).toBe('right-to-left');
    expect(span2.span).toBe(1);

    // Outbound web destination: planner (0) to host:... -> Web (5)
    const span3 = getArrowSpan(columns, 'planner', 'host:gion-maru-travel.example');
    expect(span3.fromIndex).toBe(0);
    expect(span3.toIndex).toBe(5);
    expect(span3.direction).toBe('left-to-right');
    expect(span3.span).toBe(5);
  });

  it('the fan-out tag formatting', () => {
    expect(formatFanoutTag('Planner', 3)).toBe('⇉ Planner sent 3 at once');
    expect(formatFanoutTag('Booking', 2)).toBe('⇉ Booking sent 2 at once');
  });

  it('forwarded and private label determinations', () => {
    // Forwarded reply
    const forwardedMsg: A2AMessage = {
      ...sampleMessages[4],
      forwarded_from: ['notes_bot'],
    };
    expect(formatArrowLabel(forwardedMsg)).toBe('reply · forwarded');

    // Regular reply
    const normalReply: A2AMessage = {
      ...sampleMessages[4],
      forwarded_from: [],
    };
    expect(formatArrowLabel(normalReply)).toBe('reply');

    // Request
    expect(formatArrowLabel(sampleMessages[0])).toBe('request');

    // Refused
    expect(formatArrowLabel(sampleMessages[3])).toBe('refused');
  });

  it('approval buttons only for the task owner or admin', () => {
    const jobOwner = 'alice';

    // 1. Unauthenticated or empty user cannot decide
    expect(canDecideApproval(null, jobOwner)).toBe(false);

    // 2. Non-owner developer cannot decide
    expect(canDecideApproval({ name: 'bob', role: 'developer' }, jobOwner)).toBe(false);

    // 3. Task owner can decide
    expect(canDecideApproval({ name: 'alice', role: 'developer' }, jobOwner)).toBe(true);

    // 4. Admin can decide
    expect(canDecideApproval({ name: 'admin_user', role: 'admin' }, jobOwner)).toBe(true);
  });
});
