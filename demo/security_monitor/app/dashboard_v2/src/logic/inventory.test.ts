import { describe, expect, it } from 'vitest';
import { RISK_RULE, inventoryCards, riskOf, riskWhy } from './inventory';

describe('empty data', () => {
  it('has no cards and invents no agent', () => {
    expect(inventoryCards([], [])).toEqual([]);
    expect(inventoryCards([{ task_id: 't' }], [{ task_id: 't' }])).toEqual([]);
  });
});

describe('risk rule', () => {
  it('follows the stated thresholds', () => {
    expect(riskOf(0, 0, 0)).toBe('low');
    expect(riskOf(0, 2, 0)).toBe('low');
    expect(riskOf(1, 0, 0)).toBe('medium');
    expect(riskOf(0, 3, 0)).toBe('medium');
    expect(riskOf(0, 1, 1)).toBe('medium');
    expect(riskOf(4, 0, 1)).toBe('medium');
    expect(riskOf(5, 0, 0)).toBe('high');
    expect(riskOf(0, 2, 2)).toBe('high');
    expect(RISK_RULE).toContain('5 or more blocked actions');
  });
  it('explains one agent', () => {
    expect(riskWhy({ blocked: 1, asks: 2, promptedAsks: 1 })).toBe('This agent: 1 blocked action, 2 requests (1 prompted by a file it read).');
    expect(riskWhy({ blocked: 0, asks: 1, promptedAsks: 0 })).toBe('This agent: 0 blocked actions, 1 request.');
  });
});

describe('cards', () => {
  it('adds up per agent from tasks and requests', () => {
    const cards = inventoryCards(
      [
        { task_id: 't1', agent_id: 'a', owner: 'Ana', team: 'core', created_at: '2026-11-12T09:00:00Z', completed_at: '2026-11-12T09:05:00Z', prevented_count: 2 },
        { task_id: 't2', agent_id: 'a', owner: null, created_at: '2026-11-12T11:00:00Z', os_denials_count: 4, prevented_count: 3 },
        { task_id: 't3', agent_id: 'b', created_at: '2026-11-12T12:00:00Z' },
      ],
      [{ task_id: 't1', escalated_by_provenance: true }, { task_id: 't2' }, { task_id: 't3' }],
    );
    expect(cards).toEqual([
      { agentId: 'a', owner: 'Ana', team: 'core', tasks: 2, blocked: 6, asks: 2, promptedAsks: 1, lastActive: '2026-11-12T11:00:00Z', risk: 'high' },
      { agentId: 'b', owner: null, team: null, tasks: 1, blocked: 0, asks: 1, promptedAsks: 0, lastActive: '2026-11-12T12:00:00Z', risk: 'low' },
    ]);
  });
});

describe('configured agents and comparison runs', () => {
  const cfg = [{ id: 'finance_bot', name: 'Finance Bot', owner: 'Ana Dev', team: 'finance', description: 'Revenue reports' }];
  it('lists a configured agent before its first run', () => {
    const cards = inventoryCards([], [], cfg);
    expect(cards).toHaveLength(1);
    expect(cards[0]).toMatchObject({ agentId: 'finance_bot', name: 'Finance Bot', owner: 'Ana Dev', tasks: 0, blocked: 0, risk: 'low', configured: true });
  });
  it('never counts comparison runs', () => {
    const cards = inventoryCards(
      [
        { task_id: 'n', agent_id: 'finance_bot', condition: 'C', prevented_count: 1 },
        { task_id: 'c', agent_id: 'finance_bot', condition: 'B', prevented_count: 9 },
      ],
      [],
      cfg,
    );
    expect(cards[0]).toMatchObject({ tasks: 1, blocked: 1, risk: 'medium' });
  });
});
