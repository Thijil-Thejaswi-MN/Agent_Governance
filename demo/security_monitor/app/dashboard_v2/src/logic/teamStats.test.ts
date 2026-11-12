import { describe, expect, it } from 'vitest';
import {
  agentRows,
  countDecided,
  formatDuration,
  hourlyHeat,
  isRule,
  isTimeout,
  medianDecisionSeconds,
  startOfLocalDay,
} from './teamStats';

const NOW = new Date(2026, 10, 12, 18, 30, 0).getTime(); // local 18:30
const at = (h: number, m = 0) => new Date(2026, 10, 12, h, m, 0).toISOString();
const ago = (sec: number) => new Date(NOW - sec * 1000).toISOString();

describe('empty data', () => {
  it('gives no numbers, only dashes and empty rows', () => {
    expect(medianDecisionSeconds([], NOW)).toBeNull();
    expect(formatDuration(medianDecisionSeconds([], NOW))).toBe('—');
    expect(countDecided([], isTimeout, NOW)).toBe(0);
    expect(hourlyHeat([], [], [], NOW)).toEqual([]);
    expect(agentRows([])).toEqual([]);
  });

  it('ignores tasks without an agent instead of inventing one', () => {
    expect(agentRows([{ task_id: 't1' }])).toEqual([]);
  });

  it('keeps a missing owner as null', () => {
    expect(agentRows([{ task_id: 't1', agent_id: 'a' }])[0].owner).toBeNull();
  });
});

describe('decision time', () => {
  it('is the median over decisions by a person in the last 24 hours', () => {
    const exps = [
      { task_id: 't', created_at: ago(200), resolved_at: ago(100), resolved_by: 'operator:ana' }, // 100 s
      { task_id: 't', created_at: ago(400), resolved_at: ago(380), resolved_by: 'team_lead:lee' }, // 20 s
      { task_id: 't', created_at: ago(1000), resolved_at: ago(892), resolved_by: 'security_reviewer:sam' }, // 108 s
      { task_id: 't', created_at: ago(50), resolved_at: ago(49), resolved_by: 'auto_policy' }, // not a person
      { task_id: 't', created_at: ago(60), resolved_at: ago(10), resolved_by: 'standing_rule:rule_1' }, // a rule
      { task_id: 't', created_at: ago(90000), resolved_at: ago(89000), resolved_by: 'operator:ana' }, // too old
      { task_id: 't', created_at: ago(30), resolved_by: null }, // still waiting
    ];
    expect(medianDecisionSeconds(exps, NOW)).toBe(100);
    expect(formatDuration(108)).toBe('1m 48s');
    expect(formatDuration(42)).toBe('42s');
    expect(formatDuration(7500)).toBe('2h 5m');
  });

  it('counts timeouts and rule decisions in the window', () => {
    const exps = [
      { task_id: 't', resolved_at: ago(10), resolved_by: 'timeout_fail_closed' },
      { task_id: 't', resolved_at: ago(20), resolved_by: 'standing_rule:rule_1' },
      { task_id: 't', resolved_at: ago(30), resolved_by: 'standing_rule:rule_2' },
      { task_id: 't', resolved_at: ago(90000), resolved_by: 'timeout_fail_closed' },
    ];
    expect(countDecided(exps, isTimeout, NOW)).toBe(1);
    expect(countDecided(exps, isRule, NOW)).toBe(2);
  });
});

describe('hourly heat', () => {
  const tasks = [
    { task_id: 't1', agent_id: 'notes_bot', created_at: at(9, 5) },
    { task_id: 't2', agent_id: 'calc_bot', created_at: at(11) },
  ];
  it('uses real timestamps: blocked beats asked beats quiet', () => {
    const events = [
      { task_id: 't1', agent_id: 'os_process', timestamp: at(9, 10), prevented: true },
      { task_id: 't1', timestamp: at(15, 1), action_taken: 'BLOCK_ACTION' },
      { task_id: 't2', timestamp: at(11, 30), prevented: false, action_taken: 'LOG' },
    ];
    const exps = [{ task_id: 't1', created_at: at(9, 20) }, { task_id: 't2', created_at: at(12, 0) }];
    const rows = Object.fromEntries(hourlyHeat(tasks, events, exps, NOW).map(r => [r.agentId, r.cells]));
    expect(rows.notes_bot[9]).toBe('stopped');
    expect(rows.notes_bot[15]).toBe('stopped');
    expect(rows.notes_bot[13]).toBe('none');
    expect(rows.calc_bot[11]).toBe('quiet');
    expect(rows.calc_bot[12]).toBe('asked');
    expect(rows.calc_bot.filter(c => c === 'stopped')).toHaveLength(0);
  });

  it('ignores yesterday and the future', () => {
    const y = new Date(startOfLocalDay(NOW) - 3600_000).toISOString();
    const later = new Date(NOW + 3600_000).toISOString();
    const rows = hourlyHeat(tasks, [{ task_id: 't1', timestamp: y, prevented: true }, { task_id: 't1', timestamp: later, prevented: true }], [], NOW);
    expect(rows.find(r => r.agentId === 'notes_bot')!.cells.includes('stopped')).toBe(false);
  });
});

describe('agent rows', () => {
  it('adds up per agent and sorts by stops', () => {
    const rows = agentRows([
      { task_id: 'a', agent_id: 'x', owner: 'Ana', total_actions: 3, prevented_count: 1, status: 'COMPLETED' },
      { task_id: 'b', agent_id: 'x', total_actions: 2, prevented_count: 0, os_denials_count: 2, status: 'ACTIVE' },
      { task_id: 'c', agent_id: 'y', total_actions: 1, status: 'COMPLETED' },
    ]);
    expect(rows).toEqual([
      { agentId: 'x', owner: 'Ana', actions: 5, stops: 3, running: true },
      { agentId: 'y', owner: null, actions: 1, stops: 0, running: false },
    ]);
  });
});
