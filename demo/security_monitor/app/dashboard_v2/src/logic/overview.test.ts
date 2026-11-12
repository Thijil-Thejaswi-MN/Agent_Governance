import { describe, expect, it } from 'vitest';
import { actionsPerHour, agentDots, mapMode, medianRunSeconds, runsInLast24h, stoppedInLast24h, teamGroups } from './overview';

const NOW = new Date(2026, 10, 12, 18, 30).getTime();
const at = (h: number, m = 0) => new Date(2026, 10, 12, h, m).toISOString();
const ago = (sec: number) => new Date(NOW - sec * 1000).toISOString();

describe('empty data', () => {
  it('gives zeros, nulls and empty lists', () => {
    expect(runsInLast24h([], NOW)).toEqual([]);
    expect(medianRunSeconds([], NOW)).toBeNull();
    expect(stoppedInLast24h([], NOW)).toBe(0);
    expect(actionsPerHour([], [], NOW).every(b => b.allowed + b.stopped + b.asked === 0)).toBe(true);
    expect(agentDots([], [], [], NOW)).toEqual([]);
    expect(teamGroups([])).toEqual([]);
  });
});

describe('counts', () => {
  it('uses the last 24 hours only', () => {
    const tasks = [
      { task_id: 'a', created_at: ago(60), started_at: ago(60), completed_at: ago(50) },
      { task_id: 'b', created_at: ago(400), started_at: ago(400), completed_at: ago(370) },
      { task_id: 'c', created_at: ago(200000), started_at: ago(200000), completed_at: ago(199000) },
    ];
    expect(runsInLast24h(tasks, NOW).map(t => t.task_id)).toEqual(['a', 'b']);
    expect(medianRunSeconds(tasks, NOW)).toBe(20);
    expect(stoppedInLast24h([{ timestamp: ago(10), prevented: true }, { timestamp: ago(100000), prevented: true }, { timestamp: ago(5) }], NOW)).toBe(1);
  });

  it('buckets today by local hour', () => {
    const b = actionsPerHour(
      [{ timestamp: at(9, 5) }, { timestamp: at(9, 6), prevented: true }, { timestamp: at(14), action_taken: 'BLOCK_ACTION' }],
      [{ task_id: 't', created_at: at(14, 2) }],
      NOW,
    );
    expect(b[9]).toEqual({ hour: 9, allowed: 1, stopped: 1, asked: 0 });
    expect(b[14]).toEqual({ hour: 14, allowed: 0, stopped: 1, asked: 1 });
  });
});

describe('agents and teams', () => {
  const tasks = [
    { task_id: 't1', agent_id: 'a1', team: 'core', status: 'ACTIVE' },
    { task_id: 't2', agent_id: 'a2', team: 'core', status: 'COMPLETED' },
    { task_id: 't3', agent_id: 'a3', team: null, status: 'ACTIVE' },
    { task_id: 't4', agent_id: 'a4', team: 'ops', status: 'COMPLETED' },
  ];
  it('marks asking, stopped, running and idle', () => {
    const dots = agentDots(tasks, [{ task_id: 't1' }], [{ task_id: 't4', timestamp: ago(60), prevented: true }], NOW);
    expect(dots.map(d => [d.agentId, d.state])).toEqual([
      ['a1', 'asking'],
      ['a4', 'stopped'],
      ['a3', 'running'],
      ['a2', 'idle'],
    ]);
    expect(teamGroups(dots)).toEqual([
      { team: 'core', agents: 2, running: 1, waiting: 1 },
      { team: 'No team', agents: 1, running: 1, waiting: 0 },
      { team: 'ops', agents: 1, running: 1, waiting: 0 },
    ]);
  });
  it('chooses the map layout by running tasks', () => {
    expect([mapMode(0), mapMode(20), mapMode(21), mapMode(500), mapMode(501)]).toEqual(['individual', 'individual', 'teams', 'teams', 'canvas']);
  });
});
