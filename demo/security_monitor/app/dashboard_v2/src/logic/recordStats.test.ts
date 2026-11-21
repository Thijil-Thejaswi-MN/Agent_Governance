import { describe, expect, it } from 'vitest';
import { decidedByPerson, decisionsLine, recordBadge, recordStats, recordsLine, stoppedLine } from './recordStats';

const task = (id: string, stops: number, extra: Record<string, unknown> = {}) =>
  ({ task_id: id, prevented_count: stops, agent_id: 'a', request_text: 'r', workspace_root: '/w', status: 'COMPLETED', created_at: '', total_actions: 0, ...extra }) as any;
const exp = (task_id: string, status: string, resolved_by?: string, expires_at?: string) =>
  ({ task_id, status, resolved_by, expires_at, request_id: Math.random().toString() }) as any;

describe('what the records show', () => {
  it('counts only decisions a person made', () => {
    expect(decidedByPerson(exp('t', 'APPROVED', 'Asha'))).toBe(true);
    expect(decidedByPerson(exp('t', 'APPROVED', 'auto_policy'))).toBe(false);
    expect(decidedByPerson(exp('t', 'DENIED', 'policy_deny_high_risk'))).toBe(false);
    expect(decidedByPerson(exp('t', 'DENIED', 'timeout_fail_closed'))).toBe(false);
    expect(decidedByPerson(exp('t', 'APPROVED', 'standing_rule:rule_1'))).toBe(false);
    expect(decidedByPerson(exp('t', 'APPROVED', 'simulated_user_oracle'))).toBe(false);
    expect(decidedByPerson(exp('t', 'PENDING', 'Asha'))).toBe(false);
  });

  it('sums real runs and leaves comparison runs out', () => {
    const s = recordStats(
      [task('t1', 2), task('t2', 0), task('t3', 5, { comparison_mode: true })],
      [exp('t1', 'APPROVED', 'Asha', '2026-11-17T10:00:00Z'), exp('t1', 'DENIED', 'Asha'), exp('t1', 'REVOKED', 'Asha'),
       exp('t2', 'APPROVED', 'auto_policy'), exp('t3', 'APPROVED', 'Asha'), exp('t2', 'PENDING')],
      { total: 2, verified: 2, failed: 0 },
    );
    expect(s).toMatchObject({ runs: 2, stopped: 2, runsWithStops: 1, decidedByPerson: 3, approvedByPerson: 2,
      deniedByPerson: 1, timeLimited: 1, revoked: 1, decidedOtherwise: 1, verified: 2, checked: 2 });
    expect(stoppedLine(s)).toBe('In 1 run of 2.');
    expect(decisionsLine(s)).toBe('2 allowed, 1 refused, 1 for a limited time, 1 taken back.');
    expect(recordsLine(s)).toBe('2 of 2 checked; none changed.');
  });

  it('says so when there is nothing yet', () => {
    const s = recordStats([], [], null);
    expect([stoppedLine(s), decisionsLine(s), recordsLine(s)]).toEqual(['No runs yet.', 'No requests decided yet.', 'No records yet.']);
    expect(recordsLine({ ...s, checked: 3, verified: 2, failed: 1 })).toBe('1 record does not check out.');
  });
});

describe('recordBadge', () => {
  const summary = {
    failed_ids: ['t_bad', 't_downgrade'],
    verified_ids: ['t_v2', 't_v1', 't_v0'],
    events_only_ids: ['t_v0'],
    signed_ids: ['t_v2'],
    signing_unavailable_ids: ['t_unavail'],
    unsigned_after_signing_enabled_ids: ['t_downgrade'],
  };
  it('labels each run only from what the server checked', () => {
    expect(recordBadge('t_bad', summary)).toBe('failed');
    expect(recordBadge('t_downgrade', summary)).toBe('unsigned_after_signing_enabled');
    expect(recordBadge('t_unavail', summary)).toBe('signing_unavailable');
    expect(recordBadge('t_v2', summary)).toBe('signature_verified');
    expect(recordBadge('t_v1', summary)).toBe('checked');
    expect(recordBadge('t_v0', summary)).toBe('events_only');
    expect(recordBadge('t_running', summary)).toBe('none');
  });
  it('claims nothing without the summary or from an older server', () => {
    expect(recordBadge('t_v1', null)).toBe('unknown');
    expect(recordBadge('t_v1', { failed_ids: [] })).toBe('unknown');
    expect(recordBadge('t_bad', { failed_ids: ['t_bad'] })).toBe('failed');
  });
});
