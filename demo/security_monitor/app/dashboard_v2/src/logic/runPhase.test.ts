import { describe, expect, it } from 'vitest';
import { runPhase } from './runPhase';

describe('run progress pill', () => {
  it('follows the real run state, phase by phase', () => {
    expect(runPhase('preparing', false, false, false).label).toBe('Setting up the task');
    expect(runPhase('running', false, false, false).label).toBe('Setting up the task');
    expect(runPhase('running', true, false, false).label).toBe('Agent working');
    expect(runPhase('waiting_approval', true, true, false)).toMatchObject({ label: 'Waiting for you', tone: 'ask' });
    expect(runPhase('stopping', true, false, false).label).toBe('Stopping, writing the record');
    expect(runPhase('completed', true, false, false)).toMatchObject({ label: 'Writing the record', finished: false });
  });

  it('ends with how the run ended, once the record is in', () => {
    expect(runPhase('completed', true, false, true)).toMatchObject({ label: 'Done', tone: 'ok', finished: true, current: 4 });
    expect(runPhase('stopped', true, false, true)).toMatchObject({ label: 'Stopped', tone: 'bad' });
    expect(runPhase('failed', false, false, true).label).toBe('Failed');
    expect(runPhase('timed_out', true, false, true).label).toBe('Timed out');
  });

  it('never moves backwards within one run', () => {
    const order = [
      runPhase('preparing', false, false, false),
      runPhase('running', true, false, false),
      runPhase('waiting_approval', true, true, false),
      runPhase('stopping', true, false, false),
      runPhase('completed', true, false, true),
    ].map(v => v.current);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });
});
