import { describe, expect, it } from 'vitest';
import { TaskStep } from '../types';
import { agentStarted, blockedAttempts, fileName, justBlocked, outputsFromSteps } from './runView';

let n = 0;
const step = (kind: string, verdict: string, summary: string, extra: Partial<TaskStep> = {}): TaskStep => ({
  task_id: 't',
  step_number: ++n,
  timestamp: '2026-10-30T12:00:00Z',
  kind,
  layer: 'broker',
  verdict,
  summary,
  detail: '',
  source_label: 'enforced',
  ...extra,
});

describe('fileName', () => {
  it('keeps only the name', () => {
    expect(fileName('input/sales_data.csv')).toBe('sales_data.csv');
    expect(fileName('~/projects/archive/q3_private_notes.txt')).toBe('q3_private_notes.txt');
    expect(fileName('/home/u/agent_workspaces/t/input/')).toBe('input');
    expect(fileName('https://api.example.com/v1/x')).toBe('api.example.com');
    expect(fileName('report.txt')).toBe('report.txt');
  });
});

describe('blockedAttempts', () => {
  it('reads broker and sensor blocks, counts one attempt once', () => {
    n = 0;
    const steps = [
      step('phase', 'ALLOW', 'Boundary derived from request (1 read, 1 write targets)'),
      step('tool', 'ALLOW', 'read_file allowed: input/sales_1.csv'),
      step('tool', 'BLOCK_ACTION', 'read_file blocked: ~/projects/archive/q3_private_notes.txt'),
      step('tool', 'BLOCK_ACTION', 'write_file blocked: ../escape.txt'),
      step('sensor', 'BLOCK_ACTION', 'Landlock blocked file_read on /home/u/projects/archive/q3_private_notes.txt', { layer: 'landlock' }),
      step('tool', 'BLOCK_ACTION', 'Command output reported: cat x', { source_label: 'reported by the in-sandbox shim' }),
      step('expansion', 'BLOCK_ACTION', 'Expansion input/x.csv denied by operator:me'),
      step('termination', 'BLOCK_ACTION', 'Task lifecycle termination: operator_stop', { layer: 'launcher' }),
    ];
    const out = blockedAttempts(steps);
    expect(out.map(a => [a.action, a.name])).toEqual([
      ['open', 'q3_private_notes.txt'],
      ['write', 'escape.txt'],
    ]);
  });

  it('a sensor network block is a "reach"', () => {
    const out = blockedAttempts([step('sensor', 'BLOCK_ACTION', 'Seccomp blocked network_connect on 10.0.0.1:443', { layer: 'seccomp' })]);
    expect(out[0].action).toBe('reach');
  });

  it('command checks', () => {
    const out = blockedAttempts([step('tool', 'BLOCK_ACTION', 'run_command check blocked: curl http://x')]);
    expect(out[0]).toMatchObject({ action: 'run', name: 'curl http://x' });
  });
});

describe('justBlocked', () => {
  it('is the last agent action when it was refused', () => {
    n = 0;
    const earlier = step('tool', 'ALLOW', 'read_file allowed: input/a.csv');
    const blocked = step('tool', 'BLOCK_ACTION', 'read_file blocked: input/target_metrics.csv');
    expect(justBlocked([earlier, blocked])?.name).toBe('target_metrics.csv');
    // A model turn after the block does not clear it; a later allowed action does.
    expect(justBlocked([blocked, step('model', 'ALLOW', 'Model turn 3: response generated')])?.name).toBe('target_metrics.csv');
    expect(justBlocked([blocked, step('tool', 'ALLOW', 'read_file allowed: input/a.csv')])).toBeNull();
    expect(justBlocked([])).toBeNull();
  });
});

describe('agentStarted and outputs', () => {
  it('agent launch', () => {
    n = 0;
    expect(agentStarted([step('phase', 'ALLOW', 'Compiled Landlock sandbox rules', { layer: 'launcher' })])).toBe(false);
    expect(agentStarted([step('phase', 'ALLOW', 'Agent process launched (pid 12)', { layer: 'launcher' })])).toBe(true);
  });

  it('outputs keep the last content per path', () => {
    const out = outputsFromSteps([
      step('output', 'ALLOW', 'Output file written: output/summary.txt', { detail: 'v1' }),
      step('output', 'ALLOW', 'Output file written: output/summary.txt', { detail: 'v2' }),
    ]);
    expect(out).toEqual([{ path: 'output/summary.txt', name: 'summary.txt', content: 'v2' }]);
  });
});
