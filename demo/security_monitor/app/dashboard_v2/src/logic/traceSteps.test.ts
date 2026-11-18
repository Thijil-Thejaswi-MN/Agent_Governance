import { describe, expect, it } from 'vitest';
import { buildTraceRows } from './traceSteps';
import { TaskStep } from '../types';

function step(overrides: Partial<TaskStep> & { step_number: number; kind: string; summary: string }): TaskStep {
  return {
    task_id: 'task_1',
    timestamp: '2026-11-18T00:00:00Z',
    layer: 'broker',
    verdict: 'ALLOW',
    detail: '',
    source_label: 'enforced',
    ...overrides,
  };
}

describe('buildTraceRows', () => {
  it('maps model kind to Brain icon, past tense', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'model', summary: 'Model turn 1: response generated' })],
      'completed',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].icon).toBe('Brain');
    expect(rows[0].title).toBe('Asked the model');
    expect(rows[0].tone).toBe('neutral');
    expect(rows[0].live).toBe(false);
  });

  it('maps model kind live to present tense with shimmer', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'model', summary: 'Model turn 1: response generated' })],
      'running',
    );
    expect(rows[0].title).toBe('Asking the model');
    expect(rows[0].live).toBe(true);
  });

  it('maps tool read_file allowed to FileText icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'tool', summary: 'read_file allowed: input/data.csv' })],
      'completed',
    );
    expect(rows[0].icon).toBe('FileText');
    expect(rows[0].title).toBe('Read input/data.csv');
    expect(rows[0].tone).toBe('neutral');
  });

  it('maps tool write_file allowed to Pencil icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'tool', summary: 'write_file allowed: output/summary.txt' })],
      'completed',
    );
    expect(rows[0].icon).toBe('Pencil');
    expect(rows[0].title).toBe('Wrote output/summary.txt');
  });

  it('maps tool http_get to Globe icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'tool', summary: 'http_get allowed: https://example.com' })],
      'completed',
    );
    expect(rows[0].icon).toBe('Globe');
    expect(rows[0].title).toBe('Fetched https://example.com');
  });

  it('maps tool call_agent to Bot icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'tool', summary: 'call_agent allowed: travel_bot' })],
      'completed',
    );
    expect(rows[0].icon).toBe('Bot');
    expect(rows[0].title).toBe('Called travel_bot');
  });

  it('maps tool run_command to Terminal icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'tool', summary: 'run_command check allowed: cat file.csv', layer: 'broker' })],
      'completed',
    );
    expect(rows[0].icon).toBe('Terminal');
  });

  it('maps tool blocked to bad tone with "stopped" description', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'tool', summary: 'read_file blocked: ~/secrets.txt', verdict: 'BLOCK_ACTION' })],
      'completed',
    );
    expect(rows[0].tone).toBe('bad');
    expect(rows[0].description).toBe('stopped');
    expect(rows[0].title).toContain('Tried to read');
  });

  it('maps sensor kind to Cpu icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'sensor', summary: 'Landlock blocked file_read on /home/u/secret.txt', verdict: 'BLOCK_ACTION', layer: 'landlock' })],
      'completed',
    );
    expect(rows[0].icon).toBe('Cpu');
    expect(rows[0].title).toContain('The kernel saw');
    expect(rows[0].tone).toBe('bad');
  });

  it('groups consecutive identical sensor lines', () => {
    const rows = buildTraceRows(
      [
        step({ step_number: 1, kind: 'sensor', summary: 'Landlock blocked file_read on /a', verdict: 'BLOCK_ACTION', layer: 'landlock' }),
        step({ step_number: 2, kind: 'sensor', summary: 'Landlock blocked file_read on /b', verdict: 'BLOCK_ACTION', layer: 'landlock' }),
        step({ step_number: 3, kind: 'sensor', summary: 'Landlock blocked file_read on /c', verdict: 'BLOCK_ACTION', layer: 'landlock' }),
        step({ step_number: 4, kind: 'sensor', summary: 'Landlock blocked file_read on /d', verdict: 'BLOCK_ACTION', layer: 'landlock' }),
      ],
      'completed',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].title).toContain('4');
    expect(rows[0].description).toBe('4 times');
  });

  it('maps expansion pending to wait tone', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'expansion', summary: 'Expansion access requested for input/secret.csv (MEDIUM risk)', verdict: 'PENDING' })],
      'waiting_approval',
    );
    expect(rows[0].icon).toBe('Hand');
    expect(rows[0].tone).toBe('wait');
    expect(rows[0].description).toBe('waiting for you');
    expect(rows[0].live).toBe(true);
  });

  it('maps expansion approved to ok tone', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'expansion', summary: 'Expansion input/target_metrics.csv approved by operator', verdict: 'APPROVED' })],
      'running',
    );
    expect(rows[0].tone).toBe('ok');
    expect(rows[0].description).toContain('allowed');
  });

  it('maps expansion blocked to bad tone', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'expansion', summary: 'Expansion input/secret.csv denied by policy', verdict: 'BLOCK_ACTION' })],
      'completed',
    );
    expect(rows[0].tone).toBe('bad');
    expect(rows[0].description).toBe('blocked');
  });

  it('maps staged_write kind to FilePen icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'staged_write', summary: 'Staged output/note.txt for review (120 bytes)' })],
      'running',
    );
    expect(rows[0].icon).toBe('FilePen');
    expect(rows[0].title).toContain('Staged');
    expect(rows[0].title).toContain('output/note.txt');
  });

  it('maps phase with "Agent process launched" to Play icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'phase', summary: 'Agent process launched (pid 4242)', layer: 'launcher' })],
      'completed',
    );
    expect(rows[0].icon).toBe('Play');
    expect(rows[0].title).toBe('Started in its own sandbox');
  });

  it('maps output kind to FileOutput icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'output', summary: 'Output file written: output/summary.txt' })],
      'completed',
    );
    expect(rows[0].icon).toBe('FileOutput');
    expect(rows[0].title).toBe('Wrote output/summary.txt');
  });

  it('maps receipt kind to FileCheck icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'receipt', summary: 'Task receipt written and verified (final_hash=abc123...)' })],
      'completed',
    );
    expect(rows[0].icon).toBe('FileCheck');
    expect(rows[0].title).toBe('Record saved and checked');
  });

  it('maps termination with operator_stop to StopCircle icon and bad tone', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'termination', summary: 'Task execution halted (operator_stop)', verdict: 'TERMINATE' })],
      'stopped',
    );
    expect(rows[0].icon).toBe('StopCircle');
    expect(rows[0].tone).toBe('bad');
    expect(rows[0].title).toBe('Run was stopped');
  });

  it('maps finished kind to CheckCircle2 icon', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'finished', summary: 'Run ended: completed', verdict: 'COMPLETED' })],
      'completed',
    );
    expect(rows[0].icon).toBe('CheckCircle2');
    expect(rows[0].title).toBe('Finished');
  });

  it('computes duration from consecutive timestamps', () => {
    const rows = buildTraceRows(
      [
        step({ step_number: 1, kind: 'model', summary: 'Model turn 1: response generated', timestamp: '2026-11-18T00:00:00Z' }),
        step({ step_number: 2, kind: 'tool', summary: 'read_file allowed: input/data.csv', timestamp: '2026-11-18T00:00:03Z' }),
      ],
      'completed',
    );
    expect(rows[0].description).toBe('took 3 s');
  });

  it('no duration when timestamps are missing', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'model', summary: 'Model turn 1: response generated', timestamp: '' })],
      'completed',
    );
    expect(rows[0].description).toBeUndefined();
  });

  it('renders unknown kind as Circle icon with summary', () => {
    const rows = buildTraceRows(
      [step({ step_number: 1, kind: 'unknown_thing', summary: 'Something new happened' })],
      'completed',
    );
    expect(rows[0].icon).toBe('Circle');
    expect(rows[0].title).toBe('Something new happened');
    expect(rows[0].tone).toBe('neutral');
  });

  it('marks the last row as live when running', () => {
    const rows = buildTraceRows(
      [
        step({ step_number: 1, kind: 'tool', summary: 'read_file allowed: input/data.csv' }),
        step({ step_number: 2, kind: 'model', summary: 'Model turn 2: response generated' }),
      ],
      'running',
    );
    expect(rows[0].live).toBe(false);
    expect(rows[1].live).toBe(true);
  });
});
