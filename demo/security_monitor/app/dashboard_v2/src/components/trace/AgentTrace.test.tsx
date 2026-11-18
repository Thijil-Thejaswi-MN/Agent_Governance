import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AgentTrace } from './AgentTrace';
import { TaskStep } from '../../types';

function makeStep(overrides: Partial<TaskStep> & { step_number: number; kind: string; summary: string }): TaskStep {
  return {
    task_id: 'task_trace_1',
    timestamp: '2026-11-18T00:00:00Z',
    layer: 'broker',
    verdict: 'ALLOW',
    detail: '',
    source_label: 'enforced',
    ...overrides,
  };
}

describe('AgentTrace component', () => {
  it('renders rows with id="agent-trace", role="list", and list items', () => {
    const steps: TaskStep[] = [
      makeStep({ step_number: 1, kind: 'model', summary: 'Model turn 1: response generated', detail: 'prompt tokens: 42' }),
      makeStep({ step_number: 2, kind: 'tool', summary: 'read_file allowed: input/sales.csv' }),
    ];

    const html = renderToStaticMarkup(<AgentTrace steps={steps} runState="running" />);

    expect(html).toContain('id="agent-trace"');
    expect(html).toContain('role="list"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('role="listitem"');
    expect(html).toContain('Asked the model');
    expect(html).toContain('Reading input/sales.csv');
  });

  it('marks the live row with aria-busy="true"', () => {
    const steps: TaskStep[] = [
      makeStep({ step_number: 1, kind: 'model', summary: 'Model turn 1: response generated' }),
      makeStep({ step_number: 2, kind: 'tool', summary: 'read_file allowed: input/sales.csv' }),
    ];

    const html = renderToStaticMarkup(<AgentTrace steps={steps} runState="running" />);

    expect(html).toContain('aria-busy="true"');
    expect(html).toContain('trace-shimmer');
  });

  it('renders detail inside a pre block when detail is provided', () => {
    const steps: TaskStep[] = [
      makeStep({
        step_number: 1,
        kind: 'tool',
        summary: 'write_file allowed: output/summary.txt',
        detail: 'Total revenue: $120,000',
      }),
    ];

    // When running and it is the live row, detail is expanded by default
    const htmlLive = renderToStaticMarkup(<AgentTrace steps={steps} runState="running" />);
    expect(htmlLive).toContain('aria-expanded="true"');
    expect(htmlLive).toContain('Total revenue: $120,000');
    expect(htmlLive).toContain('<pre');

    // When completed, the row is not live, so detail is collapsed by default
    const htmlDone = renderToStaticMarkup(<AgentTrace steps={steps} runState="completed" />);
    expect(htmlDone).toContain('aria-expanded="false"');
  });

  it('renders empty when there are no steps', () => {
    const html = renderToStaticMarkup(<AgentTrace steps={[]} runState="running" />);
    expect(html).toBe('');
  });

  it('contains no banned words in rendered markup', () => {
    const banned = ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed'];
    const steps: TaskStep[] = [
      makeStep({ step_number: 1, kind: 'model', summary: 'Model turn 1: response generated' }),
      makeStep({ step_number: 2, kind: 'tool', summary: 'read_file allowed: input/sales.csv' }),
      makeStep({ step_number: 3, kind: 'finished', summary: 'Run ended: completed', verdict: 'COMPLETED' }),
    ];

    const html = renderToStaticMarkup(<AgentTrace steps={steps} runState="completed" />);
    for (const b of banned) {
      expect(html.toLowerCase()).not.toContain(b);
    }
  });
});
