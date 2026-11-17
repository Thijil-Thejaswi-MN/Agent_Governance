import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { GrantList, cancellableGrants } from './GrantList';
import { ExpansionItem } from '../../types';

const e = (over: Partial<ExpansionItem>): ExpansionItem =>
  ({
    request_id: 'r1',
    task_id: 't1',
    agent_id: 'finance_bot',
    resource_type: 'file_read',
    resource_target: 'input/targets.csv',
    baseline_risk_tier: 'LOW',
    effective_risk_tier: 'MEDIUM',
    justification: 'x',
    status: 'APPROVED',
    created_at: '2026-11-17T00:00:00Z',
    ...over,
  }) as ExpansionItem;

describe('cancellable grants', () => {
  it('lists approved reads and sites once, never a saved write or a decided repeat', () => {
    const list = cancellableGrants([
      e({}),
      e({ request_id: 'dup', resolved_by: 'duplicate_of:r1' }),
      e({ request_id: 'w', resource_type: 'file_write', resource_target: 'output/note.txt' }),
      e({ request_id: 'n', resource_type: 'network', resource_target: 'api.example.com:443' }),
      e({ request_id: 'd', status: 'DENIED', resource_target: 'input/x.csv' }),
      e({ request_id: 'v', status: 'REVOKED', resource_target: 'input/y.csv' }),
    ]);
    expect(list.map(g => g.request_id)).toEqual(['r1', 'n']);
  });

  it('shows a cancel button per grant, and nothing when there is none', () => {
    const html = renderToStaticMarkup(<GrantList grants={[e({})]} deciding={false} onCancel={() => {}} />);
    expect(html).toContain('Allowed during this run');
    expect(html).toContain('targets.csv');
    expect(html).toContain('id="revoke-btn-r1"');
    expect(renderToStaticMarkup(<GrantList grants={[]} deciding={false} onCancel={() => {}} />)).toBe('');
    const timed = renderToStaticMarkup(
      <GrantList grants={[e({ expires_at: '2026-11-17T10:42:00Z' })]} deciding={false} onCancel={() => {}} />,
    );
    expect(timed).toContain('data-expires="true"');
    expect(timed).toContain(' · until ');
  });
});
