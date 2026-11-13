import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ReportSheet } from './ReportPage';
import { TaskReport } from '../logic/report';

const base: TaskReport = {
  generated_at: '2026-11-12T10:10:00Z',
  task: {
    task_id: 't_rep',
    request_text: 'Summarise the minutes',
    agent_id: 'notes_bot',
    requester: 'Ana Dev',
    team: 'core',
    status: 'COMPLETED',
    created_at: '2026-11-12T10:00:00Z',
    started_at: '2026-11-12T10:00:01Z',
    completed_at: '2026-11-12T10:05:00Z',
  },
  boundary: {
    initial: { version: 1, files_read: ['input/minutes.txt'], files_write: ['output/summary.md'], network: [], tools: [] },
    final: { version: 2, files_read: ['input/minutes.txt', 'docs/notes.txt'], files_write: ['output/summary.md'], network: [], tools: [] },
  },
  approvals: [
    {
      request_id: 'e1', resource_type: 'file_read', target: 'docs/notes.txt', status: 'APPROVED', scope: 'run',
      asked_at: '2026-11-12T10:01:00Z', decided_at: '2026-11-12T10:02:00Z', decided_by: 'operator:ana',
      decided_by_label: 'ana (operator)', risk_tier: 'MEDIUM', prompted_by_file: true, reason: null,
    },
  ],
  blocked: [{ timestamp: '2026-11-12T10:03:00Z', kind: 'file_read', target: 'input/payroll.csv', layer: 'landlock', rule: null }],
  record: { available: true, verified: true, message: 'ok', final_hash: 'abc123', event_count: 7 },
};

describe('report sheet', () => {
  it('shows requester, boundary, approvals with who, blocked actions and the record check', () => {
    const html = renderToStaticMarkup(<ReportSheet report={base} />);
    expect(html).toContain('Ana Dev');
    expect(html).toContain('docs/notes.txt'); // added after a decision
    expect(html).toContain('Allowed for this run');
    expect(html).toContain('ana (operator)');
    expect(html).toContain('prompted by a file it read');
    expect(html).toContain('Kernel (Landlock)');
    expect(html).toContain('Attempted, not successful');
    expect(html).toContain('Record checked: no entries changed');
    expect(html).toContain('7 hash-chained entries (SHA-256)');
  });

  it('has plain empty states', () => {
    const html = renderToStaticMarkup(
      <ReportSheet
        report={{ ...base, approvals: [], blocked: [], record: { available: false, verified: false, message: null, final_hash: null, event_count: 0 }, task: { ...base.task, requester: null } }}
      />,
    );
    expect(html).toContain('The agent asked for nothing beyond its boundary.');
    expect(html).toContain('Nothing was blocked.');
    expect(html).toContain('No record was saved for this run.');
    expect(html).toMatch(/id="report-requester"[^>]*>—</);
  });

  it('caps long lists for one page', () => {
    const many = Array.from({ length: 14 }, (_, i) => ({ ...base.blocked[0], target: `f${i}.txt` }));
    const html = renderToStaticMarkup(<ReportSheet report={{ ...base, blocked: many }} />);
    expect(html).toContain('and 4 more in the CSV and JSON downloads');
    expect(html).not.toContain('f13.txt');
  });

  it('uses none of the banned words', () => {
    const text = renderToStaticMarkup(<ReportSheet report={base} />).replace(/<[^>]+>/g, ' ');
    for (const w of ['safe', 'secure', 'guaranteed', 'tamper-proof', 'complete', 'signed']) {
      expect(text.toLowerCase()).not.toMatch(new RegExp(`\\b${w}\\b`));
    }
  });
});
