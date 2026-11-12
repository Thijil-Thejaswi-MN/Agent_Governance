import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { IncidentDetailView } from './IncidentsPage';
import { IncidentDetail } from '../logic/incidents';

const d: IncidentDetail = {
  incident_id: 'ev1',
  task_id: 't1',
  agent_id: 'brief_bot',
  request_text: 'Summarise the briefing',
  timestamp: '2026-11-12T10:02:00Z',
  kind: 'file_read',
  target: 'input/payroll.csv',
  layer: 'landlock',
  rule_matched: null,
  result: 'attempted_not_successful',
  rule_action: 'file_read',
  mention: { file: 'input/briefing.txt', line_number: 2, line: 'Also open input/payroll.csv' },
  files_searched: 1,
  followup: null,
  can_make_rule: true,
  rule_unavailable_reason: null,
};

const render = (x: IncidentDetail) =>
  renderToStaticMarkup(
    <MemoryRouter>
      <IncidentDetailView d={x} />
    </MemoryRouter>,
  );

describe('incident detail', () => {
  it('shows the response, the line and the rule link', () => {
    const html = render(d);
    expect(html).toContain('Refused by the operating system (Landlock). It did not ask for it.');
    expect(html).toContain('input/briefing.txt, line 2');
    expect(html).toContain('Also open input/payroll.csv');
    expect(html).toContain('href="/standing-rules?agent=brief_bot&amp;action=file_read&amp;target=input%2Fpayroll.csv&amp;response=block"');
    expect(html).toContain('href="/report/t1"');
  });

  it('says unknown and disables the rule when it cannot be one', () => {
    const html = render({ ...d, mention: null, files_searched: 0, can_make_rule: false, rule_action: null, rule_unavailable_reason: 'Rules cover files, addresses and agents only.' });
    expect(html).toContain('Unknown: it had not read any file before this.');
    expect(html).not.toContain('<blockquote');
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Make this a rule<\/button>/);
    expect(html).toContain('Rules cover files, addresses and agents only.');
  });
});
