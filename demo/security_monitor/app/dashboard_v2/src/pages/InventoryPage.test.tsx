import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { InventoryCard } from './InventoryPage';

const NOW = Date.parse('2026-11-12T12:00:00Z');

describe('inventory card', () => {
  it('shows every field, the badge and the rule', () => {
    const html = renderToStaticMarkup(
      <InventoryCard
        now={NOW}
        c={{ agentId: 'brief_bot', owner: 'Ana', team: 'core', tasks: 3, blocked: 2, asks: 2, promptedAsks: 1, lastActive: '2026-11-12T11:00:00Z', risk: 'medium' }}
      />,
    );
    for (const s of ['brief_bot', 'Ana', 'core', 'Tasks run', '>3<', 'Blocked', '>2<', '2 (1 prompted by a file)', '1 h ago', 'Medium risk']) {
      expect(html).toContain(s);
    }
    expect(html).toContain('role="tooltip"');
    expect(html).toContain('This agent: 2 blocked actions, 2 requests (1 prompted by a file it read).');
    expect(html).toContain('High: 5 or more blocked actions');
    expect(html).toContain('aria-describedby="risk-rule-brief_bot"');
  });

  it('shows dashes for missing owner, team and time', () => {
    const html = renderToStaticMarkup(
      <InventoryCard now={NOW} c={{ agentId: 'x', owner: null, team: null, tasks: 1, blocked: 0, asks: 0, promptedAsks: 0, lastActive: null, risk: 'low' }} />,
    );
    expect((html.match(/>—</g) || []).length).toBe(3);
    expect(html).toContain('Low risk');
  });
});
