import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { DiscoveredAgentCard, InventoryCard } from './InventoryPage';

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

describe('discovered agent card', () => {
  it('renders discovered card with name, description, skills and Not governed yet state', () => {
    const html = renderToStaticMarkup(
      <DiscoveredAgentCard
        item={{
          agent_id: 'google_travel_planner',
          name: 'Google Travel Planner',
          owner: 'Google A2A Samples',
          classification: 'DISCOVERED_A2A',
          status: 'IDLE',
          description: 'Plans flights, hotels and itineraries across multiple providers.',
          skills: ['flight_search', 'hotel_booking', 'itinerary_generator'],
          governance_state: 'Not governed yet',
          metadata: {
            card_url: 'http://127.0.0.1:9999/.well-known/agent-card.json',
            version: '1.0.0',
          },
        }}
      />,
    );
    expect(html).toContain('Google Travel Planner');
    expect(html).toContain('Discovered (A2A card)');
    expect(html).toContain('Provider: Google A2A Samples');
    expect(html).toContain('Plans flights, hotels and itineraries across multiple providers.');
    expect(html).toContain('flight_search');
    expect(html).toContain('hotel_booking');
    expect(html).toContain('itinerary_generator');
    expect(html).toContain('Not governed yet');
    expect(html).toContain('data-governance-state="Not governed yet"');
    expect(html).toContain('http://127.0.0.1:9999/.well-known/agent-card.json');
  });

  it('renders Governed state badge when agent has run inside our fence', () => {
    const html = renderToStaticMarkup(
      <DiscoveredAgentCard
        item={{
          agent_id: 'finance_bot',
          name: 'Finance Bot',
          owner: 'Finance Operations',
          classification: 'GOVERNED',
          status: 'ACTIVE',
          description: 'Processes corporate invoices and ledger reconciliation.',
          skills: ['invoice_review', 'reconcile'],
          governance_state: 'Governed',
        }}
      />,
    );
    expect(html).toContain('Finance Bot');
    expect(html).toContain('Discovered (A2A card)');
    expect(html).toContain('Governed');
    expect(html).toContain('data-governance-state="Governed"');
  });
});