import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { agentRows, hourlyHeat, TaskLike } from '../logic/teamStats';
import { AgentSelector } from './AskPage';

describe('AskPage agent dropdown', () => {
  const agents = [
    { id: 'finance_bot', name: 'Finance Bot', team: 'finance' },
    { id: 'notes_bot', name: 'Notes Bot', team: 'core' },
    { id: 'brief_bot', name: 'Brief Bot', team: 'legal' },
  ];

  it('renders dropdown with id agent-selector and all configured agents', () => {
    const html = renderToStaticMarkup(
      <AgentSelector agents={agents} value="finance_bot" onChange={() => {}} />,
    );

    expect(html).toContain('id="agent-selector"');
    expect(html).toContain('value="finance_bot"');
    expect(html).toContain('Finance Bot (finance)');
    expect(html).toContain('value="notes_bot"');
    expect(html).toContain('Notes Bot (core)');
    expect(html).toContain('value="brief_bot"');
    expect(html).toContain('Brief Bot (legal)');
  });

  it('reflects selected agent value in rendered markup', () => {
    const htmlNotes = renderToStaticMarkup(
      <AgentSelector agents={agents} value="notes_bot" onChange={() => {}} />,
    );
    expect(htmlNotes).toContain('value="notes_bot"');
  });
});

describe('per-agent stats for named agents', () => {
  const tasks: TaskLike[] = [
    {
      task_id: 't1',
      agent_id: 'finance_bot',
      owner: 'Ana Dev',
      total_actions: 8,
      prevented_count: 2,
      os_denials_count: 0,
      status: 'ACTIVE',
    },
    {
      task_id: 't2',
      agent_id: 'notes_bot',
      owner: 'Ravi K',
      total_actions: 5,
      prevented_count: 0,
      os_denials_count: 1,
      status: 'ACTIVE',
    },
    {
      task_id: 't3',
      agent_id: 'brief_bot',
      owner: 'Meena R',
      total_actions: 12,
      prevented_count: 0,
      os_denials_count: 0,
      status: 'COMPLETED',
    },
  ];

  it('calculates totals and running status per named agent', () => {
    const rows = agentRows(tasks);
    expect(rows).toHaveLength(3);

    const fin = rows.find(r => r.agentId === 'finance_bot')!;
    expect(fin.owner).toBe('Ana Dev');
    expect(fin.actions).toBe(8);
    expect(fin.stops).toBe(2);
    expect(fin.running).toBe(true);

    const notes = rows.find(r => r.agentId === 'notes_bot')!;
    expect(notes.owner).toBe('Ravi K');
    expect(notes.actions).toBe(5);
    expect(notes.stops).toBe(1);
    expect(notes.running).toBe(true);

    const brief = rows.find(r => r.agentId === 'brief_bot')!;
    expect(brief.owner).toBe('Meena R');
    expect(brief.actions).toBe(12);
    expect(brief.stops).toBe(0);
    expect(brief.running).toBe(false);
  });

  it('ranks agents with security stops higher in team stats', () => {
    const rows = agentRows(tasks);
    expect(rows[0].agentId).toBe('finance_bot'); // 2 stops
    expect(rows[1].agentId).toBe('notes_bot');   // 1 stop
    expect(rows[2].agentId).toBe('brief_bot');   // 0 stops
  });
});
