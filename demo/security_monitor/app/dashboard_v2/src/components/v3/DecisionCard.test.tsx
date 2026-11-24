import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { DecisionCard, RequestPreview, StagedContent } from './DecisionCard';
import { ExpansionItem } from '../../types';
import { ExpansionPreview } from '../../logic/approval';

const exp = {
  request_id: 'exp_1',
  task_id: 't1',
  agent_id: 'notes_bot',
  resource_type: 'file_read',
  resource_target: 'docs/notes.txt',
  baseline_risk_tier: 'MEDIUM',
  effective_risk_tier: 'MEDIUM',
  justification: 'need it',
  status: 'PENDING',
  created_at: new Date().toISOString(),
  timeout_seconds: 600,
} as unknown as ExpansionItem;

const preview: ExpansionPreview = {
  request_id: 'exp_1',
  kind: 'file',
  name: 'notes.txt',
  folder: 'docs',
  size_bytes: 1234,
  exists: true,
  inside_workspace: true,
  risk_tier: 'MEDIUM',
  escalated: false,
  learned_from: null,
  rule_possible: true,
};

const card = (props: Partial<React.ComponentProps<typeof DecisionCard>> = {}) =>
  renderToStaticMarkup(
    <DecisionCard exp={exp} triedBefore={false} deciding={false} onAllow={() => undefined} onDeny={() => undefined} {...props} />,
  );

describe('request preview', () => {
  it('shows name, folder, size and risk', () => {
    const html = renderToStaticMarkup(<RequestPreview exp={exp} preview={preview} />);
    expect(html).toContain('notes.txt');
    expect(html).toContain('in docs · 1.2 KB');
    expect(html).toContain('data-tier="MEDIUM"');
    expect(html).toContain('Medium risk');
  });
  it('says it is looking while the preview loads', () => {
    expect(renderToStaticMarkup(<RequestPreview exp={exp} preview={null} />)).toContain('Looking up the details…');
  });
});

describe('decision card', () => {
  it('Allow once carries the hover note', () => {
    expect(card()).toContain('title="The copy is removed after the agent’s initial read (detected by the monitor)."');
  });

  it('offers the decisions in order', () => {
    const html = card({ canManageRules: true });
    const order = ['inline-approve-btn-exp_1', 'allow-once-btn-exp_1', 'allow-timed-btn-exp_1', 'deny-btn-exp_1', 'always-btn-exp_1'].map(id =>
      html.indexOf(`id="${id}"`),
    );
    expect(order.every(i => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(html).toContain('Allow for this run');
    expect(html).toContain('Allow once');
    expect(html).toContain('Always for this agent');
    expect(html).toContain('>Block<');
    expect(html).toContain('Allow for 10 minutes');
  });

  it('offers no time limit for a write (it is saved once)', () => {
    const html = card({ exp: { ...exp, resource_type: 'file_write', resource_target: 'output/note.txt' } as ExpansionItem });
    expect(html).not.toContain('allow-timed-btn');
  });

  it('disables Always for people who cannot make rules, and says why', () => {
    const html = card({ canManageRules: false });
    expect(html).toMatch(/id="always-btn-exp_1"[^>]*disabled=""/);
    expect(html).toContain('Only a security reviewer or an admin can make a standing rule.');
  });

  it('disables Always for a request prompted by a file the agent read', () => {
    const html = card({ canManageRules: true, exp: { ...exp, escalated_by_provenance: true } as ExpansionItem });
    expect(html).toMatch(/id="always-btn-exp_1"[^>]*disabled=""/);
    expect(html).toContain('always go to a person');
  });

  it('read-only shows no buttons', () => {
    const html = card({ readOnly: true });
    expect(html).not.toContain('Allow once');
    expect(html).toContain('A decision is waiting.');
  });
});

describe('StagedContent', () => {
  const staged = { staged_path: 'staged/output/extra.txt', size_bytes: 9, content_sha256: 'b'.repeat(64), binary: false, preview: 'Total: 22', truncated: false };
  it('shows the exact content that will be saved, with its hash', () => {
    const html = renderToStaticMarkup(<StagedContent staged={staged} />);
    expect(html).toContain('id="decision-staged-content"');
    expect(html).toContain('Total: 22');
    expect(html).toContain('SHA-256 bbbbbbbbbbbbbbbb');
  });
  it('does not print binary content', () => {
    const html = renderToStaticMarkup(<StagedContent staged={{ ...staged, binary: true, preview: '' }} />);
    expect(html).not.toContain('decision-staged-content');
    expect(html).toContain('binary file');
  });
  it('renders nothing for a request with no staged content', () => {
    expect(renderToStaticMarkup(<StagedContent staged={null} />)).toBe('');
  });
});
