import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { DecisionCard, RequestPreview } from './DecisionCard';
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
  it('offers the four decisions in order', () => {
    const html = card({ canManageRules: true });
    const order = ['inline-approve-btn-exp_1', 'allow-once-btn-exp_1', 'deny-btn-exp_1', 'always-btn-exp_1'].map(id =>
      html.indexOf(`id="${id}"`),
    );
    expect(order.every(i => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(html).toContain('Allow for this run');
    expect(html).toContain('Allow once');
    expect(html).toContain('Always for this agent');
    expect(html).toContain('>Block<');
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
