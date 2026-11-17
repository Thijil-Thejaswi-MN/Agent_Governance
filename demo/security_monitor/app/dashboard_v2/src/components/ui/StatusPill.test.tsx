import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { StatusPill } from './StatusPill';

describe('StatusPill component', () => {
  it('renders ok tone with tint background, border and dot', () => {
    const html = renderToStaticMarkup(<StatusPill tone="ok" label="Active" />);
    expect(html).toContain('rounded-full');
    expect(html).toContain('h-7');
    expect(html).toContain('px-2.5');
    expect(html).toContain('text-[12px]');
    expect(html).toContain('bg-ok-tint');
    expect(html).toContain('text-ok');
    expect(html).toContain('bg-ok');
    expect(html).toContain('Active');
  });

  it('renders bad tone correctly', () => {
    const html = renderToStaticMarkup(<StatusPill tone="bad" label="Blocked" />);
    expect(html).toContain('bg-bad-tint');
    expect(html).toContain('text-bad');
    expect(html).toContain('Blocked');
  });

  it('renders wait tone correctly', () => {
    const html = renderToStaticMarkup(<StatusPill tone="wait" label="Waiting" />);
    expect(html).toContain('bg-wait-tint');
    expect(html).toContain('text-wait');
    expect(html).toContain('Waiting');
  });

  it('renders info tone correctly', () => {
    const html = renderToStaticMarkup(<StatusPill tone="info" label="Running" />);
    expect(html).toContain('bg-info-tint');
    expect(html).toContain('text-info');
    expect(html).toContain('Running');
  });

  it('renders neutral tone correctly', () => {
    const html = renderToStaticMarkup(<StatusPill tone="neutral" label="Idle" />);
    expect(html).toContain('bg-surface-3');
    expect(html).toContain('text-fg-2');
    expect(html).toContain('Idle');
  });

  it('can omit dot when dot=false', () => {
    const html = renderToStaticMarkup(<StatusPill tone="ok" label="No Dot" dot={false} />);
    expect(html).not.toContain('w-1.5 h-1.5');
    expect(html).toContain('No Dot');
  });

  it('renders children instead of label if provided', () => {
    const html = renderToStaticMarkup(
      <StatusPill tone="info">Custom Content</StatusPill>
    );
    expect(html).toContain('Custom Content');
  });

  it('contains no banned words in copy or classes', () => {
    const banned = ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed'];
    const html = renderToStaticMarkup(
      <div>
        <StatusPill tone="ok" label="Permitted" />
        <StatusPill tone="bad" label="Prohibited" />
        <StatusPill tone="wait" label="Pending" />
        <StatusPill tone="info" label="Progress" />
        <StatusPill tone="neutral" label="Inactive" />
      </div>
    );
    for (const b of banned) {
      expect(html.toLowerCase()).not.toContain(b);
    }
  });
});
