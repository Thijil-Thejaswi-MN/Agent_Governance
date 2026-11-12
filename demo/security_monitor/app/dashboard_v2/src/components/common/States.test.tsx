import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { EmptyState, ErrorState, LoadingState } from './States';
import { ResponseChip, RuleSentence } from '../policy/RuleBits';

describe('shared states', () => {
  it('loading announces itself politely', () => {
    const html = renderToStaticMarkup(<LoadingState label="Loading rules…" />);
    expect(html).toContain('role="status"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('Loading rules…');
    expect(html).toContain('motion-safe:animate-spin');
  });

  it('empty shows the title, the body and an optional action', () => {
    const html = renderToStaticMarkup(<EmptyState title="No rules yet." body="Add one above." action={<a href="/x">Go</a>} />);
    expect(html).toContain('No rules yet.');
    expect(html).toContain('Add one above.');
    expect(html).toContain('href="/x"');
  });

  it('error is an alert with a retry button only when asked', () => {
    expect(renderToStaticMarkup(<ErrorState message="Nope" />)).not.toContain('Try again');
    const html = renderToStaticMarkup(<ErrorState message="Nope" onRetry={() => undefined} />);
    expect(html).toContain('role="alert"');
    expect(html).toContain('Try again');
  });
});

describe('rule bits', () => {
  it('chip labels each response', () => {
    expect(renderToStaticMarkup(<ResponseChip response="allow" />)).toContain('Allow and log');
    expect(renderToStaticMarkup(<ResponseChip response="ask" />)).toContain('Ask');
    expect(renderToStaticMarkup(<ResponseChip response="block" />)).toContain('data-response="block"');
    expect(renderToStaticMarkup(<ResponseChip response="weird" />)).toContain('data-response="allow"');
  });

  it('sentence shows the exact target in mono', () => {
    const html = renderToStaticMarkup(
      <RuleSentence rule={{ agent_or_profile: '*', action: 'file_read', target: 'docs/notes.txt', response: 'block' }} />,
    );
    expect(html).toContain('When any agent asks to read');
    expect(html).toMatch(/<code[^>]*font-mono[^>]*>docs\/notes.txt<\/code>/);
    expect(html).toContain('block it.');
  });
});
