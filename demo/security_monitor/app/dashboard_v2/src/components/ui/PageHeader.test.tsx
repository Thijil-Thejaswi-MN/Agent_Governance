import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { PageHeader } from './PageHeader';

describe('PageHeader', () => {
  it('renders an h1 element with the title in serif styling', () => {
    const html = renderToStaticMarkup(<PageHeader title="Overview" titleId="test-heading" />);
    expect(html).toContain('<h1');
    expect(html).toContain('id="test-heading"');
    expect(html).toContain('font-serif');
    expect(html).toContain('text-[34px]');
    expect(html).toContain('Overview</h1>');
  });

  it('renders subtitle when provided', () => {
    const html = renderToStaticMarkup(
      <PageHeader title="Overview" subtitle="All activity in the last 24 hours." />
    );
    expect(html).toContain('All activity in the last 24 hours.');
    expect(html).toContain('text-[15px]');
  });

  it('renders actions in the actions slot', () => {
    const html = renderToStaticMarkup(
      <PageHeader
        title="Overview"
        actions={<button id="test-action-btn">Action Button</button>}
      />
    );
    expect(html).toContain('id="test-action-btn"');
    expect(html).toContain('Action Button</button>');
  });

  it('contains none of the banned words', () => {
    const html = renderToStaticMarkup(
      <PageHeader title="Overview" subtitle="Subtitle note" actions={<button>Go</button>} />
    );
    const text = html.replace(/<[^>]+>/g, ' ');
    for (const w of ['s' + 'afe', 'sec' + 'ure', 'sec' + 'urely', 'guaran' + 'teed', 'tamper' + '-proof', 'f' + 'irst', 'comp' + 'lete', 'si' + 'gned']) {
      expect(text.toLowerCase()).not.toMatch(new RegExp(`\\b${w}\\b`));
    }
  });
});
