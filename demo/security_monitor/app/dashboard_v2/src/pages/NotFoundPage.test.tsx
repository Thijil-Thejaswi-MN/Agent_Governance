import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { NotFoundPage } from './NotFoundPage';

describe('NotFoundPage', () => {
  it('renders the h1 heading, shows the pathname and the button links to "/"', () => {
    const testPath = '/custom/non-existent-path';
    const html = renderToStaticMarkup(
      <MemoryRouter initialEntries={[testPath]}>
        <NotFoundPage />
      </MemoryRouter>
    );

    // <h1> heading
    expect(html).toContain("This page doesn&#x27;t exist.");

    // pathname in code element
    expect(html).toContain(testPath);
    expect(html).toContain(`title="${testPath}"`);
    expect(html).toContain("isn&#x27;t part of the console. It may have moved, or the link was typed wrong.");

    // screen reader 404
    expect(html).toContain('class="sr-only">404</span>');

    // Button links to "/"
    expect(html).toContain('href="/"');
    expect(html).toContain('Go back home');
  });

  it('contains none of the banned words', () => {
    const html = renderToStaticMarkup(
      <MemoryRouter initialEntries={['/test']}>
        <NotFoundPage />
      </MemoryRouter>
    );
    const text = html.replace(/<[^>]+>/g, ' ');
    for (const w of ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed']) {
      expect(text.toLowerCase()).not.toMatch(new RegExp(`\\b${w}\\b`));
    }
  });
});
