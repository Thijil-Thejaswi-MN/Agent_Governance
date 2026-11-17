import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Button } from './Button';

describe('Button component', () => {
  it('renders primary variant with accent-grad background', () => {
    const html = renderToStaticMarkup(
      <Button variant="primary" id="btn-submit">
        Action
      </Button>
    );
    expect(html).toContain('id="btn-submit"');
    expect(html).toContain('var(--accent-grad)');
    expect(html).toContain('text-white');
    expect(html).toContain('Action');
  });

  it('renders secondary variant with surface-2 and line border', () => {
    const html = renderToStaticMarkup(
      <Button variant="secondary">
        Cancel
      </Button>
    );
    expect(html).toContain('bg-surface-2');
    expect(html).toContain('border-line');
    expect(html).toContain('Cancel');
  });

  it('renders ghost variant with transparent background', () => {
    const html = renderToStaticMarkup(
      <Button variant="ghost">
        Options
      </Button>
    );
    expect(html).toContain('bg-transparent');
    expect(html).toContain('hover:bg-surface-2');
    expect(html).toContain('Options');
  });

  it('renders danger variant with bad tint and bad text', () => {
    const html = renderToStaticMarkup(
      <Button variant="danger">
        Delete
      </Button>
    );
    expect(html).toContain('bg-bad-tint');
    expect(html).toContain('text-bad');
    expect(html).toContain('Delete');
  });

  it('supports button sizes and custom attributes', () => {
    const htmlSm = renderToStaticMarkup(<Button size="sm">Small</Button>);
    expect(htmlSm).toContain('h-8');

    const htmlIcon = renderToStaticMarkup(<Button size="icon" aria-label="Icon">X</Button>);
    expect(htmlIcon).toContain('h-9');
    expect(htmlIcon).toContain('w-9');
    expect(htmlIcon).toContain('aria-label="Icon"');

    const htmlDisabled = renderToStaticMarkup(<Button disabled>Disabled</Button>);
    expect(htmlDisabled).toContain('disabled');
  });

  it('contains no banned words in copy or classes', () => {
    const banned = ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed'];
    const html = renderToStaticMarkup(
      <div>
        <Button variant="primary">Proceed</Button>
        <Button variant="secondary">Back</Button>
        <Button variant="ghost">Close</Button>
        <Button variant="danger">Terminate</Button>
      </div>
    );
    for (const b of banned) {
      expect(html.toLowerCase()).not.toContain(b);
    }
  });
});
