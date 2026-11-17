import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MetricCard } from './MetricCard';

describe('MetricCard', () => {
  it('renders label, value, and note with tallie metric card styling', () => {
    const html = renderToStaticMarkup(
      <MetricCard
        id="test-card"
        valueId="test-val"
        label="Waiting now"
        value={12}
        note="in 3 groups"
        tone="wait"
      />
    );
    expect(html).toContain('id="test-card"');
    expect(html).toContain('id="test-val"');
    expect(html).toContain('Waiting now');
    expect(html).toContain('12');
    expect(html).toContain('in 3 groups');
    expect(html).toContain('h-36');
    expect(html).toContain('text-3xl');
    expect(html).toContain('tabular-nums');
    expect(html).toContain('text-wait-kpi');
  });

  it('renders default tone and handles optional note', () => {
    const html = renderToStaticMarkup(
      <MetricCard label="Total items" value="42" />
    );
    expect(html).toContain('Total items');
    expect(html).toContain('42');
    expect(html).toContain('text-fg');
  });
});
