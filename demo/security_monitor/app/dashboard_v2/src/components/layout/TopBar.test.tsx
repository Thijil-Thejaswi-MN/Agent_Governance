import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { TopBar } from './TopBar';

describe('TopBar component', () => {
  it('renders Agent conversations breadcrumb on /conversations/:id without Page not found', () => {
    const html = renderToStaticMarkup(
      <MemoryRouter initialEntries={['/conversations/task_planner_123']}>
        <TopBar />
      </MemoryRouter>
    );
    expect(html).toContain('Agent conversations');
    expect(html).toContain('Runtime');
    expect(html).not.toContain('Page not found');
  });
});
