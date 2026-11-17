import { describe, it, expect } from 'vitest';
// @ts-ignore
import fs from 'node:fs';
// @ts-ignore
import path from 'node:path';
import { PROTECTED_PATHS, isProtectedPath } from '../../logic/protectedPaths';
import * as AppLayoutExports from './AppLayout';

declare const __dirname: string;

describe('protectedPaths', () => {
  it('exports PROTECTED_PATHS and isProtectedPath from AppLayout', () => {
    expect(AppLayoutExports.PROTECTED_PATHS).toBeDefined();
    expect(Array.isArray(AppLayoutExports.PROTECTED_PATHS)).toBe(true);
    expect(typeof AppLayoutExports.isProtectedPath).toBe('function');
  });

  it('covers all page routes in App.tsx except exempt public routes', () => {
    // Resolve App.tsx via node path / fs or import.meta.url
    const basePath = typeof __dirname !== 'undefined' ? __dirname : '.';
    const appTsxPath = path.resolve(basePath, '../../App.tsx');
    const content = fs.readFileSync(appTsxPath, 'utf-8');

    // Collect every <Route path="..." element={page(...)} />
    const routeTagRegex = /<Route\b([^>]+)>/g;
    const matchedPaths: string[] = [];
    let match: RegExpExecArray | null;

    while ((match = routeTagRegex.exec(content)) !== null) {
      const attrs = match[1];
      if (/element=\{page\(/.test(attrs)) {
        const pathMatch = /path=["']([^"']+)["']/.exec(attrs);
        if (pathMatch) {
          matchedPaths.push(pathMatch[1]);
        }
      }
    }

    expect(matchedPaths.length).toBeGreaterThan(0);

    const exempt = new Set(['signin', 'results', '*']);

    for (const routePath of matchedPaths) {
      if (exempt.has(routePath)) {
        continue;
      }

      const baseSegment = routePath.split('/')[0];
      const withSlash = `/${baseSegment}`;

      const inProtectedList =
        PROTECTED_PATHS.includes(withSlash) ||
        PROTECTED_PATHS.includes(`/${routePath}`) ||
        PROTECTED_PATHS.includes(baseSegment) ||
        PROTECTED_PATHS.includes(routePath);

      expect(
        inProtectedList,
        `Expected route "${routePath}" to be present in PROTECTED_PATHS`
      ).toBe(true);

      expect(
        isProtectedPath(`/${routePath}`),
        `Expected isProtectedPath("/${routePath}") to be true`
      ).toBe(true);
    }
  });
});
