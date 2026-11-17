import { describe, it, expect } from 'vitest';
// @ts-ignore
import fs from 'node:fs';
// @ts-ignore
import path from 'node:path';

// Explicit allow-list of files permitted to contain raw hex colour literals
export const ALLOW_LIST: Record<string, string> = {
  'components/landing/': 'Landing presentation components retain bespoke marketing styling',
  'components/effects/': 'Background effects and interactive canvas/spark particle shaders',
  'pages/SignInPage.tsx': 'Marketing sign-in hero with specialized beam and halftone gradients',
  'pages/NotFoundPage.tsx': 'Custom 404 page background grid and decorative SVG lines',
  'components/v3/Fence.tsx': 'Technical diagram fence illustration SVG artwork',
  'components/v3/DotField.tsx': 'High-density HTML5 canvas fleet dots rendering',
};

function getAllTsxFiles(dir: string, fileList: string[] = []): string[] {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      getAllTsxFiles(filePath, fileList);
    } else if (file.endsWith('.tsx') && !file.endsWith('.test.tsx')) {
      fileList.push(filePath);
    }
  }
  return fileList;
}

describe('noRawColours', () => {
  it('ensures no hard-coded hex colour literals exist in unallowed .tsx files', () => {
    // @ts-ignore
    const dir = typeof __dirname !== 'undefined' ? __dirname : '';
    const srcDir = path.resolve(dir, '..');
    const allFiles = getAllTsxFiles(srcDir);
    const hexPattern = /#[0-9a-fA-F]{3,8}\b/g;

    const violations: Array<{ file: string; line: number; match: string }> = [];

    for (const filePath of allFiles) {
      const relPath = path.relative(srcDir, filePath).replace(/\\/g, '/');

      // Check if file is in allow-list
      const isAllowed = Object.keys(ALLOW_LIST).some(allowed =>
        relPath === allowed || relPath.startsWith(allowed) || relPath.includes(allowed)
      );

      if (isAllowed) {
        continue;
      }

      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      lines.forEach((line: string, index: number) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
          return;
        }
        const matches = line.match(hexPattern);
        if (matches) {
          for (const m of matches) {
            violations.push({
              file: relPath,
              line: index + 1,
              match: m,
            });
          }
        }
      });
    }

    if (violations.length > 0) {
      const summary = violations
        .slice(0, 30)
        .map(v => `  ${v.file}:${v.line} -> ${v.match}`)
        .join('\n');
      expect.fail(
        `Found ${violations.length} raw hex colour literals in .tsx files:\n${summary}${
          violations.length > 30 ? `\n  ... and ${violations.length - 30} more` : ''
        }`
      );
    }

    expect(violations.length).toBe(0);
  });
});
