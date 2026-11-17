import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import { FileDrop, handleDropZoneKeyDown } from './FileDrop';

describe('FileDrop component', () => {
  it('renders title, subtitle, browse button, and hint line', () => {
    const html = renderToStaticMarkup(
      <FileDrop files={{}} onFilesChange={() => {}} />
    );

    expect(html).toContain('Give the agent a file');
    expect(html).toContain('Text files only: up to 3 files, 50 KB each. The agent finds them in input/.');
    expect(html).toContain('Click to upload');
    expect(html).toContain('or drag and drop');
    expect(html).toContain('Browse files');
    expect(html).toContain('TXT, CSV, TSV, MD, JSON, YAML or LOG (max. 50 KB)');
    expect(html).toContain('aria-label="File upload drop area"');
    expect(html).toContain('type="file"');
  });

  it('triggers click on input via keyboard (Enter or Space)', () => {
    const inputMock = { click: vi.fn() };
    const preventDefault = vi.fn();

    // Enter key triggers click
    const enterHandled = handleDropZoneKeyDown({ key: 'Enter', preventDefault }, false, inputMock);
    expect(enterHandled).toBe(true);
    expect(inputMock.click).toHaveBeenCalledTimes(1);
    expect(preventDefault).toHaveBeenCalledTimes(1);

    // Space key triggers click
    const spaceHandled = handleDropZoneKeyDown({ key: ' ', preventDefault }, false, inputMock);
    expect(spaceHandled).toBe(true);
    expect(inputMock.click).toHaveBeenCalledTimes(2);

    // Other keys do nothing
    const otherHandled = handleDropZoneKeyDown({ key: 'Tab', preventDefault }, false, inputMock);
    expect(otherHandled).toBe(false);
    expect(inputMock.click).toHaveBeenCalledTimes(2);

    // Does nothing when limit is reached
    const disabledHandled = handleDropZoneKeyDown({ key: 'Enter', preventDefault }, true, inputMock);
    expect(disabledHandled).toBe(false);
    expect(inputMock.click).toHaveBeenCalledTimes(2);
  });

  it('shows an error for a too-large file in role="alert"', () => {
    const html = renderToStaticMarkup(
      <FileDrop
        files={{}}
        onFilesChange={() => {}}
        testErrors={['big.csv is larger than 50 KB.']}
      />
    );

    expect(html).toContain('role="alert"');
    expect(html).toContain('big.csv is larger than 50 KB.');
  });

  it('shows disabled state and limit message when 3 files are added', () => {
    const threeFiles = {
      'input/f1.txt': '1',
      'input/f2.txt': '2',
      'input/f3.txt': '3',
    };
    const html = renderToStaticMarkup(
      <FileDrop files={threeFiles} onFilesChange={() => {}} />
    );

    expect(html).toContain('3 files added: remove one to add another');
    expect(html).toContain('aria-disabled="true"');
    expect(html).not.toContain('Browse files');
  });

  it('contains no banned words in UI copy', () => {
    const html = renderToStaticMarkup(
      <FileDrop files={{}} onFilesChange={() => {}} />
    );

    const bannedWords = ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed'];
    for (const word of bannedWords) {
      expect(html.toLowerCase()).not.toMatch(new RegExp(`\\b${word}\\b`));
    }
  });
});
