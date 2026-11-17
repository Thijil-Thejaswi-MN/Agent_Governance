import { describe, expect, it } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { FileReview, FileReviewResult, dropReason } from './FileReview';

const base: FileReviewResult = {
  review_id: 'review_1',
  model: 'qwen2.5:7b',
  fallback: false,
  fallback_reason: null,
  reads: [
    { path: 'input/sales_q3.csv', named: false },
    { path: 'input/sales_q2.csv', named: true },
  ],
  writes: [{ path: 'output/summary.txt', named: true }],
  dropped: [{ field: 'files_read', entry: '~/.ssh/id_rsa', reason: 'outside_workspace' }],
  inputs: ['input/payroll.csv', 'input/sales_q2.csv', 'input/sales_q3.csv'],
};

describe('FileReview', () => {
  it('shows each chosen file with where it came from, and what the rules left out', () => {
    const html = renderToStaticMarkup(<FileReview result={base} agentName="Finance Bot" kept={['input/sales_q3.csv']} onToggle={() => {}} />);
    expect(html).toContain("Finance Bot&#x27;s model (qwen2.5:7b) chose these files.");
    expect(html).toContain('chosen by the model: check it');
    expect(html).toContain('named in your request');
    expect(html).toContain('id="review-read-sales_q3.csv" checked=""');
    expect(html).not.toContain('id="review-read-sales_q2.csv" checked=""');
    expect(html).toContain('outside the task folder');
    expect(html).toContain('It may write');
  });

  it('says plainly when the model could not be asked', () => {
    const html = renderToStaticMarkup(
      <FileReview result={{ ...base, fallback: true, fallback_reason: 'connection refused' }} agentName="Finance Bot" kept={[]} onToggle={() => {}} />,
    );
    expect(html).toContain('id="file-review-fallback"');
    expect(html).toContain('only the files your request names are allowed');
  });

  it('maps every rule reason to plain words', () => {
    for (const r of ['outside_workspace', 'reserved_folder', 'wildcard', 'not_an_input_file', 'write_outside_output', 'not_in_catalog', 'not_named_in_request']) {
      expect(dropReason(r)).not.toContain('_');
    }
  });
});
