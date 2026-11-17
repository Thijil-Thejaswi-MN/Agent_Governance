import { describe, expect, it } from 'vitest';
import { planUploads } from './uploadFiles';

describe('planUploads', () => {
  it('adds valid text files under input/', () => {
    const existing = {};
    const incoming = [
      { name: 'sales.csv', text: 'col1,col2\n1,2', bytes: 14 },
      { name: 'notes.md', text: '# Notes', bytes: 7 },
    ];
    const { added, errors } = planUploads(existing, incoming);
    expect(errors).toEqual([]);
    expect(added).toEqual({
      'input/sales.csv': 'col1,col2\n1,2',
      'input/notes.md': '# Notes',
    });
  });

  it('rejects unsupported file extensions with plain message', () => {
    const { added, errors } = planUploads({}, [
      { name: 'report.pdf', text: 'dummy', bytes: 5 },
      { name: 'image.png', text: 'dummy', bytes: 5 },
    ]);
    expect(added).toEqual({});
    expect(errors).toContain('report.pdf: only text files (TXT, CSV, TSV, MD, JSON, YAML, LOG).');
    expect(errors).toContain('image.png: only text files (TXT, CSV, TSV, MD, JSON, YAML, LOG).');
  });

  it('rejects files larger than 50 KB', () => {
    const bigBytes = 51201;
    const { added, errors } = planUploads({}, [
      { name: 'big.csv', text: 'large content', bytes: bigBytes },
    ]);
    expect(added).toEqual({});
    expect(errors).toContain('big.csv is larger than 50 KB.');
  });

  it('rejects files containing null bytes or binary format', () => {
    const { added, errors } = planUploads({}, [
      { name: 'data.bin', text: 'hello', bytes: 5 },
      { name: 'corrupted.txt', text: 'hello\x00world', bytes: 11 },
    ]);
    expect(added).toEqual({});
    expect(errors).toContain('data.bin is not a text file.');
    expect(errors).toContain('corrupted.txt is not a text file.');
  });

  it('enforces maximum limit of 3 files', () => {
    const existing = {
      'input/file1.txt': '1',
      'input/file2.txt': '2',
    };
    const incoming = [
      { name: 'file3.txt', text: '3', bytes: 1 },
      { name: 'notes.txt', text: '4', bytes: 1 },
    ];
    const { added, errors } = planUploads(existing, incoming);
    expect(added).toEqual({
      'input/file3.txt': '3',
    });
    expect(errors).toContain('At most 3 files: notes.txt was not added.');
  });

  it('strips folder paths to take base name only', () => {
    const { added, errors } = planUploads({}, [
      { name: 'deep/nested/folder/summary.txt', text: 'content', bytes: 7 },
    ]);
    expect(errors).toEqual([]);
    expect(added).toEqual({
      'input/summary.txt': 'content',
    });
  });

  it('rejects names with .. or backslashes', () => {
    const { added, errors } = planUploads({}, [
      { name: '../secret.txt', text: 'content', bytes: 7 },
      { name: 'sub\\secret.txt', text: 'content', bytes: 7 },
    ]);
    expect(added).toEqual({});
    expect(errors).toHaveLength(2);
    expect(errors[0]).toContain('name cannot contain .. or backslashes');
    expect(errors[1]).toContain('name cannot contain .. or backslashes');
  });

  it('resolves name collisions with -2, -3 suffix before extension', () => {
    const existing = {
      'input/report.csv': 'v1',
    };
    const incoming = [
      { name: 'report.csv', text: 'v2', bytes: 2 },
      { name: 'report.csv', text: 'v3', bytes: 2 },
    ];
    const { added, errors } = planUploads(existing, incoming);
    expect(errors).toEqual([]);
    expect(added).toEqual({
      'input/report-2.csv': 'v2',
      'input/report-3.csv': 'v3',
    });
  });

  it('contains no banned words in error messages', () => {
    const { errors } = planUploads({ 'input/1.txt': '', 'input/2.txt': '', 'input/3.txt': '' }, [
      { name: 'overflow.pdf', text: 'bad\x00content', bytes: 100000 },
    ]);
    const combined = errors.join(' ').toLowerCase();
    for (const banned of ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed']) {
      expect(combined).not.toMatch(new RegExp(`\\b${banned}\\b`));
    }
  });
});
