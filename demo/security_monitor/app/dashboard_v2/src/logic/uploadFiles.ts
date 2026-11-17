export const MAX_FILES = 3;
export const MAX_FILE_BYTES = 51200;

export const ALLOWED_EXTENSIONS = [
  '.txt',
  '.csv',
  '.tsv',
  '.md',
  '.json',
  '.yaml',
  '.yml',
  '.log',
];

export interface UploadFileInput {
  name: string;
  text: string;
  bytes: number;
}

export interface PlanUploadsResult {
  added: Record<string, string>;
  errors: string[];
}

export function planUploads(
  existing: Record<string, string>,
  incoming: UploadFileInput[]
): PlanUploadsResult {
  const added: Record<string, string> = {};
  const errors: string[] = [];

  let currentCount = Object.keys(existing).length;

  for (const item of incoming) {
    const rawName = item.name.trim();

    // Check invalid path characters
    if (rawName.includes('..') || rawName.includes('\\')) {
      errors.push(`${rawName}: name cannot contain .. or backslashes.`);
      continue;
    }

    // Take base name only (strip any folder paths)
    const baseName = rawName.split('/').filter(Boolean).pop() || rawName;

    // Check total file limit (at most 3 files)
    if (currentCount >= MAX_FILES) {
      errors.push(`At most ${MAX_FILES} files: ${baseName} was not added.`);
      continue;
    }

    // Check binary / NUL characters
    if (item.text.includes('\x00') || baseName.toLowerCase().endsWith('.bin')) {
      errors.push(`${baseName} is not a text file.`);
      continue;
    }

    // Check allowed extension
    const lowerName = baseName.toLowerCase();
    const hasAllowedExt = ALLOWED_EXTENSIONS.some(ext => lowerName.endsWith(ext));
    if (!hasAllowedExt) {
      errors.push(`${baseName}: only text files (TXT, CSV, TSV, MD, JSON, YAML, LOG).`);
      continue;
    }

    // Check size limit (max 50 KB / 51200 bytes)
    const byteLength = item.bytes ?? new TextEncoder().encode(item.text).length;
    if (byteLength > MAX_FILE_BYTES) {
      errors.push(`${baseName} is larger than 50 KB.`);
      continue;
    }

    // Resolve name collisions under input/
    let candidate = `input/${baseName}`;
    if (existing[candidate] !== undefined || added[candidate] !== undefined) {
      const lastDot = baseName.lastIndexOf('.');
      const stem = lastDot > 0 ? baseName.slice(0, lastDot) : baseName;
      const ext = lastDot > 0 ? baseName.slice(lastDot) : '';
      let counter = 2;
      while (
        existing[`input/${stem}-${counter}${ext}`] !== undefined ||
        added[`input/${stem}-${counter}${ext}`] !== undefined
      ) {
        counter++;
      }
      candidate = `input/${stem}-${counter}${ext}`;
    }

    added[candidate] = item.text;
    currentCount++;
  }

  return { added, errors };
}
