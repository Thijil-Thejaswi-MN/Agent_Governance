import React from 'react';
import { fileName } from '../../logic/runView';

/** The model's file choice for a run, checked by fixed rules on the server (derivation_grounded.py). */
export interface FileReviewResult {
  review_id: string;
  model: string;
  fallback: boolean;
  fallback_reason: string | null;
  reads: { path: string; named: boolean }[];
  writes: { path: string; named: boolean }[];
  dropped: { field: string; entry: string; reason: string }[];
  inputs: string[];
}

const DROP_REASON: Record<string, string> = {
  outside_workspace: 'outside the task folder',
  reserved_folder: 'a system folder',
  wildcard: 'a wildcard, not a file',
  not_an_input_file: "not one of this task's files",
  write_outside_output: 'new files can only go in output/',
  not_in_catalog: 'not an approved site or agent',
  not_named_in_request: "your request doesn't name it",
  not_named_no_inputs_listed: "your request doesn't name it",
};

export function dropReason(reason: string): string {
  return DROP_REASON[reason] || reason.replace(/_/g, ' ');
}

export const FileReview: React.FC<{
  result: FileReviewResult;
  agentName: string;
  kept: string[];
  onToggle: (path: string) => void;
}> = ({ result, agentName, kept, onToggle }) => {
  if (result.fallback) {
    return (
      <div id="file-review" className="flex flex-col gap-1.5 text-[14px]" style={{ color: 'var(--text-2)' }}>
        <span id="file-review-fallback" style={{ color: '#FBBF24' }}>
          {agentName}'s model ({result.model}) could not be asked, so only the files your request names are allowed.
        </span>
        {result.fallback_reason && <span className="mono text-[12px]" style={{ color: 'var(--text-3)' }}>{result.fallback_reason}</span>}
      </div>
    );
  }
  const inferred = result.reads.filter(r => !r.named).length;
  return (
    <div id="file-review" className="flex flex-col gap-2 rounded-xl px-4 py-3 border border-[#1F2633] bg-[#0E121A]">
      <span className="text-[14px] font-semibold" style={{ color: '#E6E9EF' }}>
        {result.reads.length === 0
          ? `${agentName}'s model (${result.model}) says this task needs none of its files.`
          : `${agentName}'s model (${result.model}) chose these files. Untick any it should not read.`}
      </span>
      {result.reads.map(r => (
        <label key={r.path} className="flex items-center gap-2.5 text-[14px] cursor-pointer" data-file={r.path}>
          <input
            type="checkbox"
            checked={kept.includes(r.path)}
            onChange={() => onToggle(r.path)}
            className="rounded border-[#2A3344] bg-[#0E121A]"
            id={`review-read-${fileName(r.path)}`}
          />
          <span className="mono" style={{ color: '#E6E9EF' }}>{fileName(r.path)}</span>
          <span style={{ color: r.named ? 'var(--text-3)' : '#FBBF24' }}>
            {r.named ? 'named in your request' : 'chosen by the model: check it'}
          </span>
        </label>
      ))}
      {result.writes.length > 0 && (
        <span className="text-[14px]" id="file-review-writes" style={{ color: 'var(--text-2)' }}>
          It may write{' '}
          {result.writes.map((w, i) => (
            <React.Fragment key={w.path}>
              {i > 0 ? ', ' : ''}
              <span className="mono">{fileName(w.path)}</span>
            </React.Fragment>
          ))}
          .
        </span>
      )}
      {result.dropped.length > 0 && (
        <div className="flex flex-col gap-0.5 text-[13px]" id="file-review-dropped" style={{ color: 'var(--text-3)' }}>
          <span>Left out by the rules:</span>
          {result.dropped.map(d => (
            <span key={`${d.field}:${d.entry}`}>
              <span className="mono">{d.entry}</span> ({dropReason(d.reason)})
            </span>
          ))}
        </div>
      )}
      {inferred > 0 && (
        <span className="text-[13px]" style={{ color: 'var(--text-3)' }}>
          Nothing else can be read. If the agent needs more, it will ask you during the run.
        </span>
      )}
    </div>
  );
};
