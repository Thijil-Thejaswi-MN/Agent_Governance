import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { BoundaryPreviewResponse, RunPreset } from '../types';
import { fileName } from '../logic/runView';

// Plain names for the existing presets (the ids and their prompts are the server's).
const PRESET_LABELS: Record<string, string> = {
  summarise_csv: 'Summarise a file',
  compare_target: 'Needs one more file',
  hidden_instruction: 'A file tries to trick the agent',
};

const MAX_FILES = 3;
const MAX_FILE_BYTES = 51200;

const joinNames = (xs: string[]) =>
  xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`;

export const AskPage: React.FC = () => {
  const navigate = useNavigate();
  const { hasToken, openAuthModal } = useAuth();

  const [presets, setPresets] = useState<RunPreset[]>([]);
  const [presetId, setPresetId] = useState('summarise_csv');
  const [models, setModels] = useState<string[]>(['scripted']);
  const [model, setModel] = useState('scripted');
  const [prompt, setPrompt] = useState('');
  const [files, setFiles] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<BoundaryPreviewResponse | null>(null);
  const [activeTask, setActiveTask] = useState<string | null>(null);

  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [problems, setProblems] = useState<string[]>([]);

  const [showAddFile, setShowAddFile] = useState(false);
  const [newPath, setNewPath] = useState('input/data.txt');
  const [newContent, setNewContent] = useState('');
  const [fileError, setFileError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.getRunPresets(), api.getRunModels(), api.getActiveRun()])
      .then(([ps, ms, active]) => {
        setPresets(ps);
        const all = [...ms.models];
        if (!all.includes('scripted')) all.push('scripted');
        setModels(all);
        setModel(ms.default || 'scripted');
        const first = ps.find(p => p.id === 'summarise_csv') || ps[0];
        if (first) {
          setPresetId(first.id);
          setPrompt(first.prompt);
          setFiles({ ...first.files });
        }
        if (active.active && active.task_id) setActiveTask(active.task_id);
      })
      .catch(err => console.error('Failed to load run configuration:', err));
  }, []);

  // What the request will allow, in names only.
  useEffect(() => {
    if (!prompt.trim()) {
      setPreview(null);
      return;
    }
    const t = setTimeout(() => {
      api.previewRun({ prompt, preset: presetId, files }).then(setPreview).catch(() => setPreview(null));
    }, 400);
    return () => clearTimeout(t);
  }, [prompt, presetId, files]);

  const choosePreset = (p: RunPreset) => {
    setPresetId(p.id);
    setPrompt(p.prompt);
    setFiles({ ...p.files });
    setError(null);
    setProblems([]);
  };

  const addFile = () => {
    setFileError(null);
    const path = newPath.trim();
    if (!path) return setFileError('Give the file a name.');
    if (!path.startsWith('input/')) return setFileError('The name must begin with input/');
    if (path.includes('..') || path.includes('\\')) return setFileError('The name cannot contain .. or backslashes.');
    if (Object.keys(files).length >= MAX_FILES && !files[path]) return setFileError(`At most ${MAX_FILES} files.`);
    if (new Blob([newContent]).size > MAX_FILE_BYTES) return setFileError('The file is larger than 50 KB.');
    setFiles(f => ({ ...f, [path]: newContent }));
    setNewPath('input/');
    setNewContent('');
    setShowAddFile(false);
  };

  const start = async () => {
    setError(null);
    setProblems([]);
    if (!prompt.trim()) {
      setError('Write what the agent should do.');
      return;
    }
    if (!hasToken) {
      openAuthModal();
      return;
    }
    setStarting(true);
    try {
      const res = await api.startRun({ prompt: prompt.trim(), preset: presetId, model, files });
      navigate(`/run/${res.task_id}`);
    } catch (err: any) {
      // Nothing was started: stay here and say why.
      setError(err.message || 'The run could not start.');
      setProblems(err.problems || []);
      if (err?.status === 409) {
        api.getActiveRun().then(a => setActiveTask(a.task_id)).catch(() => {});
      }
    } finally {
      setStarting(false);
    }
  };

  const reads = [...new Set((preview?.boundary_v1.files_read || []).map(fileName))];
  const writes = [...new Set((preview?.boundary_v1.files_write || []).map(fileName))];
  const fileNames = Object.keys(files).map(fileName);

  return (
    <div className="relative" style={{ overflow: 'clip', minHeight: 'calc(100vh - 88px)' }}>
      <div aria-hidden="true" className="absolute rounded-full pointer-events-none" style={{ width: 700, height: 700, left: -200, top: -300, background: 'radial-gradient(circle, rgba(34,211,238,0.28), transparent 65%)', animation: 'drift 16s ease-in-out infinite' }} />
      <div aria-hidden="true" className="absolute rounded-full pointer-events-none" style={{ width: 700, height: 700, right: -220, bottom: -320, background: 'radial-gradient(circle, rgba(167,139,250,0.28), transparent 65%)', animation: 'drift2 18s ease-in-out infinite' }} />

      <div className="relative max-w-[760px] mx-auto px-4 sm:px-6 pt-14 sm:pt-24 pb-16 flex flex-col items-center gap-7 text-center">
        <h1 className="m-0 font-display font-bold text-[38px] sm:text-[52px] leading-[1.08] tracking-[-1.2px]">What should the agent do?</h1>
        <p className="m-0 text-[18px]" style={{ color: 'var(--text-2)' }}>
          It can only touch what your request needs. Anything else is blocked, or you decide.
        </p>

        {activeTask && (
          <div id="active-run-banner" className="w-full px-4 py-3 rounded-2xl text-[15px] text-left" style={{ background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.35)' }}>
            An agent is already working. Only one runs at a time. <Link to={`/run/${activeTask}`}>Watch it</Link>
          </div>
        )}

        <div className="w-full flex flex-col gap-3 p-3.5 text-left" style={{ borderRadius: 22, background: 'rgba(18,24,41,0.9)', border: '1px solid rgba(34,211,238,0.35)', boxShadow: '0 20px 60px rgba(34,211,238,0.12)' }}>
          <label htmlFor="prompt-input" className="sr-only">
            Your request
          </label>
          <textarea
            id="prompt-input"
            rows={3}
            value={prompt}
            onChange={e => setPrompt(e.target.value)}
            placeholder="For example: read sales_data.csv and write a short summary."
            className="w-full resize-none border-none outline-none bg-transparent text-[18px] leading-normal p-2"
            style={{ color: 'var(--text)' }}
          />
          <div className="flex flex-wrap items-center justify-between gap-3 px-1">
            <label className="flex items-center gap-2 text-[14px]" style={{ color: 'var(--text-2)' }}>
              Model
              <select
                id="model-selector"
                value={model}
                onChange={e => setModel(e.target.value)}
                className="min-h-[44px] px-3 rounded-xl text-[14px] outline-none"
                style={{ background: 'var(--field)', color: 'var(--text)', border: '1px solid rgba(148,163,184,0.3)' }}
              >
                {models.map(m => (
                  <option key={m} value={m}>
                    {m === 'scripted' ? 'scripted (deterministic)' : m}
                  </option>
                ))}
              </select>
            </label>
            <button id="start-run-btn" onClick={start} disabled={starting} className="btn-primary">
              {starting ? 'Starting…' : 'Start'}
            </button>
          </div>
        </div>

        {preview && (reads.length > 0 || writes.length > 0) && (
          <p id="allow-preview" className="m-0 text-[15px]" style={{ color: 'var(--text-2)' }}>
            {reads.length > 0 && <>It will be able to read {joinNames(reads)}</>}
            {reads.length > 0 && writes.length > 0 && ' and '}
            {writes.length > 0 && <>{reads.length > 0 ? 'write ' : 'It will be able to write '}{joinNames(writes)}</>}. Nothing else.
          </p>
        )}

        {error && (
          <div id="run-error" role="alert" className="w-full text-left px-5 py-4 rounded-2xl" style={{ background: 'rgba(251,113,133,0.08)', border: '1px solid rgba(251,113,133,0.4)', color: '#FECDD3' }}>
            <div className="font-semibold text-[16px]">
              {problems.length > 0 ? "This computer can't run a fenced agent right now." : 'The run could not start.'}
            </div>
            <details className="mt-2" data-details>
              <summary className="cursor-pointer text-[14px] min-h-[32px]" style={{ color: '#FDA4AF' }}>
                Details
              </summary>
              <div className="mt-2 mono text-[13px] space-y-1" style={{ color: '#FECDD3' }}>
                <div>{error}</div>
                {problems.length > 0 && (
                  <ul className="list-disc pl-5 m-0">
                    {problems.map(p => (
                      <li key={p}>{p}</li>
                    ))}
                  </ul>
                )}
              </div>
            </details>
          </div>
        )}

        <div className="flex flex-wrap justify-center gap-2.5">
          <span className="self-center text-[14px]" style={{ color: 'var(--text-3)' }}>
            Try:
          </span>
          {presets
            .filter(p => p.id !== 'custom')
            .map(p => (
              <button
                key={p.id}
                id={`preset-${p.id}`}
                type="button"
                aria-pressed={presetId === p.id}
                onClick={() => choosePreset(p)}
                className="min-h-[44px] px-4 rounded-full text-[14px] cursor-pointer"
                style={{
                  border: presetId === p.id ? '1px solid rgba(34,211,238,0.7)' : '1px solid rgba(148,163,184,0.3)',
                  background: presetId === p.id ? 'rgba(34,211,238,0.12)' : 'transparent',
                  color: 'var(--text)',
                }}
              >
                {PRESET_LABELS[p.id] || p.name}
              </button>
            ))}
        </div>

        <div className="text-[14px] flex flex-wrap justify-center items-center gap-x-3 gap-y-1" style={{ color: 'var(--text-3)' }}>
          {fileNames.length > 0 ? <span id="attached-files">Files given to the agent: {joinNames(fileNames)}.</span> : <span>No files given to the agent.</span>}
          {Object.keys(files).length < MAX_FILES && (
            <button className="link-btn text-[14px]" onClick={() => setShowAddFile(v => !v)} aria-expanded={showAddFile}>
              {showAddFile ? 'Cancel' : 'Add your own file'}
            </button>
          )}
          {Object.keys(files).length > 0 && (
            <button className="link-btn text-[14px]" onClick={() => setFiles({})}>
              Remove files
            </button>
          )}
        </div>

        {showAddFile && (
          <div className="w-full card p-4 text-left space-y-3">
            <label className="block text-[14px]">
              File name
              <input
                value={newPath}
                onChange={e => setNewPath(e.target.value)}
                className="mt-1 w-full min-h-[44px] px-3 rounded-xl mono text-[14px] outline-none"
                style={{ background: 'var(--field)', color: 'var(--text)', border: '1px solid rgba(148,163,184,0.3)' }}
              />
            </label>
            <label className="block text-[14px]">
              Text (up to 50 KB)
              <textarea
                rows={4}
                value={newContent}
                onChange={e => setNewContent(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded-xl mono text-[13px] outline-none"
                style={{ background: 'var(--field)', color: 'var(--text)', border: '1px solid rgba(148,163,184,0.3)' }}
              />
            </label>
            {fileError && (
              <div className="text-[14px]" style={{ color: '#FDA4AF' }}>
                {fileError}
              </div>
            )}
            <button className="btn-ghost" onClick={addFile}>
              Add file
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
