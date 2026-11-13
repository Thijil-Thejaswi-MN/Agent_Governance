import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { BoundaryPreviewResponse, RunPreset, ConfiguredAgent, ActiveRunTask } from '../types';
import { fileName } from '../logic/runView';

// Plain names for the existing presets (the ids and their prompts are the server's).
const PRESET_LABELS: Record<string, string> = {
  summarise_csv: 'Summarise a file',
  compare_target: 'Needs one more file',
  hidden_instruction: 'A file tries to trick the agent',
  shell_injection: 'A file tricks the agent into a shell command',
  network_exfiltration: 'A file tells the agent to send data to a website',
  a2a_agent: 'Travel planner agent (modelled on Google a2a-samples)',
};

const MAX_FILES = 3;
const MAX_FILE_BYTES = 51200;

const joinNames = (xs: string[]) =>
  xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`;

export const AskPage: React.FC = () => {
  const navigate = useNavigate();
  const { hasToken, openAuthModal, role } = useAuth();
  const [comparisonMode, setComparisonMode] = useState(false);

  const [presets, setPresets] = useState<RunPreset[]>([]);
  const [presetId, setPresetId] = useState('summarise_csv');
  const [models, setModels] = useState<string[]>(['scripted']);
  const [model, setModel] = useState('scripted');
  const [agents, setAgents] = useState<ConfiguredAgent[]>([
    { id: 'finance_bot', name: 'Finance Bot', owner: 'Ana Dev', team: 'finance', description: 'Financial analysis' },
    { id: 'notes_bot', name: 'Notes Bot', owner: 'Ravi K', team: 'core', description: 'Documentation' },
    { id: 'brief_bot', name: 'Brief Bot', owner: 'Meena R', team: 'legal', description: 'Legal briefing' },
  ]);
  const [agentId, setAgentId] = useState<string>('finance_bot');
  const [prompt, setPrompt] = useState('');
  const [files, setFiles] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<BoundaryPreviewResponse | null>(null);
  const [activeTask, setActiveTask] = useState<string | null>(null);
  const [activeCount, setActiveCount] = useState<number>(0);
  const [activeTasks, setActiveTasks] = useState<ActiveRunTask[]>([]);

  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [problems, setProblems] = useState<string[]>([]);

  const [showAddFile, setShowAddFile] = useState(false);
  const [newPath, setNewPath] = useState('input/data.txt');
  const [newContent, setNewContent] = useState('');
  const [fileError, setFileError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.getRunPresets(),
      api.getRunModels(),
      api.getActiveRun(),
      api.getRunAgents().catch(() => [] as ConfiguredAgent[]),
    ])
      .then(([ps, ms, active, ags]) => {
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
        if (ags && ags.length > 0) {
          setAgents(ags);
          setAgentId(prev => (ags.some(a => a.id === prev) ? prev : ags[0].id));
        }
        if (active.active && active.task_id) {
          setActiveTask(active.task_id);
          setActiveCount(active.active_count ?? 1);
          if (active.active_tasks) setActiveTasks(active.active_tasks);
        }
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

  const canCompare = !!presets.find(p => p.id === presetId)?.comparable;

  const choosePreset = (p: RunPreset) => {
    setPresetId(p.id);
    if (!p.comparable) setComparisonMode(false);
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
      const presetFiles = presets.find(p => p.id === presetId)?.files || {};
      const hasUploadedFiles = Object.keys(files).some(k => !(k in presetFiles) || files[k] !== presetFiles[k]);
      if (comparisonMode && canCompare && (!presetId || presetId === 'custom' || hasUploadedFiles)) {
        setError('Comparison mode requires a preset with decoys; custom requests or uploaded files are not allowed.');
        setStarting(false);
        return;
      }
      const res = await api.startRun({ prompt: prompt.trim(), preset: presetId, model, files, agent_id: agentId, comparison_mode: comparisonMode && canCompare });
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
    <div className="max-w-[820px] flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <h1 className="m-0 font-display font-bold text-[28px] sm:text-[32px] leading-[1.15] text-[#E6E9EF]">What should the agent do?</h1>
        <p className="m-0 text-[16px] text-[#A7B0C0]">
          It can only touch what your request needs. Anything else is blocked, or you decide.
        </p>
      </div>

      {activeCount >= 3 ? (
        <div id="active-run-banner" className="w-full px-4 py-3 rounded-xl text-[15px] text-left text-[#F59E0B] bg-[rgba(245,158,11,0.10)] border border-[rgba(245,158,11,0.45)]">
          Maximum concurrent runs reached (3 active runs). Please wait for an active run to complete.
        </div>
      ) : activeCount > 0 ? (
        <div id="active-run-banner" className="w-full px-4 py-3 rounded-xl text-[15px] text-left text-[#E6E9EF] bg-[rgba(59,130,246,0.10)] border border-[rgba(59,130,246,0.45)] flex items-center justify-between">
          <span>{activeCount} agent(s) currently working ({3 - activeCount} slot(s) available).</span>
          <div className="flex items-center gap-2">
            {activeTasks.length > 0 ? (
              activeTasks.map(t => (
                <Link key={t.task_id} to={`/run/${t.task_id}`} className="text-[#3B82F6] hover:underline font-mono text-[13px]">
                  Watch {t.agent_id || t.task_id.slice(0, 8)}
                </Link>
              ))
            ) : (
              activeTask && <Link to={`/run/${activeTask}`} className="text-[#3B82F6] hover:underline font-mono text-[13px]">Watch active run</Link>
            )}
          </div>
        </div>
      ) : null}

      <div className="card w-full flex flex-col gap-3 p-3 sm:p-4 text-left border-[#2A3344] focus-within:border-[#3B82F6] transition-colors">
        <label htmlFor="prompt-input" className="sr-only">
          Your request
        </label>
        <textarea
          id="prompt-input"
          rows={3}
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
          placeholder="For example: read sales_data.csv and write a short summary."
          className="w-full resize-none border-none outline-none bg-transparent text-[16px] sm:text-[17px] leading-normal p-2 text-[#E6E9EF] placeholder-[#6B7487]"
        />
        <div className="flex flex-wrap items-center justify-between gap-3 px-1 pt-3 border-t border-[#1F2633]">
          <div className="flex flex-wrap items-center gap-4">
            <AgentSelector agents={agents} value={agentId} onChange={setAgentId} />
            <label className="flex items-center gap-2 text-[14px] text-[#A7B0C0]">
              Model
              <select
                id="model-selector"
                value={model}
                onChange={e => setModel(e.target.value)}
                className="min-h-[44px] sm:min-h-[40px] px-3 rounded-lg text-[14px] outline-none bg-[#0E121A] text-[#E6E9EF] border border-[#2A3344] focus:border-[#3B82F6]"
              >
                {models.map(m => (
                  <option key={m} value={m}>
                    {m === 'scripted' ? 'scripted (deterministic)' : m}
                  </option>
                ))}
              </select>
            </label>
            {role === 'admin' && (
              <label
                className={`flex items-center gap-2 text-[13px] text-[#FBBF24] ${canCompare ? 'cursor-pointer' : 'opacity-60 cursor-not-allowed'}`}
                title={canCompare ? undefined : 'Pick one of the "A file tries to trick the agent" examples to compare'}
              >
                <input
                  type="checkbox"
                  id="comparison-mode-toggle"
                  checked={comparisonMode && canCompare}
                  disabled={!canCompare}
                  onChange={e => {
                    setComparisonMode(e.target.checked);
                    setError(null);
                  }}
                  className="rounded border-[#F59E0B]/40 bg-[#0E121A] text-[#F59E0B] focus:ring-[#F59E0B]"
                />
                <span>Comparison mode: kernel lock off, for demonstration</span>
                {!canCompare && <span className="text-[#8B95A7]">(only for the trick examples)</span>}
              </label>
            )}
          </div>
          <button
            id="start-run-btn"
            onClick={start}
            disabled={starting || activeCount >= 3}
            className="btn-primary min-h-[44px] sm:min-h-[40px] px-6"
          >
            {starting ? 'Starting…' : 'Start'}
          </button>
        </div>
      </div>

      {preview && (reads.length > 0 || writes.length > 0) && (
        <p id="allow-preview" className="m-0 text-[15px] text-[#A7B0C0] flex items-start gap-2">
          <span aria-hidden="true" className="mt-[7px] inline-block w-2 h-2 rounded-[3px] bg-[#22C55E] flex-none" />
          <span>
            {reads.length > 0 && <>It will be able to read {joinNames(reads)}</>}
            {reads.length > 0 && writes.length > 0 && ' and '}
            {writes.length > 0 && <>{reads.length > 0 ? 'write ' : 'It will be able to write '}{joinNames(writes)}</>}. Nothing else.
          </span>
        </p>
      )}

      {error && (
        <div id="run-error" role="alert" className="w-full text-left px-4 py-4 rounded-xl bg-[rgba(239,68,68,0.08)] border border-[rgba(239,68,68,0.45)] text-[#FECACA]">
          <div className="font-semibold text-[16px]">
            {problems.length > 0 ? "This computer can't run a fenced agent right now." : 'The run could not start.'}
          </div>
          <details className="mt-2" data-details>
            <summary className="cursor-pointer text-[14px] min-h-[32px] text-[#FCA5A5]">
              Details
            </summary>
            <div className="mt-2 mono text-[13px] space-y-1 text-[#FECACA]">
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

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[13px] font-semibold uppercase tracking-wider text-[#8B95A7] mr-1">
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
              className={`min-h-[44px] sm:min-h-[40px] px-4 rounded-lg text-[14px] cursor-pointer transition-colors border ${
                presetId === p.id
                  ? 'border-[#3B82F6] bg-[rgba(59,130,246,0.14)] text-[#E6E9EF] font-semibold'
                  : 'border-[#2A3344] bg-[#11151D] text-[#A7B0C0] hover:text-[#E6E9EF] hover:border-[#3B82F6]'
              }`}
            >
              {PRESET_LABELS[p.id] || p.name}
            </button>
          ))}
      </div>

      <div className="text-[14px] flex flex-wrap items-center gap-x-4 gap-y-1 text-[#8B95A7]">
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
          <label className="block text-[14px] text-[#A7B0C0]">
            File name
            <input
              value={newPath}
              onChange={e => setNewPath(e.target.value)}
              className="mt-1 w-full min-h-[44px] px-3 rounded-lg mono text-[14px] outline-none bg-[#0E121A] text-[#E6E9EF] border border-[#2A3344] focus:border-[#3B82F6]"
            />
          </label>
          <label className="block text-[14px] text-[#A7B0C0]">
            Text (up to 50 KB)
            <textarea
              rows={4}
              value={newContent}
              onChange={e => setNewContent(e.target.value)}
              className="mt-1 w-full px-3 py-2 rounded-lg mono text-[13px] outline-none bg-[#0E121A] text-[#E6E9EF] border border-[#2A3344] focus:border-[#3B82F6]"
            />
          </label>
          {fileError && <div className="text-[14px] text-[#FCA5A5]">{fileError}</div>}
          <button className="btn-ghost min-h-[44px] sm:min-h-[40px]" onClick={addFile}>
            Add file
          </button>
        </div>
      )}
    </div>
  );
};

export function AgentSelector({
  agents,
  value,
  onChange,
}: {
  agents: { id: string; name: string; team?: string }[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-[14px] text-[#A7B0C0]">
      Agent
      <select
        id="agent-selector"
        value={value}
        onChange={e => onChange(e.target.value)}
        className="min-h-[44px] sm:min-h-[40px] px-3 rounded-lg text-[14px] outline-none bg-[#0E121A] text-[#E6E9EF] border border-[#2A3344] focus:border-[#3B82F6]"
      >
        {agents.map(a => (
          <option key={a.id} value={a.id}>
            {a.name} ({a.team || 'core'})
          </option>
        ))}
      </select>
    </label>
  );
}
