import React, { useEffect, useState } from 'react';
import { RunActionButton } from '../components/action/RunActionButton';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { BoundaryPreviewResponse, RunPreset, ConfiguredAgent, ActiveRunTask } from '../types';
import { fileName } from '../logic/runView';
import { FileReview, FileReviewResult } from '../components/v3/FileReview';
import { FileDrop } from '../components/upload/FileDrop';
import { Button } from '../components/ui/Button';

// Plain names for the existing presets (the ids and their prompts are the server's).
const PRESET_LABELS: Record<string, string> = {
  summarise_csv: 'Summarise a file',
  compare_target: 'Needs to read one more file',
  hidden_instruction: 'A file tries to trick the agent',
  shell_injection: 'A file tricks the agent into a shell command',
  network_exfiltration: 'A file tells the agent to send data to a website',
  a2a_agent: 'Plan a trip with the travel planner (modelled on Google a2a-samples)',
  contract_review: 'A contract tries to trick the agent',
  save_extra_file: 'Needs to save one more file',
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
  // '' = the agent's own model; otherwise an override for this run only.
  const [modelOverride, setModelOverride] = useState('');
  const [ollamaReachable, setOllamaReachable] = useState(true);
  const [agents, setAgents] = useState<ConfiguredAgent[]>([
    { id: 'finance_bot', name: 'Finance Bot', owner: 'Ana Dev', team: 'finance', description: 'Revenue, targets and timesheet summaries' },
    { id: 'notes_bot', name: 'Notes Bot', owner: 'Ravi K', team: 'operations', description: 'Summarises server logs and system audits' },
    { id: 'brief_bot', name: 'Brief Bot', owner: 'Meena R', team: 'legal', description: 'Summarises contracts and compliance documents' },
    { id: 'travel_bot', name: 'Travel Bot', owner: 'Kiran S', team: 'travel desk', description: 'Plans business trips' },
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

  // "Let the agent's model choose the files": the model's choice, checked by rules on the
  // server, which the requester reviews (and can untick) before Start.
  const [modelChooses, setModelChooses] = useState(false);
  const [review, setReview] = useState<FileReviewResult | null>(null);
  const [kept, setKept] = useState<string[]>([]);
  const [reviewing, setReviewing] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);

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
        setOllamaReachable(ms.ollama_reachable !== false);
        const first = ps.find(p => p.id === 'summarise_csv') || ps[0];
        if (first) {
          setPresetId(first.id);
          setPrompt(first.prompt);
          setFiles({ ...first.files });
        }
        if (ags && ags.length > 0) {
          setAgents(ags);
          const own = first?.agent && ags.some(a => a.id === first.agent) ? first.agent : null;
          setAgentId(prev => own || (ags.some(a => a.id === prev) ? prev : ags[0].id));
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

  // A review belongs to one request, one set of files and one agent: any change makes it stale.
  useEffect(() => {
    setReview(null);
    setKept([]);
    setReviewError(null);
  }, [prompt, files, agentId, modelChooses]);

  const checkFiles = async () => {
    setReviewError(null);
    if (!prompt.trim()) return setReviewError('Write what the agent should do first.');
    if (!hasToken) return openAuthModal();
    setReviewing(true);
    try {
      const res = await api.deriveRunFiles({
        prompt: prompt.trim(),
        preset: presetId,
        files,
        agent_id: agentId,
        ...(modelOverride && modelOverride !== 'scripted' ? { model: modelOverride } : {}),
      });
      setReview(res);
      setKept(res.reads.map(r => r.path));
    } catch (err: any) {
      setReviewError(err.message || 'The model could not be asked.');
    } finally {
      setReviewing(false);
    }
  };

  const chosenAgent = agents.find(a => a.id === agentId);
  const agentModel = chosenAgent?.model || '';
  // The agent's model is unavailable (Ollama not running or not installed): fall back to the
  // scripted steps and say so, rather than refusing to start.
  const agentModelMissing = !modelOverride && !!agentModel && !models.includes(agentModel);
  const runModel = modelOverride || (agentModelMissing ? 'scripted' : '');
  const effectiveModel = runModel || agentModel || 'scripted';

  const canCompare = !!presets.find(p => p.id === presetId)?.comparable;
  const toolsNeeded = presets.find(p => p.id === presetId)?.tools_needed || [];
  const missingTools = chosenAgent?.tools ? toolsNeeded.filter(t => !chosenAgent.tools!.includes(t)) : [];
  const presetAgent = agents.find(a => a.id === presets.find(p => p.id === presetId)?.agent);

  const choosePreset = (p: RunPreset) => {
    setPresetId(p.id);
    // Each example is a job for one agent: pick that agent (it can still be changed).
    if (p.agent && agents.some(a => a.id === p.agent)) setAgentId(p.agent);
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
    if (modelChooses && !review) {
      setError("Check the files first: press \"Ask the model\" and review its choice.");
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
      const res = await api.startRun({
        prompt: prompt.trim(),
        preset: presetId,
        ...(runModel ? { model: runModel } : {}),
        files,
        agent_id: agentId,
        comparison_mode: comparisonMode && canCompare,
        ...(modelChooses && review ? { review_id: review.review_id, approved_reads: kept } : {}),
      });
      navigate(`/run/${res.task_id}`);
    } catch (err: any) {
      // Nothing was started: stay here and say why.
      setError(err.message || 'The run could not start.');
      setProblems(err.problems || []);
      if (err?.status === 409) {
        api.getActiveRun().then(a => setActiveTask(a.task_id)).catch(() => { });
      }
    } finally {
      setStarting(false);
    }
  };

  const reads = [...new Set((preview?.boundary_v1.files_read || []).map(fileName))];
  const writes = [...new Set((preview?.boundary_v1.files_write || []).map(fileName))];
  const fileNames = Object.keys(files);

  return (
    <div className="max-w-[820px] flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <h1 className="m-0 font-display font-bold text-[28px] sm:text-[32px] leading-[1.15] text-fg">What should the agent do?</h1>
        <p className="m-0 text-[16px] text-fg-2">
          It can only touch what your request needs. Anything else is blocked, or you decide.
        </p>
      </div>

      {activeCount >= 3 ? (
        <div id="active-run-banner" className="w-full px-4 py-3 rounded-xl text-[15px] text-left text-wait bg-wait/10 border border-wait/45">
          Maximum concurrent runs reached (3 active runs). Please wait for an active run to complete.
        </div>
      ) : activeCount > 0 ? (
        <div id="active-run-banner" className="w-full px-4 py-3 rounded-xl text-[15px] text-left text-fg bg-accent/10 border border-accent/45 flex items-center justify-between">
          <span>{activeCount} agent(s) currently working ({3 - activeCount} slot(s) available).</span>
          <div className="flex items-center gap-2">
            {activeTasks.length > 0 ? (
              activeTasks.map(t => (
                <Link key={t.task_id} to={`/run/${t.task_id}`} className="text-accent hover:underline font-mono text-[13px]">
                  Watch {t.agent_id || t.task_id.slice(0, 8)}
                </Link>
              ))
            ) : (
              activeTask && <Link to={`/run/${activeTask}`} className="text-accent hover:underline font-mono text-[13px]">Watch active run</Link>
            )}
          </div>
        </div>
      ) : null}

      <div className="rounded-2xl border border-line bg-surface-1 w-full flex flex-col gap-3 p-3 sm:p-4 text-left transition-colors focus-within:border-line-strong shadow-sm">
        <label htmlFor="prompt-input" className="sr-only">
          Your request
        </label>
        <textarea
          id="prompt-input"
          rows={3}
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
          placeholder="For example: read sales_data.csv and write a short summary."
          className="w-full resize-none border-none outline-none bg-transparent text-[16px] sm:text-[17px] leading-normal p-2 text-fg placeholder-fg-dim"
        />
        <div className="flex flex-wrap items-center justify-between gap-3 px-1 pt-3 border-t border-line">
          <div className="flex flex-wrap items-center gap-4">
            <AgentSelector agents={agents} value={agentId} onChange={setAgentId} />
            <label className="flex items-center gap-2 text-[14px] text-fg-2">
              Model
              <select
                id="model-selector"
                value={modelOverride}
                onChange={e => setModelOverride(e.target.value)}
                className="min-h-[44px] sm:min-h-[40px] px-3 rounded-lg text-[14px] outline-none bg-surface-2 text-fg border border-line focus:border-line-strong"
              >
                <option value="">
                  {agentModelMissing
                    ? `scripted (${agentModel} is not available)`
                    : agentModel
                      ? `${agentModel} (the agent's own)`
                      : "the agent's own"}
                </option>
                {models
                  .filter(m => m !== agentModel)
                  .map(m => (
                    <option key={m} value={m}>
                      {m === 'scripted' ? 'scripted: fixed steps, no AI (for repeatable demos)' : `${m} (override for this run)`}
                    </option>
                  ))}
              </select>
            </label>
            {missingTools.length > 0 && (
              <p className="basis-full m-0 text-[13px] leading-relaxed" id="agent-tools-missing" style={{ color: 'var(--wait-kpi)' }}>
                This example needs <span className="mono">{missingTools.join(', ')}</span>, which {chosenAgent?.name} may not call, so
                that step will be refused. Pick {presetAgent && presetAgent.id !== chosenAgent?.id ? presetAgent.name : 'an agent with that tool'} to run it, or keep {chosenAgent?.name} to show the refusal.
              </p>
            )}
            <AgentModelNote agent={chosenAgent} model={effectiveModel} overridden={!!runModel} missing={agentModelMissing} ollamaReachable={ollamaReachable} />
            {role === 'admin' && (
              <label
                className={`flex items-center gap-2 text-[13px] text-wait-kpi ${canCompare ? 'cursor-pointer' : 'opacity-60 cursor-not-allowed'}`}
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
                  className="rounded border-wait/40 bg-surface-1 text-wait focus:ring-wait"
                />
                <span>Comparison mode: kernel lock off, for demonstration</span>
                {!canCompare && <span className="text-fg-3">(only for the trick examples)</span>}
              </label>
            )}
          </div>
          <RunActionButton id="start-run-btn" onClick={start} busy={starting} disabled={activeCount >= 3} />
        </div>
      </div>

      <div className="flex flex-col gap-2" id="model-chooses-block">
        <label className="flex items-center gap-2 text-[14px] cursor-pointer" style={{ color: 'var(--text-2)' }}>
          <input
            type="checkbox"
            id="model-chooses-toggle"
            checked={modelChooses}
            onChange={e => setModelChooses(e.target.checked)}
            className="rounded border-line-strong bg-surface-1"
          />
          <span>
            Let {chosenAgent?.name || 'the agent'}'s model choose which files it needs (you check them before Start)
          </span>
        </label>
        {modelChooses && !review && (
          <div className="flex items-center gap-3">
            <Button id="ask-model-btn" type="button" variant="secondary" size="md" onClick={checkFiles} disabled={reviewing} className="min-h-[40px] px-4">
              {reviewing ? 'Asking the model…' : 'Ask the model'}
            </Button>
            {reviewError && (
              <span id="file-review-error" className="text-[14px]" style={{ color: 'var(--bad-text)' }}>
                {reviewError}
              </span>
            )}
          </div>
        )}
        {modelChooses && review && (
          <FileReview
            result={review}
            agentName={chosenAgent?.name || 'The agent'}
            kept={kept}
            onToggle={p => setKept(k => (k.includes(p) ? k.filter(x => x !== p) : [...k, p]))}
          />
        )}
      </div>

      {preview && !(modelChooses && review) && (reads.length > 0 || writes.length > 0) && (
        <p id="allow-preview" className="m-0 text-[15px] text-fg-2 flex items-start gap-2">
          <span aria-hidden="true" className="mt-[7px] inline-block w-2 h-2 rounded-[3px] bg-ok flex-none" />
          <span>
            {reads.length > 0 && <>It will be able to read {joinNames(reads)}</>}
            {reads.length > 0 && writes.length > 0 && ' and '}
            {writes.length > 0 && <>{reads.length > 0 ? 'write ' : 'It will be able to write '}{joinNames(writes)}</>}. Nothing else.
          </span>
        </p>
      )}

      {error && (
        <div id="run-error" role="alert" className="w-full text-left px-4 py-4 rounded-xl bg-bad/[0.08] border border-bad/45 text-bad-lighter">
          <div className="font-semibold text-[16px]">
            {problems.length > 0 ? "This computer can't run a fenced agent right now." : 'The run could not start.'}
          </div>
          <details className="mt-2" data-details>
            <summary className="cursor-pointer text-[14px] min-h-[32px] text-bad-text">
              Details
            </summary>
            <div className="mt-2 mono text-[13px] space-y-1 text-bad-lighter">
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

      <PresetGroups presets={presets} agents={agents} presetId={presetId} agentId={agentId} onChoose={choosePreset} />

      <div className="text-[14px] flex flex-wrap items-center gap-x-4 gap-y-1 text-fg-3">
        {fileNames.length > 0 ? <span id="attached-files">Files given to the agent: {joinNames(fileNames)}.</span> : <span>No files given to the agent.</span>}
        {(Object.keys(files).length < MAX_FILES || showAddFile) && (
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
        <div className="w-full rounded-2xl border border-line bg-surface-1 p-4 text-left space-y-4 shadow-sm">
          <FileDrop files={files} onFilesChange={setFiles} />

          <div className="relative flex items-center py-1">
            <div className="flex-grow border-t border-line"></div>
            <span className="flex-shrink mx-4 text-[12px] uppercase tracking-wider text-fg-3">
              or paste text
            </span>
            <div className="flex-grow border-t border-line"></div>
          </div>

          <label className="block text-[14px] text-fg-2">
            File name
            <input
              value={newPath}
              onChange={e => setNewPath(e.target.value)}
              className="mt-1 w-full min-h-[44px] px-3 rounded-lg mono text-[14px] outline-none bg-surface-2 text-fg border border-line focus:border-line-strong"
            />
          </label>
          <label className="block text-[14px] text-fg-2">
            Text (up to 50 KB)
            <textarea
              rows={4}
              value={newContent}
              onChange={e => setNewContent(e.target.value)}
              className="mt-1 w-full px-3 py-2 rounded-lg mono text-[13px] outline-none bg-surface-2 text-fg border border-line focus:border-line-strong"
            />
          </label>
          {fileError && <div className="text-[14px] text-bad-text">{fileError}</div>}
          <Button variant="secondary" size="md" className="min-h-[44px] sm:min-h-[40px]" onClick={addFile}>
            Add file
          </Button>
        </div>
      )}
    </div>
  );
};

/** The examples grouped by the agent whose job they are, with that agent's team and purpose. */
export function PresetGroups({
  presets,
  agents,
  presetId,
  agentId,
  onChoose,
}: {
  presets: RunPreset[];
  agents: ConfiguredAgent[];
  presetId: string;
  agentId: string;
  onChoose: (p: RunPreset) => void;
}) {
  const shown = presets.filter(p => p.id !== 'custom');
  const groups = groupPresets(shown, agents);
  const chosen = shown.find(p => p.id === presetId);
  const jobOf = agents.find(a => a.id === chosen?.agent);
  const running = agents.find(a => a.id === agentId);
  return (
    <div className="flex flex-col gap-3" id="preset-groups">
      <span className="text-[13px] font-semibold uppercase tracking-wider text-fg-3">Try a job:</span>
      {groups.map(g => (
        <div key={g.agent?.id || 'other'} className="flex flex-col gap-1.5" data-preset-group={g.agent?.id || 'other'}>
          <span className="text-[13px] text-fg-2">
            {g.agent ? (
              <>
                <span className="font-semibold text-fg">{g.agent.name}</span>
                {g.agent.team ? ` · ${g.agent.team} team` : ''}
                {g.agent.description ? ` · ${g.agent.description}` : ''}
              </>
            ) : (
              'Other examples'
            )}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            {g.presets.map(p => (
              <button
                key={p.id}
                id={`preset-${p.id}`}
                type="button"
                aria-pressed={presetId === p.id}
                onClick={() => onChoose(p)}
                className={`min-h-[44px] sm:min-h-[40px] px-4 rounded-lg text-[14px] cursor-pointer transition-colors border ${
                  presetId === p.id
                    ? 'bg-surface-2 text-fg font-medium'
                    : 'border-line bg-surface-2 text-fg-2 hover:text-fg hover:border-line-strong'
                }`}
                style={
                  presetId === p.id
                    ? {
                        border: '1px solid transparent',
                        backgroundImage: 'linear-gradient(var(--surface-2), var(--surface-2)), var(--accent-grad)',
                        backgroundOrigin: 'border-box',
                        backgroundClip: 'padding-box, border-box',
                      }
                    : undefined
                }
              >
                {PRESET_LABELS[p.id] || p.name}
              </button>
            ))}
          </div>
        </div>
      ))}
      {jobOf && (
        <p id="preset-agent" className="m-0 text-[14px] text-fg-2">
          {running && running.id !== jobOf.id
            ? `This is ${jobOf.name}'s job (${jobOf.team || 'its'} team); ${running.name} is running it instead, with ${running.name}'s own tool limit.`
            : `A job for ${jobOf.name}${jobOf.owner ? `, owned by ${jobOf.owner}` : ''}${jobOf.team ? ` (${jobOf.team} team)` : ''}.`}
        </p>
      )}
    </div>
  );
}

export function groupPresets(presets: RunPreset[], agents: ConfiguredAgent[]): { agent?: ConfiguredAgent; presets: RunPreset[] }[] {
  const out: { agent?: ConfiguredAgent; presets: RunPreset[] }[] = [];
  for (const a of agents) {
    const ps = presets.filter(p => p.agent === a.id);
    if (ps.length) out.push({ agent: a, presets: ps });
  }
  const rest = presets.filter(p => !p.agent || !agents.some(a => a.id === p.agent));
  if (rest.length) out.push({ presets: rest });
  return out;
}

export function AgentSelector({
  agents,
  value,
  onChange,
}: {
  agents: { id: string; name: string; team?: string; model?: string }[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-[14px] text-fg-2">
      Agent
      <select
        id="agent-selector"
        value={value}
        onChange={e => onChange(e.target.value)}
        className="min-h-[44px] sm:min-h-[40px] px-3 rounded-lg text-[14px] outline-none bg-surface-2 text-fg border border-line focus:border-line-strong"
      >
        {agents.map(a => (
          <option key={a.id} value={a.id}>
            {a.name} ({a.team || 'core'}){a.model ? ` · ${a.model}` : ''}
          </option>
        ))}
      </select>
    </label>
  );
}


// An agent is an accountable identity with its own model; say so where it is chosen.
const AgentModelNote: React.FC<{
  agent?: ConfiguredAgent;
  model: string;
  overridden: boolean;
  missing: boolean;
  ollamaReachable: boolean;
}> = ({ agent, model, overridden, missing, ollamaReachable }) => (
  <div className="basis-full flex flex-col gap-1 text-[13px] leading-relaxed" id="agent-model-note" style={{ color: 'var(--text-3)' }}>
    {agent && (
      <span>
        <span style={{ color: 'var(--text-2)' }}>{agent.name}</span>
        {agent.description ? ` (${agent.description.charAt(0).toLowerCase()}${agent.description.slice(1)})` : ''} is owned by{' '}
        {agent.owner}, {agent.team} team, and runs on{' '}
        <span className="mono" style={{ color: 'var(--text-2)' }}>{agent.model || 'qwen2.5:7b'}</span>.
        {overridden &&
          (model === 'scripted'
            ? ' This run replays fixed steps instead (no AI), so it is repeatable.'
            : ` This run uses ${model} instead.`)}{' '}
        It may call only{' '}
        <span className="mono" style={{ color: 'var(--text-2)' }} id="agent-tool-limit">
          {(agent.tools || []).join(', ') || 'its default tools'}
        </span>
        ; which files and sites it may touch comes from your request.
      </span>
    )}
    {missing && (
      <span id="agent-model-missing" style={{ color: 'var(--wait-kpi)' }}>
        {agent?.model} is not available here, so this run will use the scripted steps. Start Ollama, or install the model
        with <span className="mono">ollama pull {agent?.model}</span>.
      </span>
    )}
    {!ollamaReachable && (
      <span id="ollama-unreachable" style={{ color: 'var(--wait-kpi)' }}>
        Ollama is not running, so only the scripted agent is available. Start Ollama and reload this page.
      </span>
    )}
  </div>
);
