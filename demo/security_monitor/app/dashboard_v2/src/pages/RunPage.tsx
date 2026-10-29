import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Play,
  Square,
  Shield,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileText,
  Terminal,
  Cpu,
  ChevronDown,
  ChevronUp,
  Download,
  ExternalLink,
  Plus,
  Trash2,
  RefreshCw,
  Eye,
  Layers,
  ArrowRight,
  Database,
} from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import {
  TaskStep,
  RunPreset,
  BoundaryPreviewResponse,
  RunOutputFile,
  ReceiptResponse,
  ExpansionItem,
} from '../types';

// No step for this long (or a stream error) -> stop trusting the stream and read stored state.
const STREAM_STALL_MS = 20000;
const POLL_INTERVAL_MS = 2000;

const TERMINAL_STATES = ['completed', 'stopped', 'failed', 'timed_out'];

const STATUS_LABELS: Record<string, string> = {
  idle: 'Idle',
  preparing: 'Preparing sandbox',
  running: 'Running',
  waiting_approval: 'Waiting for Approval',
  stopping: 'Stopping',
  completed: 'Completed',
  stopped: 'Stopped',
  failed: 'Failed',
  timed_out: 'Timed out',
};

const TASK_STATUS_TO_STATE: Record<string, string> = {
  COMPLETED: 'completed',
  FAILED: 'failed',
  TERMINATED: 'stopped',
  EXPIRED: 'timed_out',
};

export const RunPage: React.FC = () => {
  const { hasToken, openAuthModal } = useAuth();

  // Presets and models state
  const [presets, setPresets] = useState<RunPreset[]>([]);
  const [selectedPresetId, setSelectedPresetId] = useState<string>('summarise_csv');
  const [models, setModels] = useState<string[]>(['scripted']);
  const [selectedModel, setSelectedModel] = useState<string>('scripted');

  // Input configuration state
  const [prompt, setPrompt] = useState<string>('');
  const [files, setFiles] = useState<Record<string, string>>({});
  const [newFilePath, setNewFilePath] = useState<string>('input/data.txt');
  const [newFileContent, setNewFileContent] = useState<string>('');
  const [showAddFile, setShowAddFile] = useState<boolean>(false);
  const [fileError, setFileError] = useState<string | null>(null);

  // Boundary preview state
  const [boundaryPreview, setBoundaryPreview] = useState<BoundaryPreviewResponse | null>(null);
  const [previewLoading, setPreviewLoading] = useState<boolean>(false);

  // Live execution state
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [executionStatus, setExecutionStatus] = useState<string>('idle');
  const [steps, setSteps] = useState<TaskStep[]>([]);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorProblems, setErrorProblems] = useState<string[]>([]);
  const [endReason, setEndReason] = useState<string | null>(null);
  const [streamNote, setStreamNote] = useState<string | null>(null);
  const [stopNote, setStopNote] = useState<string | null>(null);
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({});

  // End-of-run data
  const [outputFiles, setOutputFiles] = useState<RunOutputFile[]>([]);
  const [receiptData, setReceiptData] = useState<ReceiptResponse | null>(null);

  // Active expansion for inline card
  const [pendingExpansion, setPendingExpansion] = useState<ExpansionItem | null>(null);
  const [approvingExpansion, setApprovingExpansion] = useState<boolean>(false);
  const [denyReason, setDenyReason] = useState<string>('');
  const [showDenyInput, setShowDenyInput] = useState<boolean>(false);
  const [now, setNow] = useState<number>(Date.now());

  const timerRef = useRef<any>(null);
  const concludedRef = useRef<string | null>(null);

  // Load presets & models on mount
  useEffect(() => {
    const loadSetupData = async () => {
      try {
        const [loadedPresets, modelsResp, activeResp] = await Promise.all([
          api.getRunPresets(),
          api.getRunModels(),
          api.getActiveRun(),
        ]);
        setPresets(loadedPresets);

        // Only models that are really installed, plus the deterministic scripted mock.
        const allModels = [...modelsResp.models];
        if (!allModels.includes('scripted')) {
          allModels.push('scripted');
        }
        setModels(allModels);
        setSelectedModel(modelsResp.default || 'scripted');

        // Apply initial preset
        const initialPreset = loadedPresets.find(p => p.id === 'summarise_csv') || loadedPresets[0];
        if (initialPreset) {
          setSelectedPresetId(initialPreset.id);
          setPrompt(initialPreset.prompt);
          setFiles({ ...initialPreset.files });
        }

        // If a task is already running, latch on to it
        if (activeResp && activeResp.active && activeResp.task_id) {
          setActiveTaskId(activeResp.task_id);
          setIsRunning(true);
          setExecutionStatus('running');
          setElapsedSeconds(Math.floor(activeResp.elapsed_seconds));
        }
      } catch (err: any) {
        console.error('Failed to load run configuration:', err);
      }
    };
    loadSetupData();
  }, []);

  // Preset switch handler
  const handleSelectPreset = (presetId: string) => {
    setSelectedPresetId(presetId);
    const p = presets.find(item => item.id === presetId);
    if (p) {
      setPrompt(p.prompt);
      setFiles({ ...p.files });
      setErrorMessage(null);
    }
  };

  // Debounced Boundary Preview
  useEffect(() => {
    if (!prompt.trim()) {
      setBoundaryPreview(null);
      return;
    }
    const timer = setTimeout(async () => {
      setPreviewLoading(true);
      try {
        const res = await api.previewRun({
          prompt,
          preset: selectedPresetId,
          files,
        });
        setBoundaryPreview(res);
      } catch (err) {
        console.debug('Preview generation error:', err);
      } finally {
        setPreviewLoading(false);
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [prompt, selectedPresetId, files]);

  // Live timer tick & time sync
  useEffect(() => {
    const clockInterval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(clockInterval);
  }, []);

  useEffect(() => {
    if (isRunning) {
      timerRef.current = setInterval(() => {
        setElapsedSeconds(s => s + 1);
      }, 1000);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isRunning]);

  // Ends the run in the UI exactly once, with the server-reported terminal state.
  const concludeRun = (taskId: string, state: string, reason: string) => {
    if (concludedRef.current === taskId) return;
    concludedRef.current = taskId;
    setExecutionStatus(TERMINAL_STATES.includes(state) ? state : 'failed');
    setEndReason(reason || null);
    setIsRunning(false);
    setPendingExpansion(null);
    loadRunConcludedData(taskId);
  };

  const trackExpansion = (taskId: string, step: TaskStep) => {
    if (step.kind !== 'expansion') return;
    if (step.verdict === 'PENDING') {
      setExecutionStatus('waiting_approval');
      loadPendingExpansion(taskId);
    } else {
      setExecutionStatus(s => (s === 'waiting_approval' ? 'running' : s));
      setPendingExpansion(null);
    }
  };

  // Reads stored steps + task status and shows the real state. Returns true once terminal.
  const reconcileFromStorage = async (taskId: string): Promise<boolean> => {
    try {
      const polled = await api.getRunSteps(taskId, 0);
      setSteps(polled);
      const finished = polled.find(s => s.kind === 'finished');
      if (finished) {
        concludeRun(taskId, finished.verdict.toLowerCase(), finished.detail);
        return true;
      }
      const lastExpansion = [...polled].reverse().find(s => s.kind === 'expansion');
      if (lastExpansion) trackExpansion(taskId, lastExpansion);

      const active = await api.getActiveRun();
      if (active.active && active.task_id === taskId) {
        setExecutionStatus(s => (s === 'preparing' && polled.length > 0 ? 'running' : s));
        return false;
      }
      try {
        const detail = await api.getTaskDetail(taskId);
        const state = TASK_STATUS_TO_STATE[detail.task.status];
        if (state) {
          concludeRun(taskId, state, `task status ${detail.task.status}`);
          return true;
        }
      } catch {
        // no task record: fall through
      }
      concludeRun(taskId, 'failed', 'The run is no longer active and ended without a terminal event.');
      return true;
    } catch (err: any) {
      setStreamNote(`Could not read run state: ${err.message || err}`);
      return err?.status === 401;
    }
  };

  // Connect to SSE stream whenever activeTaskId is set; fall back to stored state when it stalls.
  useEffect(() => {
    if (!activeTaskId) return;
    const taskId = activeTaskId;
    let ended = false;
    let watchdog: ReturnType<typeof setTimeout> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const es = new EventSource(api.getRunStreamUrl(taskId), { withCredentials: true });

    const startFallback = (note: string) => {
      if (ended || pollTimer) return;
      es.close();
      if (watchdog) clearTimeout(watchdog);
      setStreamNote(note);
      const tick = async () => {
        if (ended) return;
        if (await reconcileFromStorage(taskId)) {
          ended = true;
          if (pollTimer) clearInterval(pollTimer);
        }
      };
      pollTimer = setInterval(tick, POLL_INTERVAL_MS);
      tick();
    };

    const armWatchdog = () => {
      if (watchdog) clearTimeout(watchdog);
      watchdog = setTimeout(
        () => startFallback(`No update from the live stream for ${STREAM_STALL_MS / 1000} s; showing stored state.`),
        STREAM_STALL_MS,
      );
    };

    es.onmessage = (event) => {
      armWatchdog();
      let step: TaskStep;
      try {
        step = JSON.parse(event.data);
      } catch {
        return;
      }
      setSteps(prev => {
        if (prev.some(s => s.step_number === step.step_number)) {
          return prev;
        }
        return [...prev, step].sort((a, b) => a.step_number - b.step_number);
      });
      setExecutionStatus(s => (s === 'preparing' ? 'running' : s));
      trackExpansion(taskId, step);
    };

    es.addEventListener('end', (event) => {
      ended = true;
      es.close();
      if (watchdog) clearTimeout(watchdog);
      try {
        const data = JSON.parse((event as MessageEvent).data);
        concludeRun(taskId, data.state, data.reason);
      } catch {
        concludeRun(taskId, 'failed', 'Malformed end event');
      }
    });

    es.onerror = () => startFallback('Live stream interrupted; showing stored state.');

    armWatchdog();

    return () => {
      ended = true;
      es.close();
      if (watchdog) clearTimeout(watchdog);
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [activeTaskId]);

  const loadPendingExpansion = async (taskId: string) => {
    try {
      const exps = await api.getExpansions(taskId, 'PENDING');
      if (exps && exps.length > 0) {
        setPendingExpansion(exps[0]);
      } else {
        setPendingExpansion(null);
      }
    } catch {
      setPendingExpansion(null);
    }
  };

  const loadRunConcludedData = async (taskId: string) => {
    try {
      const [outputResp, receiptResp] = await Promise.all([
        api.getRunOutput(taskId).catch(() => ({ task_id: taskId, files: [] })),
        api.getTaskReceipt(taskId).catch(() => null),
      ]);
      setOutputFiles(outputResp.files || []);
      setReceiptData(receiptResp);
    } catch (err) {
      console.error('Error fetching concluded task telemetry:', err);
    }
  };

  // Add custom file
  const handleAddFile = () => {
    setFileError(null);
    const trimmedPath = newFilePath.trim();
    if (!trimmedPath) {
      setFileError('File path is required');
      return;
    }
    if (!trimmedPath.startsWith('input/')) {
      setFileError('File path must begin with input/');
      return;
    }
    if (trimmedPath.includes('..') || trimmedPath.includes('\\')) {
      setFileError('Path cannot contain .. or backslashes');
      return;
    }
    if (Object.keys(files).length >= 3 && !files[trimmedPath]) {
      setFileError('Maximum 3 files allowed');
      return;
    }
    if (new Blob([newFileContent]).size > 51200) {
      setFileError('File exceeds 50 KB limit');
      return;
    }

    setFiles(prev => ({ ...prev, [trimmedPath]: newFileContent }));
    setNewFilePath('input/');
    setNewFileContent('');
    setShowAddFile(false);
  };

  const handleRemoveFile = (pathKey: string) => {
    setFiles(prev => {
      const next = { ...prev };
      delete next[pathKey];
      return next;
    });
  };

  // Start Run
  const handleStartRun = async () => {
    setErrorMessage(null);
    setErrorProblems([]);
    if (!prompt.trim()) {
      setErrorMessage('Please enter a task request.');
      return;
    }

    if (!hasToken) {
      openAuthModal();
      return;
    }

    setSteps([]);
    setOutputFiles([]);
    setReceiptData(null);
    setPendingExpansion(null);
    setEndReason(null);
    setStreamNote(null);
    setStopNote(null);
    setElapsedSeconds(0);
    setActiveTaskId(null);
    setIsRunning(true);
    setExecutionStatus('preparing');

    try {
      const res = await api.startRun({
        prompt: prompt.trim(),
        preset: selectedPresetId,
        model: selectedModel,
        files,
      });

      concludedRef.current = null;
      setActiveTaskId(res.task_id);
    } catch (err: any) {
      // Nothing was started: stay idle and show why.
      setIsRunning(false);
      setExecutionStatus('idle');
      setErrorMessage(err.message || 'Failed to start run.');
      setErrorProblems(err.problems || []);
    }
  };

  // Stop Run: the stream's end event (or the stored state) reports when it has really stopped.
  const handleStopRun = async () => {
    if (!activeTaskId) return;
    if (!hasToken) {
      openAuthModal();
      return;
    }

    try {
      const res = await api.stopRun(activeTaskId);
      setExecutionStatus('stopping');
      setStopNote(res.killed ? 'Task cgroup killed.' : 'Cancelled before the agent started.');
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to stop task cgroup.');
    }
  };

  // Inline Approval Handlers
  const handleInlineApprove = async (reqId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    setApprovingExpansion(true);
    try {
      await api.approveExpansion(reqId, {
        decided_by: 'operator',
        reason: 'Approved via live inline card',
      });
      setPendingExpansion(null);
      setExecutionStatus('running');
    } catch (err: any) {
      setErrorMessage(err.message || 'Approval error');
    } finally {
      setApprovingExpansion(false);
    }
  };

  const handleInlineDeny = async (reqId: string) => {
    if (!hasToken) {
      openAuthModal();
      return;
    }
    const reasonText = denyReason.trim() || 'Denied by operator: outside authorized scope';
    setApprovingExpansion(true);
    try {
      await api.denyExpansion(reqId, {
        decided_by: 'operator',
        reason: reasonText,
      });
      setPendingExpansion(null);
      setShowDenyInput(false);
      setDenyReason('');
      setExecutionStatus('running');
    } catch (err: any) {
      setErrorMessage(err.message || 'Denial error');
    } finally {
      setApprovingExpansion(false);
    }
  };

  const toggleStepExpand = (stepNum: number) => {
    setExpandedSteps(prev => ({ ...prev, [stepNum]: !prev[stepNum] }));
  };

  // Live Metrics
  const blockedCount = steps.filter(s => s.verdict === 'DENY' || s.verdict === 'BLOCKED').length;
  const pendingCount = pendingExpansion ? 1 : steps.filter(s => s.verdict === 'PENDING').length;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
            <Play className="w-6 h-6 text-cyan-500 fill-cyan-500/20" />
            <span>Governed Task Execution</span>
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Run a live agent inside isolated Condition C sandbox. Watch enforcement layers, broker mediation, and review boundary expansions live.
          </p>
        </div>

        {activeTaskId && (
          <div className="flex items-center gap-2 font-mono text-xs text-slate-500">
            <span>Task ID:</span>
            <span className="font-semibold text-slate-900 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded-lg">
              {activeTaskId}
            </span>
          </div>
        )}
      </div>

      {/* Main Grid: Left Setup, Right Live */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* ========================================================= */}
        {/* LEFT COLUMN: SETUP & BOUNDARY PREVIEW (lg:col-span-4)     */}
        {/* ========================================================= */}
        <div className="lg:col-span-5 space-y-5">
          {/* Preset Selector Card */}
          <div className="p-4 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-3 shadow-xs">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block">
              Task Preset
            </label>
            <div className="grid grid-cols-2 gap-2">
              {presets.map(p => (
                <button
                  key={p.id}
                  id={`preset-${p.id}`}
                  onClick={() => handleSelectPreset(p.id)}
                  disabled={isRunning}
                  className={`p-2.5 rounded-xl text-left border text-xs transition-all ${
                    selectedPresetId === p.id
                      ? 'border-cyan-500 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 font-semibold shadow-xs'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <div className="font-medium truncate">{p.name}</div>
                  <div className="text-[10px] text-slate-400 dark:text-slate-500 line-clamp-1 mt-0.5">
                    {p.description}
                  </div>
                </button>
              ))}
            </div>

            {/* Model Selector */}
            <div className="pt-2 border-t border-slate-100 dark:border-slate-800/80">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1.5">
                Execution Model
              </label>
              <select
                id="model-selector"
                value={selectedModel}
                onChange={e => setSelectedModel(e.target.value)}
                disabled={isRunning}
                className="w-full text-xs font-mono bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-3 py-2 text-slate-900 dark:text-slate-100 focus:outline-hidden focus:ring-1 focus:ring-cyan-500"
              >
                {models.map(m => (
                  <option key={m} value={m}>
                    {m === 'scripted' ? 'scripted (deterministic)' : m}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Prompt Input Box */}
          <div className="p-4 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-2 shadow-xs">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                User Request Prompt
              </label>
              <span className="text-[10px] text-slate-400 font-mono">
                {prompt.length} chars
              </span>
            </div>
            <textarea
              id="prompt-input"
              rows={4}
              value={prompt}
              onChange={e => setPrompt(e.target.value)}
              disabled={isRunning}
              placeholder="Describe the task for the governed agent..."
              className="w-full text-xs font-mono bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-hidden focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          {/* Input Files Section */}
          <div className="p-4 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-3 shadow-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-slate-400" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Custom Input Files ({Object.keys(files).length}/3)
                </span>
              </div>
              {Object.keys(files).length < 3 && !isRunning && (
                <button
                  onClick={() => setShowAddFile(v => !v)}
                  className="text-xs text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1 font-medium"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>{showAddFile ? 'Cancel' : 'Add file'}</span>
                </button>
              )}
            </div>

            {/* Existing Files List */}
            <div className="space-y-2">
              {Object.keys(files).length === 0 ? (
                <div className="text-xs text-slate-400 dark:text-slate-500 italic p-2 bg-slate-50 dark:bg-slate-900 rounded-lg">
                  No custom input files attached.
                </div>
              ) : (
                Object.entries(files).map(([fPath, fContent]) => (
                  <div
                    key={fPath}
                    className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-cyan-600 dark:text-cyan-400 truncate">
                        {fPath}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-slate-400">{fContent.length} bytes</span>
                        {!isRunning && (
                          <button
                            onClick={() => handleRemoveFile(fPath)}
                            className="text-rose-500 hover:text-rose-400 p-0.5 rounded"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </div>
                    <pre className="text-[10px] text-slate-600 dark:text-slate-400 line-clamp-2 overflow-hidden bg-white/50 dark:bg-black/30 p-1 rounded">
                      {fContent}
                    </pre>
                  </div>
                ))
              )}
            </div>

            {/* Add file inline panel */}
            {showAddFile && (
              <div className="p-3 rounded-xl border border-dashed border-cyan-500/50 bg-cyan-500/5 space-y-2 text-xs">
                <input
                  type="text"
                  placeholder="input/filename.csv"
                  value={newFilePath}
                  onChange={e => setNewFilePath(e.target.value)}
                  className="w-full text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-900 dark:text-slate-100"
                />
                <textarea
                  rows={3}
                  placeholder="File content (plain text, <= 50 KB)..."
                  value={newFileContent}
                  onChange={e => setNewFileContent(e.target.value)}
                  className="w-full text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-slate-900 dark:text-slate-100"
                />
                {fileError && (
                  <div className="text-rose-500 text-[11px] font-semibold">{fileError}</div>
                )}
                <button
                  onClick={handleAddFile}
                  className="w-full py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 transition-colors"
                >
                  Save File
                </button>
              </div>
            )}
          </div>

          {/* Derived Boundary Preview Card */}
          <div className="p-4 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 space-y-3 shadow-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <Shield className="w-4 h-4 text-cyan-500" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                  Derived Boundary Preview
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 font-semibold border border-cyan-500/20">
                {boundaryPreview?.active_version || 'v1'}
              </span>
            </div>

            {previewLoading ? (
              <div className="py-6 text-center text-xs text-slate-400 font-mono flex items-center justify-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-500" />
                <span>Deriving sandbox boundary...</span>
              </div>
            ) : boundaryPreview ? (
              <div className="space-y-3 text-xs">
                {/* Files Read */}
                <div className="space-y-1">
                  <span className="text-[10px] font-bold uppercase text-slate-400 font-mono">
                    Files Read ({boundaryPreview.boundary_v1.files_read.length})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {boundaryPreview.boundary_v1.files_read.map((f, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded-md font-mono text-[11px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"
                      >
                        {f}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Files Write */}
                <div className="space-y-1">
                  <span className="text-[10px] font-bold uppercase text-slate-400 font-mono">
                    Files Write ({boundaryPreview.boundary_v1.files_write.length})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {boundaryPreview.boundary_v1.files_write.map((f, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded-md font-mono text-[11px] bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20"
                      >
                        {f}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Tools */}
                <div className="space-y-1">
                  <span className="text-[10px] font-bold uppercase text-slate-400 font-mono">
                    Permitted Tools
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {boundaryPreview.boundary_v1.tools.map((t, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded-md font-mono text-[11px] bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Network Hosts */}
                <div className="space-y-1">
                  <span className="text-[10px] font-bold uppercase text-slate-400 font-mono">
                    Network Egress
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {boundaryPreview.boundary_v1.hosts.length === 0 ? (
                      <span className="px-2 py-0.5 rounded-md font-mono text-[11px] bg-slate-100 dark:bg-slate-800 text-slate-400">
                        None (strict air-gap isolation)
                      </span>
                    ) : (
                      boundaryPreview.boundary_v1.hosts.map((h, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded-md font-mono text-[11px] bg-cyan-500/10 text-cyan-600 dark:text-cyan-400"
                        >
                          {h}
                        </span>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-4 text-center text-xs text-slate-400 italic">
                Enter a prompt above to preview the derived task boundary.
              </div>
            )}
          </div>

          {/* Error notice */}
          {errorMessage && (
            <div
              id="run-error"
              role="alert"
              className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 text-xs font-medium flex items-start gap-2"
            >
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div>{errorMessage}</div>
                {errorProblems.length > 0 && (
                  <ul className="list-disc pl-4 font-mono text-[11px] font-normal">
                    {errorProblems.map(p => (
                      <li key={p}>{p}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}

          {/* Action Button: Start or Stop */}
          <div className="pt-1">
            {!isRunning ? (
              <button
                id="start-run-btn"
                onClick={handleStartRun}
                className="w-full py-3.5 px-4 rounded-xl font-bold text-sm bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-600/25 transition-all flex items-center justify-center gap-2 active:scale-[0.99]"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>Start Governed Run</span>
              </button>
            ) : (
              <button
                id="stop-run-btn"
                onClick={handleStopRun}
                disabled={!activeTaskId || executionStatus === 'stopping'}
                className="w-full py-3.5 px-4 rounded-xl font-bold text-sm bg-rose-600 hover:bg-rose-500 disabled:opacity-60 disabled:cursor-not-allowed text-white shadow-lg shadow-rose-600/25 transition-all flex items-center justify-center gap-2 active:scale-[0.99]"
              >
                <Square className="w-4 h-4 fill-white" />
                <span>{executionStatus === 'stopping' ? 'Stopping…' : 'Stop Run (cancel or cgroup kill)'}</span>
              </button>
            )}
          </div>
        </div>

        {/* ========================================================= */}
        {/* RIGHT COLUMN: LIVE TIMELINE & RECEIPTS (lg:col-span-8)    */}
        {/* ========================================================= */}
        <div className="lg:col-span-7 space-y-5">
          {/* Header Status Bar */}
          <div className="p-4 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 shadow-xs flex flex-wrap items-center justify-between gap-4">
            {/* Status Badge & Indicator */}
            <div className="flex items-center gap-3">
              <div
                className={`w-3 h-3 rounded-full ${
                  isRunning
                    ? 'bg-cyan-500 animate-ping'
                    : executionStatus === 'completed'
                    ? 'bg-emerald-500'
                    : executionStatus === 'stopped' || executionStatus === 'failed'
                    ? 'bg-rose-500'
                    : executionStatus === 'timed_out'
                    ? 'bg-amber-500'
                    : 'bg-slate-400'
                }`}
              />
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                  Status
                </span>
                <span
                  id="run-status"
                  data-state={executionStatus}
                  className="text-sm font-bold uppercase tracking-tight font-mono text-slate-900 dark:text-white"
                >
                  {STATUS_LABELS[executionStatus] || executionStatus}
                </span>
                {(endReason || stopNote) && (
                  <span id="run-end-reason" className="block text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    {endReason || stopNote}
                  </span>
                )}
              </div>
            </div>

            {/* Metrics Counters */}
            <div className="flex items-center gap-4 sm:gap-6 font-mono text-xs">
              <div>
                <div className="text-[10px] text-slate-400 uppercase">Elapsed</div>
                <div className="font-bold text-slate-700 dark:text-slate-200 flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span>{elapsedSeconds}s</span>
                </div>
              </div>

              <div>
                <div className="text-[10px] text-slate-400 uppercase">Steps</div>
                <div className="font-bold text-slate-700 dark:text-slate-200">{steps.length}</div>
              </div>

              <div>
                <div className="text-[10px] text-slate-400 uppercase">Blocked</div>
                <div className={`font-bold ${blockedCount > 0 ? 'text-rose-500' : 'text-slate-700 dark:text-slate-200'}`}>
                  {blockedCount}
                </div>
              </div>

              <div>
                <div className="text-[10px] text-slate-400 uppercase">Pending</div>
                <div className={`font-bold ${pendingCount > 0 ? 'text-amber-500' : 'text-slate-700 dark:text-slate-200'}`}>
                  {pendingCount}
                </div>
              </div>
            </div>
          </div>

          {/* INLINE APPROVAL CARD (When expansion request is pending) */}
          {pendingExpansion && (
            <div
              id={`inline-approval-card-${pendingExpansion.request_id}`}
              className="p-5 rounded-2xl bg-amber-500/10 dark:bg-amber-950/20 border-2 border-amber-500 shadow-lg shadow-amber-500/10 space-y-4 animate-pulse"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-amber-500/30 pb-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-500" />
                  <span className="font-mono text-xs font-bold text-amber-600 dark:text-amber-400 uppercase">
                    Runtime Expansion Requested ({pendingExpansion.request_id})
                  </span>
                </div>
                <div className="font-mono text-xs text-amber-600 dark:text-amber-400 font-bold bg-amber-500/20 px-2 py-0.5 rounded">
                  {Math.max(0, Math.ceil(((new Date(pendingExpansion.created_at).getTime() + (pendingExpansion.timeout_seconds || 120) * 1000) - now) / 1000))}s until fail-closed DENY
                </div>
              </div>

              {/* Resource Target & Risk */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-amber-500/20">
                  <span className="text-slate-500 block text-[10px]">Resource Target</span>
                  <span className="font-bold text-slate-900 dark:text-white">
                    {pendingExpansion.resource_type}: {pendingExpansion.resource_target}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-amber-500/20">
                  <span className="text-slate-500 block text-[10px]">Risk Tier Transition</span>
                  <span className="font-bold text-slate-700 dark:text-slate-300">
                    {pendingExpansion.baseline_risk_tier} → {pendingExpansion.effective_risk_tier}
                  </span>
                </div>
              </div>

              {/* Provenance Warning */}
              {(pendingExpansion.escalated_by_provenance || pendingExpansion.provenance_escalation) && (
                <div className="p-3 rounded-xl bg-amber-500/20 border border-amber-500/40 text-xs space-y-1.5">
                  <div className="font-bold text-amber-700 dark:text-amber-300 flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 shrink-0" />
                    <span>Requested after reading untrusted content</span>
                  </div>
                  <p className="text-[11px] text-slate-700 dark:text-slate-300">
                    This request was elevated from baseline {pendingExpansion.baseline_risk_tier} to effective {pendingExpansion.effective_risk_tier} because the agent previously inspected untrusted input.
                  </p>
                  {pendingExpansion.prior_untrusted_reads && pendingExpansion.prior_untrusted_reads.length > 0 && (
                    <div className="space-y-1 pt-1">
                      {pendingExpansion.prior_untrusted_reads.map((pr, idx) => (
                        <div
                          key={idx}
                          className={`p-1.5 rounded font-mono text-[10px] ${
                            pr.linked
                              ? 'bg-amber-500/30 border border-amber-500/60 font-semibold text-amber-900 dark:text-amber-200'
                              : 'bg-white/40 dark:bg-black/30 text-slate-600 dark:text-slate-400'
                          }`}
                        >
                          <div>Source: {pr.source_target}</div>
                          {pr.linked && (
                            <div className="text-amber-800 dark:text-amber-300 text-[10px] mt-0.5">
                              ★ this read mentions the requested resource
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Agent Justification */}
              <div className="p-2.5 rounded-lg bg-white/60 dark:bg-slate-900/60 border border-amber-500/20 text-xs font-mono">
                <span className="text-amber-600 dark:text-amber-400 font-bold block text-[10px]">
                  Agent Justification (Untrusted):
                </span>
                <span className="text-slate-800 dark:text-slate-200">
                  "{pendingExpansion.justification}"
                </span>
              </div>

              {/* Deny Reason Input */}
              {showDenyInput && (
                <div className="space-y-1.5 pt-1">
                  <input
                    type="text"
                    value={denyReason}
                    onChange={e => setDenyReason(e.target.value)}
                    placeholder="Enter denial reason..."
                    className="w-full text-xs font-mono bg-white dark:bg-slate-900 border border-rose-500/40 rounded-lg p-2 text-slate-900 dark:text-white"
                  />
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center justify-end gap-3 pt-1">
                {!showDenyInput ? (
                  <button
                    onClick={() => setShowDenyInput(true)}
                    disabled={approvingExpansion}
                    className="px-3.5 py-1.5 text-xs font-semibold text-rose-600 hover:text-rose-500 border border-rose-500/30 rounded-xl hover:bg-rose-500/10 transition-colors"
                  >
                    Deny...
                  </button>
                ) : (
                  <button
                    onClick={() => handleInlineDeny(pendingExpansion.request_id)}
                    disabled={approvingExpansion}
                    className="px-3.5 py-1.5 text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white rounded-xl transition-colors"
                  >
                    Confirm Denial
                  </button>
                )}

                <button
                  id={`inline-approve-btn-${pendingExpansion.request_id}`}
                  onClick={() => handleInlineApprove(pendingExpansion.request_id)}
                  disabled={approvingExpansion}
                  className="px-4 py-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl shadow-md transition-colors flex items-center gap-1.5"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Approve Expansion</span>
                </button>
              </div>
            </div>
          )}

          {/* Timeline of Live Steps */}
          <div className="p-4 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2.5">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                Live Execution Timeline
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                {steps.length} total events
              </span>
            </div>

            {streamNote && (
              <div id="stream-note" className="text-[11px] font-mono text-amber-600 dark:text-amber-400">
                {streamNote}
              </div>
            )}

            {steps.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-400 italic">
                Awaiting task execution. Press "Start Governed Run" to initiate.
              </div>
            ) : (
              <div className="space-y-3">
                {steps.map(step => {
                  const isBlocked = step.verdict === 'DENY' || step.verdict === 'BLOCKED';
                  const isPending = step.verdict === 'PENDING';
                  const isAllow = step.verdict === 'ALLOW';
                  const isExpanded = expandedSteps[step.step_number];

                  // Source label pill styling
                  const sourcePillClass =
                    step.source_label === 'enforced'
                      ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/20'
                      : step.source_label === 'observed by OS sensor'
                      ? 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20'
                      : step.source_label === 'model output (untrusted)'
                      ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
                      : 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20';

                  return (
                    <div
                      key={step.step_number}
                      className={`p-3.5 rounded-xl border text-xs transition-all duration-200 animate-in fade-in slide-in-from-bottom-2 ${
                        isBlocked
                          ? 'border-rose-500/60 bg-rose-500/5 animate-pulse'
                          : isPending
                          ? 'border-amber-500/60 bg-amber-500/5'
                          : isAllow
                          ? 'border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/30'
                          : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/40'
                      }`}
                    >
                      {/* Step Header */}
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                            #{step.step_number}
                          </span>

                          {/* Source Label */}
                          <span
                            className={`font-mono text-[10px] px-2 py-0.5 rounded border font-semibold ${sourcePillClass}`}
                          >
                            {step.source_label}
                          </span>

                          {/* Layer Badge */}
                          <span className="font-mono text-[10px] text-slate-500 uppercase">
                            [{step.layer}]
                          </span>

                          {/* Verdict Badge */}
                          <span
                            className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded ${
                              isBlocked
                                ? 'bg-rose-500 text-white'
                                : isPending
                                ? 'bg-amber-500 text-white'
                                : isAllow
                                ? 'bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 font-semibold'
                                : 'bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200'
                            }`}
                          >
                            {step.verdict}
                          </span>
                        </div>

                        <span className="text-[10px] text-slate-400 font-mono">
                          {step.timestamp.split('T')[1]?.slice(0, 8) || step.timestamp}
                        </span>
                      </div>

                      {/* Step Summary */}
                      <div className="mt-2 text-slate-800 dark:text-slate-200 font-medium text-xs leading-relaxed">
                        {step.summary}
                      </div>

                      {/* Collapsible Detail */}
                      {step.detail && step.detail.trim().length > 0 && (
                        <div className="mt-2 pt-2 border-t border-slate-200/50 dark:border-slate-800/50">
                          <button
                            onClick={() => toggleStepExpand(step.step_number)}
                            className="text-[11px] text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1 font-mono"
                          >
                            <span>{isExpanded ? 'Hide details' : 'Show details'}</span>
                            {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          </button>
                          {isExpanded && (
                            <pre className="mt-1.5 p-2 rounded-lg bg-slate-100 dark:bg-slate-950 font-mono text-[10px] text-slate-700 dark:text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-60 overflow-y-auto">
                              {step.detail}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* ========================================================= */}
          {/* CONCLUDED TASK DATA: OUTPUT FILE & VERIFIED RECEIPT       */}
          {/* ========================================================= */}
          {outputFiles.length > 0 && (
            <div className="p-4 rounded-2xl bg-white dark:bg-surface-cardDark border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
              <div className="flex items-center gap-1.5 border-b border-slate-100 dark:border-slate-800 pb-2.5">
                <FileText className="w-4 h-4 text-emerald-500" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                  Generated Output Files ({outputFiles.length})
                </span>
              </div>
              <div className="space-y-3">
                {outputFiles.map(out => (
                  <div
                    key={out.path}
                    className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs font-mono space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-emerald-600 dark:text-emerald-400">
                        {out.path}
                      </span>
                      <span className="text-[10px] text-slate-400">{out.size} bytes</span>
                    </div>
                    <pre className="p-2.5 rounded bg-white dark:bg-black/40 text-[11px] text-slate-800 dark:text-slate-200 whitespace-pre-wrap max-h-48 overflow-y-auto border border-slate-200 dark:border-slate-800">
                      {out.content}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Verified Receipt Card */}
          {receiptData && (
            <div className="p-5 rounded-2xl bg-white dark:bg-surface-cardDark border-2 border-emerald-500/40 shadow-sm space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                  <div>
                    <span className="text-xs font-bold text-slate-900 dark:text-white block">
                      Hash-chained Task Receipt
                    </span>
                    <span className="text-[11px] text-emerald-600 dark:text-emerald-400 font-mono font-medium">
                      {receiptData.verified ? 'Verified (SHA-256 hash chain intact)' : 'Unverified / Chain mismatch'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <a
                    href={api.getRawReceiptUrl(receiptData.task_id)}
                    download={`${receiptData.task_id}_receipt.json`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-xl transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download receipt (JSON)</span>
                  </a>

                  <Link
                    to={`/tasks/${receiptData.task_id}`}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 hover:bg-cyan-500/20 rounded-xl transition-colors"
                  >
                    <span>View Task Detail</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              {/* Receipt Hash Details */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 text-[10px] block">Final Hash Chain</span>
                  <span className="text-slate-700 dark:text-slate-300 truncate block">
                    {receiptData.final_hash || receiptData.receipt?.hash_chain?.final_hash || 'N/A'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                  <span className="text-slate-400 text-[10px] block">Recorded Events</span>
                  <span className="text-slate-700 dark:text-slate-300 block">
                    {receiptData.receipt?.hash_chain?.count || receiptData.receipt?.events?.length || 0} chained events
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
