export type TaskLifecycle = 'CREATED' | 'RUNNING' | 'ACTIVE' | 'COMPLETED' | 'FAILED' | 'TERMINATED' | 'FROZEN';
export type EnforcementMode = 'OBSERVE' | 'ENFORCE';
export type EventVerdict = 'INSIDE' | 'OUTSIDE' | 'AMBIGUOUS' | 'UNATTRIBUTED';
export type RiskTier = 'LOW' | 'MEDIUM' | 'HIGH';
export type ExpansionStatus = 'PENDING' | 'APPROVED' | 'DENIED' | 'AUTO_APPROVED';

export interface TaskRecord {
  task_id: string;
  request_text: string;
  request_hash?: string;
  agent_id: string;
  workspace_root: string;
  status: TaskLifecycle;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  total_actions: number;
  actions_inside: number;
  actions_outside: number;
  prevented_count: number;
  compliance_pct: number;
  llm_provider?: string;
  os_denials_count?: number;
}

export interface TaskBoundary {
  task_id: string;
  workspace_root: string;
  files_read: string[];
  files_write: string[];
  tools: string[];
  network_hosts?: string[];
  peer_agents?: string[];
  version?: number;
}

export interface TaskEvent {
  event_id?: string;
  task_id: string;
  agent_id?: string;
  timestamp: string;
  source: string;
  kind: string;
  target?: string;
  verdict: EventVerdict;
  risk_tier?: RiskTier;
  action_taken?: string;
  prevented: boolean;
  prevented_by?: string;
  rule_matched?: string;
  channel?: string;
  observed_by?: string[];
  details?: Record<string, any>;
  syscall?: string;
  seq?: number;
}

export interface UntrustedRead {
  task_id: string;
  agent_id?: string;
  timestamp: string;
  source_type: string;
  source_target: string;
  content_hash: string;
  content_len: number;
  content_snippet?: string;
  linked?: boolean;
}

export interface ExpansionItem {
  request_id: string;
  task_id: string;
  agent_id: string;
  resource_type: string;
  resource_target: string;
  baseline_risk_tier: RiskTier;
  effective_risk_tier: RiskTier;
  justification: string;
  status: ExpansionStatus;
  created_at: string;
  resolved_at?: string;
  resolved_by?: string;
  decided_at?: string;
  decided_by?: string;
  denial_reason?: string;
  reason?: string;
  single_use?: boolean;
  timeout_seconds?: number;
  escalated_by_provenance?: boolean;
  provenance_escalation?: boolean;
  task_request_text?: string;
  prior_untrusted_reads?: UntrustedRead[];
}

export interface TaskReceipt {
  task_id: string;
  version?: string;
  events?: TaskEvent[];
  hash_chain?: {
    count: number;
    final_hash: string;
  };
  event_counts?: {
    by_verdict?: Record<string, number>;
  };
  [key: string]: any;
}

export interface ReceiptResponse {
  task_id: string;
  available?: boolean;
  receipt: TaskReceipt | null;
  verified: boolean;
  verification_message: string;
  receipt_file?: string | null;
  file_sha256?: string | null;
  final_hash?: string | null;
}

export interface ResultsSummary {
  generated_at: string;
  evaluation_label: string;
  model: string;
  harm_injected: Record<string, { exposed: number; total: number; rate: number; ratio: string }>;
  shell_only_decoy_exposure: Record<string, { exposed: number; total: number; rate: number; ratio: string }>;
  shell_attacks_succeeded: Record<string, { succeeded: number; total: number; ratio: string }>;
  utility_anticipated_correct: Record<string, { correct: number; total: number; rate: number; ratio: string }>;
  expansion_chain_unanticipated_c: {
    denied_before_request: number;
    requested: number;
    granted: number;
    delivered_read_ok: number;
    total: number;
    chain: number[];
    chain_str: string;
    steps?: Array<{ name: string; count: number; total: number }>;
  };
  timings_and_timeouts: Record<string, { mean_s?: number; median_s?: number; total_trials?: number; timeouts?: number; timeout_ratio?: string }>;
  limitations: string[];
}

export interface AgentInventoryItem {
  agent_id: string;
  declared_role?: string;
  status: 'GOVERNED' | 'SHADOW';
  active_task_id?: string;
  last_seen?: string;
  reputation_score?: number;
}


export interface SystemStatusResponse {
  status: 'healthy' | 'partial' | 'unsupported';
  landlock_abi: number;
  seccomp_available: boolean;
  cgroup_v2: boolean;
  sensor_mode: string;
  enforcing: boolean;
}


export interface TaskStep {
  task_id: string;
  step_number: number;
  timestamp: string;
  kind: string;
  layer: string;
  verdict: string;
  summary: string;
  detail: string;
  source_label: string;
}

export interface RunPreset {
  id: string;
  name: string;
  description: string;
  prompt: string;
  files: Record<string, string>;
}

export interface BoundaryPreviewResponse {
  active_version: string;
  boundary_v1: {
    files_read: string[];
    files_write: string[];
    tools: string[];
    hosts: string[];
    peer_agents?: string[];
  };
  boundary_v2: {
    files_read: string[];
    files_write: string[];
    tools: string[];
    hosts: string[];
    peer_agents?: string[];
    requires_user_review?: boolean;
  } | null;
  explanation: string;
}

export interface RunOutputFile {
  path: string;
  name: string;
  size: number;
  content: string;
  truncated: boolean;
}

export interface RunModelsResponse {
  models: string[];
  default: string;
  scripted_available: boolean;
}

export interface ActiveRunInfo {
  active: boolean;
  task_id: string | null;
  elapsed_seconds: number;
}
