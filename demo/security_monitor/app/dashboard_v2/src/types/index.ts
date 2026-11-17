// The server's TaskLifecycle (models.py), plus older values some records may carry.
export type TaskLifecycle = 'PENDING' | 'ACTIVE' | 'COMPLETED' | 'FAILED' | 'TERMINATED' | 'EXPIRED' | 'CREATED' | 'RUNNING' | 'FROZEN';
export type EnforcementMode = 'OBSERVE' | 'ENFORCE';
export type EventVerdict = 'INSIDE' | 'OUTSIDE' | 'AMBIGUOUS' | 'UNATTRIBUTED';
export type RiskTier = 'LOW' | 'MEDIUM' | 'HIGH';
export type ExpansionStatus = 'PENDING' | 'APPROVED' | 'DENIED' | 'AUTO_APPROVED' | 'REVOKED';

export interface TaskRecord {
  owner?: string | null;
  team?: string | null;
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
  condition?: string | null;
  comparison_mode?: boolean;
  model?: string | null;
}

export interface TaskBoundary {
  network_outbound?: string[];
  task_id: string;
  workspace_root: string;
  files_read: string[];
  files_write: string[];
  tools: string[];
  network?: string[];
  network_hosts?: string[];
  peer_agents?: string[];
  version?: number;
}

export interface TaskEvent {
  operation?: string;
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
  /** "Allow for N minutes": when the grant ends on its own. */
  expires_at?: string | null;
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
  /** whole_record (v1: events chained and the whole record hashed) or events_only (older v0 record). */
  verified_scope?: 'whole_record' | 'events_only' | null;
  verification_message: string;
  receipt_file?: string | null;
  file_sha256?: string | null;
  final_hash?: string | null;
}

export interface ResultsSummary {
  generated_at: string;
  evaluation_label: string;
  model: string;
  harm_injected: Record<string, { exposed: number; total: number; rate: number; ratio: string; attempted?: number }>;
  shell_only_decoy_exposure: Record<string, { exposed: number; total: number; rate: number; ratio: string; attempted?: number }>;
  shell_attacks_succeeded: Record<string, { succeeded: number; total: number; ratio: string }>;
  utility_anticipated_correct: Record<string, { correct: number; total: number; rate: number; ratio: string }>;
  utility_unanticipated_correct?: Record<string, { correct: number; total: number; ratio: string; mean_s: number | null }>;
  utility_boundary_source?: string;
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
  utility_timings_anticipated?: {
    A?: { mean_s: number; mean_s_exact?: number; total_trials: number };
    C?: { mean_s: number; mean_s_exact?: number; total_trials: number };
    extra_s_c_vs_a?: number;
  };
  limitations: string[];
}

export interface AgentInventoryItem {
  agent_id: string;
  name?: string;
  owner?: string;
  classification?: string;
  status: string;
  active_task_id?: string;
  last_seen?: string;
  reputation_score?: number;
  description?: string | null;
  skills?: string[];
  governance_state?: string | null;
  metadata?: Record<string, any>;
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
  comparable?: boolean;
  tools_needed?: string[];
  /** The configured agent this example is a job for. */
  agent?: string | null;
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
  location?: string;
  windows_location?: string | null;
  contains_private?: boolean | null;
}

/** One file the run involved, opened from its name on the Run page. */
export interface RunFile extends RunOutputFile {
  kind: 'input' | 'output' | 'private';
  location?: string | undefined;
  canary?: string | null;
}

export interface RunModelsResponse {
  models: string[];
  default: string;
  scripted_available: boolean;
  ollama_reachable?: boolean;
}

export interface ConfiguredAgent {
  id: string;
  name: string;
  owner: string;
  team: string;
  description: string;
  model?: string; // the model this agent runs on
  tools?: string[]; // the tools its agent loop offers; each call is checked by the broker
}

export interface ActiveRunTask {
  task_id: string;
  agent_id?: string;
  elapsed_seconds: number;
}

export interface ActiveRunInfo {
  active: boolean;
  task_id: string | null;
  elapsed_seconds: number;
  active_count?: number;
  max_concurrent?: number;
  active_tasks?: ActiveRunTask[];
}

export type DotState = 'working' | 'waiting' | 'blocked' | 'idle' | 'no_task';

export interface FleetNeedsYouItem {
  request_id: string;
  task_id: string;
  agent_id: string;
  resource_type: string;
  resource_target: string;
  escalated_by_provenance: boolean;
  learned_from: string | null;
  baseline_risk_tier?: string;
  effective_risk_tier?: string;
  created_at: string;
  deadline: string | null;
}

export interface FleetBlockedGroup {
  target_class: 'mentioned_in_input' | 'outside_website' | 'private_folder' | 'other';
  count: number;
  task_count: number;
  task_ids: string[];
  agent_count: number;
  by_layer: Record<string, number>;
  by_kind: Record<string, number>;
  examples: string[];
  plain: string;
  label: string;
}

export interface FleetDot {
  id: string;
  label: string;
  state: DotState;
  task_id: string | null;
  view: 'watch' | 'history' | null;
  classification?: string;
}

export interface FleetSummary {
  generated_at: string;
  agents_at_work: number;
  need_you: number;
  running_tasks: Array<{ task_id: string; agent_id: string; request_text: string; started_at: string; state: DotState }>;
  dots: { basis: 'inventory' | 'tasks'; items: FleetDot[]; counts: Partial<Record<DotState, number>> };
  needs_you: FleetNeedsYouItem[];
  blocked: { window_hours: number; total: number; groups: FleetBlockedGroup[] };
  inventory_size: number;
  known_tasks: number;
}


export type Role = 'developer' | 'team_lead' | 'security_reviewer' | 'admin' | 'auditor';

export interface UserSession {
  name: string;
  role: Role;
  team?: string | null;
}

export interface PendingGroup {
  group_key: string;
  /** The server's field; older code read normalized_target. */
  target?: string;
  requests?: { request_id: string; task_id: string }[];
  agent_id: string;
  resource_type: string;
  normalized_target: string;
  escalated_by_provenance: boolean;
  count: number;
  request_ids: string[];
  justifications: string[];
  created_at_min: string;
  created_at_max: string;
}

// Shape returned by /standing-rules (see logic/rules.ts for wording).
export type { PolicyRule as StandingRule } from '../logic/rules';

export interface RecordsSummary {
  total: number;
  verified: number;
  failed: number;
  failed_ids: string[];
  /** Records that passed the check (both scopes). Older servers omit these lists. */
  verified_ids?: string[];
  /** Older v0 records: only the event list could be checked. */
  events_only_ids?: string[];
}

// Evidence browser: recorded evaluation trials, read from the committed raw files.
export interface EvidenceMetric {
  label: string;
  value: number;
  of: number;
}

export interface EvidenceDataset {
  id: string;
  title: string;
  about: string;
  file: string;
  scenario_files: string[];
  trials: number;
  model: string | null;
  by_condition: Record<string, { name: string; trials: number; metrics: EvidenceMetric[] }>;
}

export interface EvidenceRow {
  scenario_id: string;
  category: string;
  condition: string;
  repeat: number;
  harm: boolean;
  decoy_exposed: boolean;
  written_outside: boolean;
  sink_contacted: boolean;
  injection_exposed: boolean;
  answer_correct: boolean | null;
  attempts_blocked: number;
  steps: number;
  wall_time_s: number | null;
  has_receipt: boolean;
}

export interface EvidenceStep {
  step: number;
  tool: string;
  args: Record<string, unknown> | null;
  status: string;
  output: unknown;
  error: unknown;
}

export interface EvidenceTrial {
  dataset: string;
  row: EvidenceRow;
  condition_name: string;
  model: string | null;
  git_commit: string | null;
  timestamp: string | null;
  canary: string | null;
  ground_truth: Record<string, unknown> | null;
  scenario: {
    id: string;
    user_prompt: string | null;
    input_files: Record<string, string>;
    expected_boundary: Record<string, unknown> | null;
    injected_target: string | null;
    decoys: string[];
    expected_answer_numbers: string[] | null;
  };
  tool_history: EvidenceStep[];
  attempts: Array<Record<string, unknown>>;
  receipt: {
    task_id: string;
    integrity: string;
    isolation_level: string;
    initial_boundary: Record<string, unknown> | null;
    event_counts: { total: number; by_verdict: Record<string, number> } | null;
    outside_events: Array<Record<string, unknown>>;
    chain_verified: boolean;
    chain_message: string;
    final_hash: string;
    recorded_final_hash: string | null;
    chained_events: number;
  } | null;
}

// Guided evidence walkthrough: one attack, the trap and the key step in each setup.
export type AttackVerdict = 'reached' | 'done' | 'broker' | 'kernel' | 'network' | 'asked_refused' | 'failed';

export interface AttackRow {
  id: string;
  injected_action: string;
  injected_target: string;
  phrasing: string;
  by_condition: Record<string, { trials: number; harm: number; acted: number }>;
}

export interface AttackStory {
  repeat: number;
  harm: boolean;
  decoy_exposed: boolean;
  written_outside: boolean;
  sink_contacted: boolean;
  saw_note: boolean;
  answer_correct: boolean | null;
  steps: number;
  key_step: { step: number; tool: string; what: string; result: string; verdict: AttackVerdict } | null;
  prevented_by: string[];
  canary: string | null;
  has_receipt: boolean;
}

export interface AttackDetail {
  dataset: string;
  model: string;
  file: string;
  scenario_files: string[];
  scenario: {
    id: string;
    user_prompt: string;
    injected_action: string;
    injected_target: string;
    phrasing: string;
    boundary: { files_read?: string[]; files_write?: string[]; hosts?: string[]; tools?: string[] } | null;
    decoys: string[];
    files: { path: string; lines: { n: number; text: string; hidden: boolean }[] }[];
  };
  conditions: { condition: string; name: string; trials: number; harm: number; acted: number; stories: AttackStory[] }[];
}
