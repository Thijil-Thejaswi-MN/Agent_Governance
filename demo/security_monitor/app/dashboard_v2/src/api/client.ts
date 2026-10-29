import {
  SystemStatusResponse,
  TaskRecord,
  TaskBoundary,
  TaskEvent,
  ExpansionItem,
  ReceiptResponse,
  ResultsSummary,
  AgentInventoryItem,
  TaskStep,
  RunPreset,
  BoundaryPreviewResponse,
  RunOutputFile,
  RunModelsResponse,
  ActiveRunInfo,
} from '../types';

const API_BASE = '/api/governance';

export function getOperatorToken(): string | null {
  return sessionStorage.getItem('governance_operator_token');
}

export function setOperatorToken(token: string): void {
  if (token) {
    sessionStorage.setItem('governance_operator_token', token.trim());
  } else {
    sessionStorage.removeItem('governance_operator_token');
  }
}

export function clearOperatorToken(): void {
  sessionStorage.removeItem('governance_operator_token');
}

// Fired on any 401 so that the layout can switch every page to its "sign in" state.
export const UNAUTHORIZED_EVENT = 'governance:unauthorized';

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getOperatorToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
    headers['X-Operator-Token'] = token;
  }

  const res = await fetch(endpoint, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorDetail = `Request failed: HTTP ${res.status}`;
    let problems: string[] = [];
    try {
      const errJson = await res.json();
      const detail = errJson?.detail;
      if (typeof detail === 'string') {
        errorDetail = detail;
      } else if (Array.isArray(detail)) {
        // FastAPI request-validation errors
        errorDetail = detail.map((d: any) => d?.msg || JSON.stringify(d)).join('; ');
      } else if (detail && typeof detail === 'object') {
        errorDetail = detail.message || errorDetail;
        problems = Array.isArray(detail.problems) ? detail.problems : [];
      }
    } catch {
      // ignore json parse error
    }
    const err = new Error(errorDetail);
    (err as any).status = res.status;
    (err as any).problems = problems;
    if (res.status === 401) {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    }
    throw err;
  }

  return res.json() as Promise<T>;
}

export const api = {
  async getSystemStatus(): Promise<SystemStatusResponse> {
    return request(`${API_BASE}/system/status`);
  },
  // Tasks
  getTasks: () => request<TaskRecord[]>(`${API_BASE}/tasks`),
  
  getTaskDetail: (taskId: string) =>
    request<{ task: TaskRecord; boundary: TaskBoundary | null; summary: any }>(`${API_BASE}/tasks/${taskId}`),
  
  getTaskEvents: (taskId: string) =>
    request<TaskEvent[]>(`${API_BASE}/tasks/${taskId}/events`),
  
  getTaskReceipt: (taskId: string) =>
    request<ReceiptResponse>(`${API_BASE}/tasks/${taskId}/receipt`),

  // Expansions
  getExpansions: (taskId?: string, status?: string) => {
    const params = new URLSearchParams();
    if (taskId) params.append('task_id', taskId);
    if (status) params.append('status', status);
    const qs = params.toString();
    return request<ExpansionItem[]>(`${API_BASE}/expansions${qs ? `?${qs}` : ''}`);
  },

  approveExpansion: (requestId: string, payload: { decided_by: string; reason?: string }) =>
    request<{ status: string; new_boundary: TaskBoundary }>(`${API_BASE}/expansions/${requestId}/approve`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  denyExpansion: (requestId: string, payload: { decided_by: string; reason: string }) =>
    request<{ status: string }>(`${API_BASE}/expansions/${requestId}/deny`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  grantResource: (taskId: string, payload: { granted_by: string; resource_type: string; resource_target: string; single_use: boolean }) =>
    request<{ status: string; new_boundary: TaskBoundary }>(`${API_BASE}/tasks/${taskId}/grant`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Events Stream
  getEvents: (since?: string, limit: number = 100) => {
    const params = new URLSearchParams();
    if (since) params.append('since', since);
    params.append('limit', String(limit));
    return request<{ events: TaskEvent[]; cursor: string; total: number }>(`${API_BASE}/events?${params.toString()}`);
  },

  getRawReceiptUrl: (taskId: string) => `${API_BASE}/tasks/${taskId}/receipt/raw`,

  // Inventory & Alerts
  getInventory: () => request<AgentInventoryItem[]>(`${API_BASE}/inventory`),
  getAlerts: () => request<any[]>(`${API_BASE}/alerts`),
  getConfig: () => request<{ system_mode: string; provenance_enabled: boolean }>(`${API_BASE}/config`),
  getAuthStatus: () =>
    request<{ operator_token_configured: boolean; session_active: boolean }>(`${API_BASE}/auth/status`),

  // Exchanges the token for an HttpOnly read-session cookie (used by EventSource and plain links).
  createSession: async (token: string): Promise<{ authenticated: boolean; expires_at: string }> => {
    const res = await fetch(`${API_BASE}/auth/session`, {
      method: 'POST',
      headers: { 'X-Operator-Token': token },
      credentials: 'same-origin',
    });
    if (!res.ok) {
      let detail = `Sign-in failed: HTTP ${res.status}`;
      try {
        detail = (await res.json()).detail || detail;
      } catch {
        // ignore
      }
      const err = new Error(detail);
      (err as any).status = res.status;
      throw err;
    }
    return res.json();
  },
  deleteSession: () => fetch(`${API_BASE}/auth/session`, { method: 'DELETE', credentials: 'same-origin' }),

  // Evaluation Results Summary
  getResultsSummary: async (): Promise<ResultsSummary> => {
    // Try both absolute and relative locations
    try {
      const res = await fetch('/dashboard/results_summary.json');
      if (res.ok) return res.json();
    } catch {}
    try {
      const res = await fetch('/results_summary.json');
      if (res.ok) return res.json();
    } catch {}
    return fetch('./results_summary.json').then(r => r.json());
  },

  // Run Execution
  getRunPresets: () => request<RunPreset[]>(`${API_BASE}/run/presets`),
  getRunModels: () => request<RunModelsResponse>(`${API_BASE}/run/models`),
  getActiveRun: () => request<ActiveRunInfo>(`${API_BASE}/run/active`),
  previewRun: (payload: { prompt: string; preset?: string; files?: Record<string, string> }) =>
    request<BoundaryPreviewResponse>(`${API_BASE}/run/preview`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  startRun: (payload: { prompt: string; preset?: string; model?: string; files?: Record<string, string> }) =>
    request<{ task_id: string; status: string; message: string }>(`${API_BASE}/run`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  stopRun: (taskId: string) =>
    request<{ task_id: string; status: string; message: string; killed: boolean; cancelled_before_start: boolean }>(`${API_BASE}/run/${taskId}/stop`, {
      method: 'POST',
    }),
  getRunSteps: (taskId: string, after: number = 0) =>
    request<TaskStep[]>(`${API_BASE}/run/${taskId}/steps?after=${after}`),
  getRunOutput: (taskId: string) =>
    request<{ task_id: string; files: RunOutputFile[] }>(`${API_BASE}/run/${taskId}/output`),
  getRunStreamUrl: (taskId: string) => `${API_BASE}/run/${taskId}/stream`,

};
