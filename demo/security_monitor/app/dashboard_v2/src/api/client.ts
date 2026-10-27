import {
  SystemStatusResponse,
  TaskRecord,
  TaskBoundary,
  TaskEvent,
  ExpansionItem,
  ReceiptResponse,
  ResultsSummary,
  AgentInventoryItem
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
    try {
      const errJson = await res.json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      // ignore json parse error
    }
    const err = new Error(errorDetail);
    (err as any).status = res.status;
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
  getAuthStatus: () => request<{ operator_token_configured: boolean }>(`${API_BASE}/auth/status`),

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
};
