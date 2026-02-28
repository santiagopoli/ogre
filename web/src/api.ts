const BASE = '/api/v1';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error || res.statusText);
  }
  return res.json();
}

export interface DashboardSummary {
  total_actions: number;
  pending_actions: number;
  chain_valid: boolean;
  connectors_count: number;
  rules_count: number;
}

export interface RuleResponse {
  id: string;
  description: string;
  effect: string;
  priority: number;
  created_at: string;
}

export interface AuditEntry {
  sequence: number;
  timestamp: string;
  action_id: string;
  classification: string | null;
  decision: string;
  step_reached: string;
}

export interface ConnectorResponse {
  id: string;
  name: string;
}

export interface CapabilityResponse {
  id: string;
  name: string;
  description: string;
  level: string;
}

export interface KeysResponse {
  ogre: string | null;
  reviewer: string | null;
  user: string | null;
}

export interface ChainVerification {
  valid: boolean;
  entries_checked: number;
  first_broken: number | null;
}

export const api = {
  dashboard: () => request<DashboardSummary>('/dashboard/summary'),
  rules: () => request<RuleResponse[]>('/rules'),
  createRule: (rule: {
    description: string;
    condition: unknown;
    effect: string;
    priority: number;
  }) => request<RuleResponse>('/rules', { method: 'POST', body: JSON.stringify(rule) }),
  audit: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<AuditEntry[]>(`/audit${qs}`);
  },
  verifyChain: () => request<ChainVerification>('/audit/verify'),
  connectors: () => request<ConnectorResponse[]>('/connectors'),
  capabilities: (id: string) => request<CapabilityResponse[]>(`/connectors/${id}/capabilities`),
  keys: () => request<KeysResponse>('/keys'),
  pendingActions: () => request<string[]>('/actions/pending'),
};
