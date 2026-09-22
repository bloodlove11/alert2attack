/**
 * Typed client for the alert2attack API.
 *
 * The row types below mirror the Pydantic response models. They are a stopgap:
 * `npm run gen:types` regenerates `schema.d.ts` from the API's own OpenAPI
 * document, and these should be replaced by references into it rather than
 * maintained as a second, drifting copy of the contract.
 */

import type { components } from "./schema";

/** Generated from the API's OpenAPI document, not hand-written. */
export type SearchResponse = components["schemas"]["SearchResponse"];
export type SearchHit = components["schemas"]["Hit"];
export type SearchMode = "lexical" | "dense" | "hybrid";

export const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

export type Severity = "low" | "medium" | "high" | "critical";
export type Split = "dev" | "test";
export type Verdict = "malicious" | "suspicious" | "likely_benign" | "not_enough_evidence";
export type JobStatus = "queued" | "running" | "succeeded" | "failed";
export type AgentModel = "ollama" | "local-7b" | "openai" | "teacher" | "replay";

/** Progress event types, mirroring alert2attack.agent.progress. */
export type ProgressType =
  | "phase"
  | "tool_call"
  | "llm_call"
  | "ledger"
  | "lever"
  | "verify"
  | "done"
  | "error";

export type Phase = "plan" | "investigate" | "write" | "verify" | "repair" | "levers";

export interface PhaseEvent {
  type: "phase";
  seq: number;
  elapsed_ms: number;
  phase: Phase;
  status: "start" | "end";
}

export interface ToolCallEvent {
  type: "tool_call";
  seq: number;
  elapsed_ms: number;
  call_seq: number;
  tool: string;
  args_digest: string;
  ok: boolean;
  evidence_ids: string[];
  duration_ms: number;
  error: string | null;
}

export interface LlmCallEvent {
  type: "llm_call";
  seq: number;
  elapsed_ms: number;
  call_seq: number;
  role: string;
  model: string;
  prompt_chars: number;
  response_chars: number;
  tool_call_count: number;
  duration_ms: number;
}

export interface LedgerEvent {
  type: "ledger";
  seq: number;
  elapsed_ms: number;
  evidence_id: string;
  kind: "event" | "sigma_rule" | "attack_technique";
}

export interface LeverEvent {
  type: "lever";
  seq: number;
  elapsed_ms: number;
  lever_id: string;
  fired: boolean;
  effect: string | null;
}

export interface VerifyEvent {
  type: "verify";
  seq: number;
  elapsed_ms: number;
  status: string;
  passed: boolean;
  error_codes: string[];
  stripped_claims: number;
  repairs_used: number;
}

export interface DoneEvent {
  type: "done";
  seq: number;
  elapsed_ms: number;
  job_id: string | null;
}

export interface StreamErrorEvent {
  type: "error";
  seq: number;
  elapsed_ms: number;
  message: string;
}

export interface ScenarioSummary {
  scenario_id: string;
  split: Split;
  origin: "otrf" | "authored";
  description: string;
  alert_id: string;
  host: string;
  rule_id: string;
  rule_title: string;
  severity: Severity;
  fired_at: string;
}

export interface ScenarioDetail extends ScenarioSummary {
  window_start: string;
  window_end: string;
  trigger_event_id: string;
  event_count: number;
}

export interface TelemetryEvent {
  event_id: string;
  kind: string;
  ts: string;
  host: string;
  user?: string | null;
  pid?: number | null;
  ppid?: number | null;
  image?: string | null;
  command_line?: string | null;
  parent_image?: string | null;
  target_image?: string | null;
  target_path?: string | null;
  details?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  dest_host?: string | null;
  query?: string | null;
  [key: string]: unknown;
}

export interface EventPage {
  events: TelemetryEvent[];
  next_cursor: string | null;
  limit: number;
}

export interface Claim {
  text: string;
  evidence: string[];
}

export interface CaseFile {
  verdict: Verdict;
  confidence: "low" | "medium" | "high";
  summary: string;
  timeline: { ts: string; text: string; evidence: string[] }[];
  techniques: { technique_id: string; evidence: string[]; note: string }[];
  scope: {
    root_process?: Claim | null;
    involved_pids: number[];
    persistence: Claim[];
    beyond_process: boolean;
  };
  next_actions: { action: string; rationale: Claim }[];
  open_questions: string[];
}

export interface Verification {
  passed: boolean;
  status: "passed" | "repaired" | "degraded";
  errors: { path: string; code: string; message: string }[];
  repairs_used: number;
  stripped_claims: number;
}

export interface InvestigationJob {
  id: string;
  status: JobStatus;
  scenario_id: string;
  model: string;
  created_at: string;
  updated_at: string;
  error: string | null;
  result: {
    case_file: CaseFile;
    verification: Verification | null;
    trace: {
      model: string;
      budget: Record<string, unknown>;
      tool_calls: {
        seq: number;
        tool: string;
        ok: boolean;
        evidence_ids: string[];
        duration_ms: number;
      }[];
      notes: string[];
    };
  } | null;
}

export interface EvidenceResolution {
  evidence_id: string;
  kind: "event" | "sigma_rule" | "attack_technique";
  first_seen_tool_seq: number | null;
  event: TelemetryEvent | null;
  rule: {
    slug: string;
    title: string;
    description: string;
    level: string;
    tags: string[];
    falsepositives: string[];
  } | null;
  technique: {
    technique_id: string;
    name: string;
    tactics: string[];
    description: string;
  } | null;
}

export interface Review {
  id: string;
  job_id: string;
  scenario_id: string;
  agent_verdict: string;
  agrees: boolean;
  corrected_verdict: Verdict | null;
  note: string;
  reviewer: string;
  created_at: string;
}

export interface ReviewRequest {
  agrees: boolean;
  corrected_verdict?: Verdict | null;
  note?: string;
}

export interface AuthState {
  authenticated: boolean;
  auth_enabled: boolean;
  username?: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly detail: string,
  ) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
  }
}

/**
 * The bearer token lives in module memory, never in localStorage.
 *
 * localStorage is readable by any injected script, and this console renders
 * attacker-controlled command lines from telemetry — the wrong place to be
 * relaxed about XSS. The cost is that a refresh loses the session, which is
 * the right trade for a single-operator tool.
 */
let bearerToken: string | null = null;

export function setBearerToken(token: string | null): void {
  bearerToken = token;
}

export function getBearerToken(): string | null {
  return bearerToken;
}

function authHeaders(): Record<string, string> {
  return bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {};
}

async function get<T>(path: string): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/json", ...authHeaders() },
  });
  if (!resp.ok) {
    // FastAPI puts the message in `detail`; fall back to the status text.
    let detail = resp.statusText;
    try {
      const body = (await resp.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // non-JSON error body; statusText is the best we have
    }
    throw new ApiError(resp.status, detail);
  }
  return (await resp.json()) as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...authHeaders(),
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const parsed = (await resp.json()) as { detail?: unknown };
      if (typeof parsed.detail === "string") detail = parsed.detail;
    } catch {
      // non-JSON error body
    }
    throw new ApiError(resp.status, detail);
  }
  return (await resp.json()) as T;
}

export interface QueueFilters {
  split?: Split | "";
  severity?: Severity | "";
  q?: string;
}

export const api = {
  health: () => get<{ status: string }>("/health"),

  scenarios: (filters: QueueFilters = {}) => {
    const params = new URLSearchParams();
    if (filters.split) params.set("split", filters.split);
    if (filters.severity) params.set("severity", filters.severity);
    if (filters.q) params.set("q", filters.q);
    const query = params.toString();
    return get<ScenarioSummary[]>(`/scenarios${query ? `?${query}` : ""}`);
  },

  scenario: (id: string) => get<ScenarioDetail>(`/scenarios/${id}`),

  events: (id: string, opts: { cursor?: string | null; pid?: number; q?: string; limit?: number }) => {
    const params = new URLSearchParams();
    params.set("limit", String(opts.limit ?? 100));
    if (opts.cursor) params.set("cursor", opts.cursor);
    if (opts.pid !== undefined) params.set("pid", String(opts.pid));
    if (opts.q) params.set("q", opts.q);
    return get<EventPage>(`/scenarios/${id}/events?${params.toString()}`);
  },

  investigations: (limit = 50) => get<InvestigationJob[]>(`/investigations?limit=${limit}`),

  /**
   * Start a run. `replay` is the canned responder — it needs no model and is
   * the only option that works on a machine without Ollama.
   */
  startInvestigation: (scenarioId: string, model: AgentModel = "replay") =>
    post<InvestigationJob>("/investigations", {
      scenario_id: scenarioId,
      model,
      sync: false,
    }),

  investigation: (jobId: string) => get<InvestigationJob>(`/investigations/${jobId}`),

  evidence: (jobId: string, evidenceId: string) =>
    get<EvidenceResolution>(`/investigations/${jobId}/evidence/${evidenceId}`),

  searchTechniques: (q: string, mode?: SearchMode, k = 10) => {
    const params = new URLSearchParams({ q, k: String(k) });
    if (mode) params.set("mode", mode);
    return get<SearchResponse>(`/search/techniques?${params.toString()}`);
  },

  me: () => get<AuthState>("/me"),

  login: (username: string, password: string) =>
    post<{ access_token: string; expires_in: number }>("/auth/token", { username, password }),

  reviews: (scenarioId?: string) =>
    get<Review[]>(`/reviews${scenarioId ? `?scenario_id=${scenarioId}` : ""}`),

  addReview: (jobId: string, body: ReviewRequest) =>
    post<Review>(`/investigations/${jobId}/review`, body),
};
