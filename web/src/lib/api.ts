/**
 * Typed client for the alert2attack API.
 *
 * Every type the API owns is aliased out of `schema.d.ts`, which
 * `npm run gen:types` regenerates from the API's own OpenAPI document and CI
 * checks for drift. Retyping them here by hand would be a second copy of the
 * contract with nothing holding it to the first.
 */

import type { components } from "./schema";

type Schemas = components["schemas"];

export type SearchResponse = Schemas["SearchResponse"];
export type SearchHit = Schemas["Hit"];
export type SearchMode = SearchResponse["mode"];

export const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

export type Severity = Schemas["Severity"];
export type Split = Schemas["ScenarioSummary"]["split"];
export type Verdict = NonNullable<Schemas["Review"]["corrected_verdict"]>;
export type JobStatus = Schemas["InvestigationJobResponse"]["status"];
// `scripted` is a test-only model and the console never offers it.
export type AgentModel = Exclude<Schemas["CreateInvestigationRequest"]["model"], "scripted">;

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

export type ScenarioSummary = Schemas["ScenarioSummary"];
export type ScenarioDetail = Schemas["ScenarioDetail"];
export type TelemetryEvent = Schemas["Event"];
export type EventPage = Schemas["EventPage"];
export type EvidenceResolution = Schemas["EvidenceResolution"];
export type Review = Schemas["Review"];
export type ReviewRequest = Schemas["ReviewRequest"];

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

/**
 * The job row, with `result` narrowed.
 *
 * The API types `result` as a free-form object, so the OpenAPI document cannot
 * describe what is inside it. Everything else comes from the generated schema.
 */
export interface InvestigationJob extends Omit<Schemas["InvestigationJobResponse"], "result"> {
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

/** `/me` returns a free-form object, so this one stays hand-written too. */
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

async function failure(resp: Response): Promise<ApiError> {
  // FastAPI puts the message in `detail`; fall back to the status text.
  let detail = resp.statusText;
  try {
    const body = (await resp.json()) as { detail?: unknown };
    if (typeof body.detail === "string") detail = body.detail;
  } catch {
    // non-JSON error body; statusText is the best we have
  }
  return new ApiError(resp.status, detail);
}

async function get<T>(path: string): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/json", ...authHeaders() },
  });
  if (!resp.ok) throw await failure(resp);
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
  if (!resp.ok) throw await failure(resp);
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

  scenario: (id: string) => get<ScenarioDetail>(`/scenarios/${encodeURIComponent(id)}`),

  events: (id: string, opts: { cursor?: string | null; pid?: number; q?: string; limit?: number }) => {
    const params = new URLSearchParams();
    params.set("limit", String(opts.limit ?? 100));
    if (opts.cursor) params.set("cursor", opts.cursor);
    if (opts.pid !== undefined) params.set("pid", String(opts.pid));
    if (opts.q) params.set("q", opts.q);
    return get<EventPage>(`/scenarios/${encodeURIComponent(id)}/events?${params.toString()}`);
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

  investigation: (jobId: string) => get<InvestigationJob>(`/investigations/${encodeURIComponent(jobId)}`),

  evidence: (jobId: string, evidenceId: string) =>
    get<EvidenceResolution>(
      `/investigations/${encodeURIComponent(jobId)}/evidence/${encodeURIComponent(evidenceId)}`,
    ),

  searchTechniques: (q: string, mode?: SearchMode, k = 10) => {
    const params = new URLSearchParams({ q, k: String(k) });
    if (mode) params.set("mode", mode);
    return get<SearchResponse>(`/search/techniques?${params.toString()}`);
  },

  me: () => get<AuthState>("/me"),

  login: (username: string, password: string) =>
    post<{ access_token: string; expires_in: number }>("/auth/token", { username, password }),

  reviews: (scenarioId?: string) =>
    get<Review[]>(
      `/reviews${scenarioId ? `?${new URLSearchParams({ scenario_id: scenarioId }).toString()}` : ""}`,
    ),

  addReview: (jobId: string, body: ReviewRequest) =>
    post<Review>(`/investigations/${encodeURIComponent(jobId)}/review`, body),
};
