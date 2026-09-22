import { useEffect, useRef, useState } from "react";
import {
  API_BASE,
  type DoneEvent,
  type LedgerEvent,
  type LeverEvent,
  type LlmCallEvent,
  type Phase,
  type PhaseEvent,
  type StreamErrorEvent,
  type ToolCallEvent,
  type VerifyEvent,
} from "./api";

export type StreamStatus = "idle" | "connecting" | "streaming" | "done" | "error";

export interface TraceState {
  status: StreamStatus;
  phase: Phase | null;
  phasesSeen: Phase[];
  toolCalls: ToolCallEvent[];
  llmCalls: LlmCallEvent[];
  levers: LeverEvent[];
  ledger: LedgerEvent[];
  verification: VerifyEvent | null;
  error: string | null;
  lastSeq: number;
}

const EMPTY: TraceState = {
  status: "idle",
  phase: null,
  phasesSeen: [],
  toolCalls: [],
  llmCalls: [],
  levers: [],
  ledger: [],
  verification: null,
  error: null,
  lastSeq: 0,
};

/**
 * Follows one investigation's progress stream.
 *
 * Deliberately does not carry the case file: `done` means "refetch over REST",
 * so there is exactly one authoritative representation of a case file and this
 * hook never becomes a second parser of it.
 *
 * Reconnection is the browser's job. EventSource resends Last-Event-ID on its
 * own and the server replays from its buffer, which is most of why the
 * transport is SSE rather than a WebSocket.
 */
export function useInvestigationStream(jobId: string | null, onDone?: () => void): TraceState {
  const [state, setState] = useState<TraceState>(EMPTY);
  // Kept in a ref so re-renders do not re-subscribe and replay the run.
  const doneRef = useRef(onDone);
  doneRef.current = onDone;

  useEffect(() => {
    if (!jobId) {
      setState(EMPTY);
      return;
    }

    setState({ ...EMPTY, status: "connecting" });
    const source = new EventSource(`${API_BASE}/investigations/${jobId}/events`);

    function patch(fn: (prev: TraceState) => TraceState) {
      setState((prev) => ({ ...fn(prev), status: "streaming" }));
    }

    function on<T>(type: string, handle: (data: T, prev: TraceState) => TraceState) {
      source.addEventListener(type, (raw) => {
        const data = JSON.parse((raw as MessageEvent).data) as T & { seq: number };
        patch((prev) => ({ ...handle(data, prev), lastSeq: data.seq }));
      });
    }

    on<PhaseEvent>("phase", (e, prev) => ({
      ...prev,
      phase: e.phase,
      phasesSeen: prev.phasesSeen.includes(e.phase) ? prev.phasesSeen : [...prev.phasesSeen, e.phase],
    }));
    on<ToolCallEvent>("tool_call", (e, prev) => ({ ...prev, toolCalls: [...prev.toolCalls, e] }));
    on<LlmCallEvent>("llm_call", (e, prev) => ({ ...prev, llmCalls: [...prev.llmCalls, e] }));
    on<LedgerEvent>("ledger", (e, prev) => ({ ...prev, ledger: [...prev.ledger, e] }));
    on<LeverEvent>("lever", (e, prev) => ({ ...prev, levers: [...prev.levers, e] }));
    on<VerifyEvent>("verify", (e, prev) => ({ ...prev, verification: e }));

    source.addEventListener("done", (raw) => {
      const data = JSON.parse((raw as MessageEvent).data) as DoneEvent;
      setState((prev) => ({ ...prev, status: "done", phase: null, lastSeq: data.seq }));
      source.close();
      doneRef.current?.();
    });

    source.addEventListener("error", (raw) => {
      // Two very different things arrive here: a server-sent `error` event with
      // a JSON body, and EventSource's own transport error, which has none.
      // Only the first is terminal — the browser retries the second itself.
      const message = (raw as MessageEvent).data;
      if (typeof message !== "string") return;
      const data = JSON.parse(message) as StreamErrorEvent;
      setState((prev) => ({ ...prev, status: "error", error: data.message, lastSeq: data.seq }));
      source.close();
    });

    return () => source.close();
  }, [jobId]);

  return state;
}
