import { Panel, SectionTitle } from "../components/ui";
import type { Phase } from "../lib/api";
import type { TraceState } from "../lib/useInvestigationStream";

const RAIL: { phase: Phase; label: string }[] = [
  { phase: "plan", label: "Plan" },
  { phase: "investigate", label: "Investigate" },
  { phase: "write", label: "Write" },
  { phase: "verify", label: "Verify" },
  { phase: "repair", label: "Repair" },
  { phase: "levers", label: "Levers" },
];

function StepRail({ trace }: { trace: TraceState }) {
  return (
    <ol className="flex flex-wrap gap-1 px-4 pb-3">
      {RAIL.map(({ phase, label }) => {
        const active = trace.phase === phase;
        const seen = trace.phasesSeen.includes(phase);
        const tone = active
          ? "border-accent bg-accent/20 text-accent"
          : seen
            ? "border-benign/40 bg-benign/10 text-benign"
            : "border-edge text-dim/60";
        return (
          <li key={phase} className={`rounded border px-2 py-1 text-[11px] ${tone}`}>
            {active ? "▸ " : seen ? "✓ " : ""}
            {label}
          </li>
        );
      })}
    </ol>
  );
}

/**
 * The deterministic post-write controls.
 *
 * A lever that declined to fire is shown, not hidden. On a benign LSASS alert
 * the interesting fact is that the ceiling looked at it and acted — and on a
 * real attack, that it looked and let it through.
 */
function Levers({ trace }: { trace: TraceState }) {
  if (trace.levers.length === 0) return null;
  return (
    <div className="px-4 pb-3">
      <div className="mb-1 text-[11px] uppercase tracking-wide text-dim">Graph levers</div>
      <div className="flex flex-wrap gap-1">
        {trace.levers.map((lever, i) => (
          <span
            key={`${lever.lever_id}-${i}`}
            className={`mono rounded border px-1.5 py-0.5 text-[11px] ${
              lever.fired
                ? "border-suspicious/50 bg-suspicious/15 text-suspicious"
                : "border-edge text-dim/70"
            }`}
            title={lever.fired ? (lever.effect ?? "") : "considered, did not fire"}
          >
            {lever.lever_id}
            {lever.fired && lever.effect ? ` · ${lever.effect}` : " · quiet"}
          </span>
        ))}
      </div>
    </div>
  );
}

export function TraceView({ trace }: { trace: TraceState }) {
  const llmMs = trace.llmCalls.reduce((sum, c) => sum + c.duration_ms, 0);
  const uniqueEvidence = new Set(trace.ledger.map((l) => l.evidence_id)).size;

  return (
    <Panel>
      <div className="flex items-center justify-between px-4 pt-3">
        <SectionTitle>Live trace</SectionTitle>
        <span className="text-[11px] text-dim">
          {trace.status === "streaming"
            ? "running…"
            : trace.status === "done"
              ? "finished"
              : trace.status === "error"
                ? "failed"
                : trace.status}
        </span>
      </div>

      <StepRail trace={trace} />

      <dl className="grid grid-cols-4 gap-2 px-4 pb-3 text-center">
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-dim">Tool calls</dt>
          <dd className="mono text-sm">{trace.toolCalls.length}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-dim">LLM calls</dt>
          <dd className="mono text-sm">{trace.llmCalls.length}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-dim">Evidence</dt>
          <dd className="mono text-sm">{uniqueEvidence}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wide text-dim">Model time</dt>
          <dd className="mono text-sm">{(llmMs / 1000).toFixed(1)}s</dd>
        </div>
      </dl>

      <Levers trace={trace} />

      {trace.verification ? (
        <div className="px-4 pb-3">
          <span
            className={`rounded border px-2 py-1 text-[11px] ${
              trace.verification.status === "degraded"
                ? "border-suspicious/50 bg-suspicious/15 text-suspicious"
                : "border-benign/40 bg-benign/10 text-benign"
            }`}
          >
            verification: {trace.verification.status}
            {trace.verification.stripped_claims > 0
              ? ` · ${trace.verification.stripped_claims} claim(s) stripped`
              : ""}
            {trace.verification.repairs_used > 0
              ? ` · ${trace.verification.repairs_used} repair(s)`
              : ""}
          </span>
        </div>
      ) : null}

      {trace.error ? (
        <div className="mx-4 mb-3 rounded border border-malicious/40 bg-malicious/10 p-2 text-xs text-malicious">
          {trace.error}
        </div>
      ) : null}

      {trace.toolCalls.length > 0 ? (
        <div className="max-h-64 overflow-y-auto border-t border-edge">
          <table className="w-full text-xs">
            <tbody>
              {trace.toolCalls.map((call) => (
                <tr
                  key={call.seq}
                  className={`border-b border-edge/30 last:border-0 ${
                    call.ok ? "" : "bg-suspicious/10"
                  }`}
                >
                  <td className="mono w-10 px-4 py-1 text-dim">#{call.call_seq}</td>
                  <td className="mono px-2 py-1">{call.tool}</td>
                  <td className="mono max-w-xs truncate px-2 py-1 text-dim" title={call.args_digest}>
                    {call.args_digest}
                  </td>
                  <td className="px-2 py-1 text-right text-dim">
                    {call.ok ? (
                      <span className="mono text-[11px]">{call.evidence_ids.length} ev</span>
                    ) : (
                      // A failed tool is data the agent handled, not a crash.
                      <span className="text-suspicious" title={call.error ?? ""}>
                        no result
                      </span>
                    )}
                  </td>
                  <td className="mono w-16 px-4 py-1 text-right text-dim">
                    {call.duration_ms.toFixed(0)}ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </Panel>
  );
}
