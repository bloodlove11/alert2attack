import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  EmptyState,
  ErrorBox,
  EvidenceChip,
  Panel,
  SectionTitle,
  SeverityBadge,
  Spinner,
  VerdictBadge,
} from "../components/ui";
import { api, type CaseFile, type InvestigationJob } from "../lib/api";
import { useInvestigationStream } from "../lib/useInvestigationStream";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { ReviewForm } from "./ReviewForm";
import { TraceView } from "./TraceView";

function AlertHeader({ scenarioId }: { scenarioId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["scenario", scenarioId],
    queryFn: () => api.scenario(scenarioId),
  });

  if (isPending) return <Spinner label="Loading alert" />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  return (
    <Panel className="p-4">
      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={data.severity} />
        <h1 className="text-lg font-semibold">{data.rule_title}</h1>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
        <div>
          <dt className="text-dim">Host</dt>
          <dd className="mono">{data.host}</dd>
        </div>
        <div>
          <dt className="text-dim">Fired</dt>
          <dd className="mono">{data.fired_at.replace("T", " ").slice(0, 19)}</dd>
        </div>
        <div>
          <dt className="text-dim">Window</dt>
          <dd className="mono">
            {data.window_start.slice(11, 19)} → {data.window_end.slice(11, 19)}
          </dd>
        </div>
        <div>
          <dt className="text-dim">Events in window</dt>
          <dd className="mono">{data.event_count}</dd>
        </div>
      </dl>
    </Panel>
  );
}

function CaseFileView({
  caseFile,
  job,
  onOpenEvidence,
}: {
  caseFile: CaseFile;
  job: InvestigationJob;
  onOpenEvidence: (id: string) => void;
}) {
  const verification = job.result?.verification;

  return (
    <div className="space-y-4">
      {verification && verification.status !== "passed" ? (
        <div className="rounded border border-suspicious/40 bg-suspicious/10 p-3 text-xs text-suspicious">
          Verification <strong>{verification.status}</strong> — {verification.stripped_claims}{" "}
          claim(s) stripped after {verification.repairs_used} repair turn(s). Unsupported claims
          were removed rather than shipped.
        </div>
      ) : null}

      <Panel className="p-4">
        <div className="flex items-center gap-3">
          <VerdictBadge verdict={caseFile.verdict} />
          <span className="text-xs text-dim">confidence: {caseFile.confidence}</span>
        </div>
        <p className="mt-3 text-sm leading-relaxed">{caseFile.summary}</p>
      </Panel>

      {caseFile.timeline.length > 0 ? (
        <Panel>
          <SectionTitle>Timeline</SectionTitle>
          <ol className="px-4 pb-3">
            {caseFile.timeline.map((entry, i) => (
              <li key={i} className="border-b border-edge/40 py-2 text-sm last:border-0">
                <div className="mono text-[11px] text-dim">{entry.ts}</div>
                <div className="mt-0.5">{entry.text}</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {entry.evidence.map((id) => (
                    <EvidenceChip key={id} evidenceId={id} onOpen={onOpenEvidence} />
                  ))}
                </div>
              </li>
            ))}
          </ol>
        </Panel>
      ) : null}

      {caseFile.techniques.length > 0 ? (
        <Panel>
          <SectionTitle>ATT&amp;CK techniques</SectionTitle>
          <ul className="px-4 pb-3">
            {caseFile.techniques.map((t) => (
              <li key={t.technique_id} className="border-b border-edge/40 py-2 text-sm last:border-0">
                <span className="mono text-accent">{t.technique_id}</span>
                {t.note ? <span className="ml-2 text-dim">{t.note}</span> : null}
                <div className="mt-1 flex flex-wrap gap-1">
                  {t.evidence.map((id) => (
                    <EvidenceChip key={id} evidenceId={id} onOpen={onOpenEvidence} />
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      {caseFile.next_actions.length > 0 ? (
        <Panel>
          <SectionTitle>Recommended actions</SectionTitle>
          <ul className="px-4 pb-3">
            {caseFile.next_actions.map((a, i) => (
              <li key={i} className="border-b border-edge/40 py-2 text-sm last:border-0">
                <span className="mono rounded border border-edge px-1.5 py-0.5 text-[11px]">
                  {a.action}
                </span>
                <div className="mt-1">{a.rationale.text}</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {a.rationale.evidence.map((id) => (
                    <EvidenceChip key={id} evidenceId={id} onOpen={onOpenEvidence} />
                  ))}
                </div>
              </li>
            ))}
          </ul>
          <p className="px-4 pb-3 text-[11px] text-dim">
            The agent recommends. A person still decides — nothing here is executed.
          </p>
        </Panel>
      ) : null}

      {caseFile.open_questions.length > 0 ? (
        <Panel>
          <SectionTitle>Open questions</SectionTitle>
          <ul className="list-inside list-disc px-4 pb-3 text-sm text-dim">
            {caseFile.open_questions.map((q) => (
              <li key={q}>{q}</li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </div>
  );
}

function TelemetryTable({ scenarioId }: { scenarioId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["events", scenarioId],
    queryFn: () => api.events(scenarioId, { limit: 100 }),
  });

  if (isPending) return <Spinner label="Loading telemetry" />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  return (
    <Panel>
      <SectionTitle>
        Telemetry window ({data.events.length}
        {data.next_cursor ? "+" : ""} events)
      </SectionTitle>
      <div className="max-h-[28rem] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-panel">
            <tr className="border-b border-edge text-left uppercase tracking-wide text-dim">
              <th className="px-4 py-1.5 font-medium">Id</th>
              <th className="px-4 py-1.5 font-medium">Time</th>
              <th className="px-4 py-1.5 font-medium">Kind</th>
              <th className="px-4 py-1.5 font-medium">PID</th>
              <th className="px-4 py-1.5 font-medium">Image / detail</th>
            </tr>
          </thead>
          <tbody>
            {data.events.map((e) => (
              <tr key={e.event_id} className="border-b border-edge/30 last:border-0">
                <td className="mono px-4 py-1 text-accent">{e.event_id}</td>
                <td className="mono px-4 py-1 text-dim">{e.ts.slice(11, 23)}</td>
                <td className="px-4 py-1 text-dim">{e.kind}</td>
                <td className="mono px-4 py-1 text-dim">{e.pid ?? "—"}</td>
                <td className="mono max-w-md truncate px-4 py-1" title={e.command_line ?? e.image ?? ""}>
                  {e.command_line ?? e.image ?? e.target_path ?? e.details ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.next_cursor ? (
        <p className="px-4 py-2 text-[11px] text-dim">
          More events available — paging is wired in the API; the “load more” control lands with
          the trace view.
        </p>
      ) : null}
    </Panel>
  );
}

export function CasePage() {
  const { scenarioId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const openEvidence = params.get("ev");

  // The job this page is streaming, if the user started one on this visit.
  const [liveJobId, setLiveJobId] = useState<string | null>(null);

  const { data: jobs } = useQuery({
    queryKey: ["investigations"],
    queryFn: () => api.investigations(50),
  });

  const trace = useInvestigationStream(liveJobId, () => {
    // `done` means "refetch over REST" — the stream never carries a case file.
    void queryClient.invalidateQueries({ queryKey: ["investigations"] });
  });

  const start = useMutation({
    mutationFn: () => api.startInvestigation(scenarioId, "replay"),
    onSuccess: (job) => setLiveJobId(job.id),
  });

  // Prefer the run happening now; otherwise the latest finished one.
  const finished = jobs?.find((j) => j.scenario_id === scenarioId && j.status === "succeeded");
  const liveJob = jobs?.find((j) => j.id === liveJobId);
  const job = liveJob?.status === "succeeded" ? liveJob : finished;

  function setEvidence(id: string | null) {
    const next = new URLSearchParams(params);
    if (id) next.set("ev", id);
    else next.delete("ev");
    setParams(next, { replace: true });
  }

  const running = trace.status === "connecting" || trace.status === "streaming";

  return (
    <div className="mx-auto max-w-6xl p-6">
      <Link to="/" className="text-xs text-accent hover:underline">
        ← Queue
      </Link>

      <div className="mt-3 space-y-4">
        <AlertHeader scenarioId={scenarioId} />

        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={running || start.isPending}
            onClick={() => start.mutate()}
            className="rounded border border-accent/40 bg-accent/15 px-3 py-1.5 text-sm text-accent hover:bg-accent/25 disabled:opacity-50"
          >
            {running ? "Investigating…" : "Investigate (replay)"}
          </button>
          <span className="text-[11px] text-dim">
            The replay responder needs no model. It is a canned agent, not an investigator —
            the graph, tools, ledger and verifier around it are real.
          </span>
        </div>

        {start.error ? <ErrorBox error={start.error} /> : null}

        {liveJobId ? <TraceView trace={trace} /> : null}

        {job?.result ? (
          <>
            <CaseFileView
              caseFile={job.result.case_file}
              job={job}
              onOpenEvidence={(id) => setEvidence(id)}
            />
            <ReviewForm jobId={job.id} scenarioId={scenarioId} />
          </>
        ) : running ? null : (
          <Panel>
            <EmptyState
              title="No investigation has been run for this case yet."
              hint="Press Investigate to watch one run end to end."
            />
          </Panel>
        )}

        <TelemetryTable scenarioId={scenarioId} />
      </div>

      {openEvidence && job ? (
        <EvidenceDrawer
          jobId={job.id}
          evidenceId={openEvidence}
          onClose={() => setEvidence(null)}
        />
      ) : null}
    </div>
  );
}
