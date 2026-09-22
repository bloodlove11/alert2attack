import { useQuery } from "@tanstack/react-query";
import { ApiError, api } from "../lib/api";
import { ErrorBox, Spinner } from "../components/ui";

function Field({ label, value }: { label: string; value: unknown }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="grid grid-cols-[9rem_1fr] gap-2 border-b border-edge/40 py-1.5 last:border-0">
      <dt className="text-xs uppercase tracking-wide text-dim">{label}</dt>
      <dd className="mono break-all text-xs">{String(value)}</dd>
    </div>
  );
}

/**
 * Resolves one citation back to the record the agent fetched.
 *
 * A 404 here is not a UI failure: the verifier is supposed to have stripped any
 * claim citing evidence outside the run's ledger, so an unresolvable citation
 * means something upstream is wrong. It is rendered loudly for that reason.
 */
export function EvidenceDrawer({
  jobId,
  evidenceId,
  onClose,
}: {
  jobId: string;
  evidenceId: string;
  onClose: () => void;
}) {
  const { data, isPending, error } = useQuery({
    queryKey: ["evidence", jobId, evidenceId],
    queryFn: () => api.evidence(jobId, evidenceId),
    retry: false,
  });

  const unverifiable = error instanceof ApiError && error.status === 404;

  return (
    <aside className="fixed inset-y-0 right-0 z-20 w-[32rem] max-w-full overflow-y-auto border-l border-edge bg-panel shadow-2xl">
      <header className="sticky top-0 flex items-center justify-between border-b border-edge bg-panel px-4 py-3">
        <div>
          <div className="mono text-sm text-accent">{evidenceId}</div>
          {data ? (
            <div className="text-[11px] text-dim">
              {data.kind.replace(/_/g, " ")}
              {data.first_seen_tool_seq !== null
                ? ` · first seen at tool call #${data.first_seen_tool_seq}`
                : null}
            </div>
          ) : null}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded border border-edge px-2 py-1 text-xs text-dim hover:text-white"
        >
          Close
        </button>
      </header>

      <div className="p-4">
        {isPending ? <Spinner label="Resolving citation" /> : null}

        {unverifiable ? (
          <div className="rounded border border-malicious/40 bg-malicious/10 p-4 text-sm">
            <p className="font-semibold text-malicious">Unverifiable citation</p>
            <p className="mt-1 text-xs text-malicious/80">
              This run never fetched <span className="mono">{evidenceId}</span>. The verifier
              should have stripped the claim that cites it — this is a bug indicator, not a
              display problem.
            </p>
          </div>
        ) : error ? (
          <ErrorBox error={error} />
        ) : null}

        {data?.event ? (
          <dl>
            <Field label="Event id" value={data.event.event_id} />
            <Field label="Kind" value={data.event.kind} />
            <Field label="Timestamp" value={data.event.ts} />
            <Field label="Host" value={data.event.host} />
            <Field label="User" value={data.event.user} />
            <Field label="PID" value={data.event.pid} />
            <Field label="Parent PID" value={data.event.ppid} />
            <Field label="Image" value={data.event.image} />
            <Field label="Command line" value={data.event.command_line} />
            <Field label="Parent image" value={data.event.parent_image} />
            <Field label="Target image" value={data.event.target_image} />
            <Field label="Target path" value={data.event.target_path} />
            <Field label="Destination" value={data.event.dest_ip ?? data.event.dest_host} />
            <Field label="Port" value={data.event.dest_port} />
            <Field label="Query" value={data.event.query} />
            <Field label="Details" value={data.event.details} />
          </dl>
        ) : null}

        {data?.rule ? (
          <div className="space-y-3">
            <h3 className="font-semibold">{data.rule.title}</h3>
            <p className="text-sm text-dim">{data.rule.description}</p>
            <dl>
              <Field label="Slug" value={data.rule.slug} />
              <Field label="Level" value={data.rule.level} />
              <Field label="Tags" value={data.rule.tags.join(", ")} />
            </dl>
            {data.rule.falsepositives.length > 0 ? (
              <div>
                <h4 className="text-xs uppercase tracking-wide text-dim">Known false positives</h4>
                <ul className="mt-1 list-inside list-disc text-xs text-dim">
                  {data.rule.falsepositives.map((fp) => (
                    <li key={fp}>{fp}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : null}

        {data?.technique ? (
          <div className="space-y-3">
            <h3 className="font-semibold">
              <span className="mono text-accent">{data.technique.technique_id}</span>{" "}
              {data.technique.name}
            </h3>
            <Field label="Tactics" value={data.technique.tactics.join(", ")} />
            <p className="text-sm leading-relaxed text-dim">{data.technique.description}</p>
          </div>
        ) : null}
      </div>
    </aside>
  );
}
