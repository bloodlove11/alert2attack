import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Panel, SectionTitle } from "../components/ui";
import { api, type Verdict } from "../lib/api";

const VERDICTS: Verdict[] = ["malicious", "suspicious", "likely_benign", "not_enough_evidence"];

/**
 * Records whether an analyst agrees with a case file.
 *
 * It never edits the case file. A review is an observation about what the
 * agent said on that run, and the run's record stays as it was — the API
 * enforces this, and the UI should not suggest otherwise.
 */
export function ReviewForm({ jobId, scenarioId }: { jobId: string; scenarioId: string }) {
  const queryClient = useQueryClient();
  const [agrees, setAgrees] = useState<boolean | null>(null);
  const [verdict, setVerdict] = useState<Verdict>("likely_benign");
  const [note, setNote] = useState("");

  const { data: existing } = useQuery({
    queryKey: ["reviews", scenarioId],
    queryFn: () => api.reviews(scenarioId),
  });

  const submit = useMutation({
    mutationFn: () =>
      api.addReview(jobId, {
        agrees: agrees === true,
        corrected_verdict: agrees === false ? verdict : null,
        note,
      }),
    onSuccess: () => {
      setAgrees(null);
      setNote("");
      void queryClient.invalidateQueries({ queryKey: ["reviews", scenarioId] });
    },
  });

  return (
    <Panel>
      <SectionTitle>Analyst review</SectionTitle>

      <div className="px-4 pb-3">
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setAgrees(true)}
            className={`rounded border px-3 py-1.5 text-sm ${
              agrees === true
                ? "border-benign/50 bg-benign/20 text-benign"
                : "border-edge text-dim hover:text-white"
            }`}
          >
            Agree
          </button>
          <button
            type="button"
            onClick={() => setAgrees(false)}
            className={`rounded border px-3 py-1.5 text-sm ${
              agrees === false
                ? "border-malicious/50 bg-malicious/20 text-malicious"
                : "border-edge text-dim hover:text-white"
            }`}
          >
            Disagree
          </button>
        </div>

        {agrees === false ? (
          <label className="mt-3 block text-xs text-dim">
            It should have been
            <select
              value={verdict}
              onChange={(e) => setVerdict(e.target.value as Verdict)}
              className="mt-1 block w-full rounded border border-edge bg-panel px-2 py-1.5 text-sm text-white"
            >
              {VERDICTS.map((v) => (
                <option key={v} value={v}>
                  {v.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        {agrees !== null ? (
          <>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Why? (optional, but it is what makes this useful later)"
              rows={2}
              className="mt-3 w-full rounded border border-edge bg-panel px-2 py-1.5 text-sm placeholder:text-dim/60"
            />
            <button
              type="button"
              disabled={submit.isPending}
              onClick={() => submit.mutate()}
              className="mt-2 rounded border border-accent/40 bg-accent/15 px-3 py-1.5 text-sm text-accent hover:bg-accent/25 disabled:opacity-50"
            >
              {submit.isPending ? "Saving…" : "Save review"}
            </button>
          </>
        ) : null}

        {submit.error ? (
          <div className="mt-2">
            <ErrorBox error={submit.error} />
          </div>
        ) : null}

        <p className="mt-3 text-[11px] text-dim">
          Reviews are append-only and never change the case file. Disagreements that name a
          verdict are exported as candidate eval cases for a human to curate — they are not
          written into the dataset.
        </p>
      </div>

      {existing && existing.length > 0 ? (
        <div className="border-t border-edge">
          <ul className="px-4 py-2">
            {existing.map((review) => (
              <li key={review.id} className="border-b border-edge/30 py-1.5 text-xs last:border-0">
                <span className={review.agrees ? "text-benign" : "text-malicious"}>
                  {review.agrees ? "agreed" : `disagreed → ${review.corrected_verdict}`}
                </span>
                <span className="text-dim"> · {review.reviewer} · </span>
                <span className="mono text-dim">{review.created_at.slice(0, 19)}</span>
                {review.note ? <div className="text-dim">{review.note}</div> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Panel>
  );
}
