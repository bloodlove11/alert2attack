import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { EmptyState, ErrorBox, Panel, Spinner } from "../components/ui";
import { api, type SearchHit, type SearchMode } from "../lib/api";

const MODE_HELP: Record<SearchMode, string> = {
  lexical: "shared words (BM25)",
  dense: "meaning (embeddings in Qdrant)",
  hybrid: "both, fused by rank",
};

/** Which channels ranked a hit, and where. Shows whether it came from meaning,
 * from shared words, or from both. */
function ChannelBadges({ hit }: { hit: SearchHit }) {
  const ranks = hit.channel_ranks ?? {};
  return (
    <span className="flex gap-1">
      {Object.entries(ranks).map(([channel, rank]) => (
        <span
          key={channel}
          className="mono rounded border border-edge px-1.5 py-0.5 text-[10px] text-dim"
        >
          {channel} #{rank}
        </span>
      ))}
    </span>
  );
}

/**
 * Search over ATT&CK techniques.
 *
 * The query and mode live in the URL, so a search is a link. It submits on Enter
 * rather than on every keystroke: with a dense channel each search embeds the
 * query, and there is no reason to do that per character.
 */
export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const mode = (params.get("mode") as SearchMode | null) ?? undefined;
  const [draft, setDraft] = useState(q);

  const { data, isFetching, error } = useQuery({
    queryKey: ["search", q, mode],
    queryFn: () => api.searchTechniques(q, mode),
    enabled: q.trim().length >= 2,
  });

  function submit(next: { q?: string; mode?: SearchMode | "" }) {
    const merged = new URLSearchParams(params);
    const nq = next.q ?? q;
    if (nq) merged.set("q", nq);
    else merged.delete("q");
    const nm = next.mode === undefined ? mode : next.mode;
    if (nm) merged.set("mode", nm);
    else merged.delete("mode");
    setParams(merged, { replace: true });
  }

  const vendored = data?.corpus_source === "vendored";

  return (
    <div className="mx-auto max-w-4xl p-6">
      <Link to="/" className="text-xs text-accent hover:underline">
        ← Queue
      </Link>
      <h1 className="mt-3 text-xl font-semibold">Search ATT&amp;CK techniques</h1>
      <p className="mt-1 text-sm text-dim">
        Describe a behavior in plain words. Hits are candidates, not evidence: an agent still has
        to look a technique up before it can cite it.
      </p>

      <form
        className="mt-4 flex flex-wrap gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          submit({ q: draft });
        }}
      >
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="e.g. a script host runs code downloaded from a URL"
          className="min-w-[18rem] flex-1 rounded border border-edge bg-panel px-3 py-1.5 text-sm placeholder:text-dim/60 focus:border-accent focus:outline-none"
        />
        <select
          value={mode ?? ""}
          onChange={(e) => submit({ mode: e.target.value as SearchMode | "" })}
          className="rounded border border-edge bg-panel px-3 py-1.5 text-sm"
        >
          <option value="">Default</option>
          {(data?.available_modes ?? ["lexical"]).map((m) => (
            <option key={m} value={m}>
              {m}: {MODE_HELP[m]}
            </option>
          ))}
        </select>
        <button
          type="submit"
          className="rounded border border-accent/40 bg-accent/15 px-3 py-1.5 text-sm text-accent hover:bg-accent/25"
        >
          Search
        </button>
      </form>

      {vendored ? (
        <div className="mt-3 rounded border border-suspicious/40 bg-suspicious/10 p-3 text-xs text-suspicious">
          Searching the {data?.n_techniques} techniques vendored with the agent, not the full
          ATT&amp;CK catalog. Put the catalog at <span className="mono">datasets/raw/attack_catalog.json</span>{" "}
          for real results.
        </div>
      ) : null}

      <div className="mt-4">
        {error ? <ErrorBox error={error} /> : null}
        {isFetching ? <Spinner label="Searching" /> : null}

        {data && !isFetching ? (
          <Panel>
            <div className="border-b border-edge px-4 py-2 text-[11px] text-dim">
              {data.hits.length} results · {data.mode}
              {data.embedder ? ` · ${data.embedder}` : ""} · {data.n_techniques} techniques
              {data.catalog_revision ? ` · ${data.catalog_revision}` : ""}
            </div>
            {data.hits.length === 0 ? (
              <EmptyState
                title="Nothing matched."
                hint="Lexical search needs shared words. A dense channel matches on meaning when one is configured."
              />
            ) : (
              <ol>
                {data.hits.map((hit) => (
                  <li
                    key={hit.doc_id}
                    className="flex items-baseline gap-3 border-b border-edge/40 px-4 py-2 last:border-0"
                  >
                    <span className="mono w-6 text-right text-xs text-dim">{hit.rank}</span>
                    <span className="mono w-24 text-sm text-accent">
                      {hit.doc_id.replace("attack-", "")}
                    </span>
                    <span className="flex-1 text-sm">{hit.title}</span>
                    <ChannelBadges hit={hit} />
                  </li>
                ))}
              </ol>
            )}
          </Panel>
        ) : null}

        {!q && !data ? (
          <Panel>
            <EmptyState title="Type a behavior and press Enter." />
          </Panel>
        ) : null}
      </div>
    </div>
  );
}
