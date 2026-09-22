import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { EmptyState, ErrorBox, Panel, SeverityBadge, Spinner } from "../components/ui";
import { api, type QueueFilters, type Severity, type Split } from "../lib/api";

/**
 * The alert queue.
 *
 * Filters live in the URL rather than in component state, so a filtered queue
 * is a link someone can send. That also removes most of what a client store
 * would otherwise hold.
 */
export function QueuePage() {
  const [params, setParams] = useSearchParams();

  const filters: QueueFilters = {
    split: (params.get("split") as Split | null) ?? "",
    severity: (params.get("severity") as Severity | null) ?? "",
    q: params.get("q") ?? "",
  };

  const { data, isPending, error } = useQuery({
    queryKey: ["scenarios", filters],
    queryFn: () => api.scenarios(filters),
  });

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  return (
    <div className="mx-auto max-w-6xl p-6">
      <header className="mb-4">
        <div className="flex items-baseline justify-between">
          <h1 className="text-xl font-semibold">Alert queue</h1>
          <Link to="/search" className="text-xs text-accent hover:underline">
            Search ATT&amp;CK techniques
          </Link>
        </div>
        <p className="mt-1 text-sm text-dim">
          {data ? `${data.length} cases` : "…"} · boxed OTRF captures, one host and one window each
        </p>
      </header>

      <div className="mb-4 flex flex-wrap gap-2">
        <input
          value={filters.q}
          onChange={(e) => setFilter("q", e.target.value)}
          placeholder="Search host, rule or id"
          className="w-64 rounded border border-edge bg-panel px-3 py-1.5 text-sm placeholder:text-dim/60 focus:border-accent focus:outline-none"
        />
        <select
          value={filters.severity}
          onChange={(e) => setFilter("severity", e.target.value)}
          className="rounded border border-edge bg-panel px-3 py-1.5 text-sm"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filters.split}
          onChange={(e) => setFilter("split", e.target.value)}
          className="rounded border border-edge bg-panel px-3 py-1.5 text-sm"
        >
          <option value="">All splits</option>
          <option value="dev">Dev</option>
          <option value="test">Test (frozen)</option>
        </select>
      </div>

      {error ? <ErrorBox error={error} /> : null}
      {isPending ? <Spinner label="Loading queue" /> : null}

      {data ? (
        <Panel>
          {data.length === 0 ? (
            <EmptyState title="No cases match those filters." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-edge text-left text-xs uppercase tracking-wide text-dim">
                  <th className="px-4 py-2 font-medium">Severity</th>
                  <th className="px-4 py-2 font-medium">Rule</th>
                  <th className="px-4 py-2 font-medium">Host</th>
                  <th className="px-4 py-2 font-medium">Fired</th>
                  <th className="px-4 py-2 font-medium">Split</th>
                </tr>
              </thead>
              <tbody>
                {data.map((row) => (
                  <tr
                    key={row.scenario_id}
                    className="border-b border-edge/50 last:border-0 hover:bg-white/[0.03]"
                  >
                    <td className="px-4 py-2">
                      <SeverityBadge severity={row.severity} />
                    </td>
                    <td className="px-4 py-2">
                      <Link
                        to={`/cases/${row.scenario_id}`}
                        className="text-accent hover:underline"
                      >
                        {row.rule_title}
                      </Link>
                      <div className="mono text-[11px] text-dim">{row.scenario_id}</div>
                    </td>
                    <td className="mono px-4 py-2 text-xs text-dim">{row.host}</td>
                    <td className="px-4 py-2 text-xs text-dim">
                      {new Date(row.fired_at).toISOString().replace("T", " ").slice(0, 19)}
                    </td>
                    <td className="px-4 py-2 text-xs text-dim">{row.split}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      ) : null}
    </div>
  );
}
