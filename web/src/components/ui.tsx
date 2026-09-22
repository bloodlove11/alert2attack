import type { ReactNode } from "react";
import type { Severity, Verdict } from "../lib/api";

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-edge bg-panel ${className}`}>{children}</div>
  );
}

export function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <h2 className="px-4 py-2 text-xs font-semibold uppercase tracking-wider text-dim">
      {children}
    </h2>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-malicious/20 text-malicious border-malicious/40",
  high: "bg-malicious/15 text-malicious border-malicious/30",
  medium: "bg-suspicious/15 text-suspicious border-suspicious/30",
  low: "bg-unknown/15 text-unknown border-unknown/30",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${SEVERITY_STYLE[severity]}`}
    >
      {severity}
    </span>
  );
}

const VERDICT_STYLE: Record<Verdict, string> = {
  malicious: "bg-malicious/20 text-malicious border-malicious/40",
  suspicious: "bg-suspicious/20 text-suspicious border-suspicious/40",
  likely_benign: "bg-benign/20 text-benign border-benign/40",
  not_enough_evidence: "bg-unknown/20 text-unknown border-unknown/40",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-1 text-sm font-semibold ${VERDICT_STYLE[verdict]}`}
    >
      {verdict.replace(/_/g, " ")}
    </span>
  );
}

/**
 * A citation. Clicking it is the point of the whole console: every claim the
 * agent makes points at something a human can open and check.
 */
export function EvidenceChip({
  evidenceId,
  onOpen,
}: {
  evidenceId: string;
  onOpen: (id: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onOpen(evidenceId)}
      className="mono rounded border border-accent/30 bg-accent/10 px-1.5 py-0.5 text-[11px] text-accent hover:bg-accent/20"
    >
      {evidenceId}
    </button>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <div className="p-4 text-sm text-dim">{label}…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="rounded border border-malicious/40 bg-malicious/10 p-4 text-sm text-malicious">
      {message}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="p-8 text-center">
      <p className="text-sm text-dim">{title}</p>
      {hint ? <p className="mt-1 text-xs text-dim/70">{hint}</p> : null}
    </div>
  );
}
