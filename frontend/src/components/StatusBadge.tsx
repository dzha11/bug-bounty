const tone: Record<string, string> = {
  SUBMITTED: "border-line text-muted",
  TRIAGE: "border-brand text-brand",
  VALIDATED: "border-brand text-brand",
  ACCEPTED: "border-brand text-brand",
  SEVERITY_ASSIGNED: "border-brand text-brand",
  REWARD_APPROVED: "border-ok text-ok",
  PAID: "border-ok text-ok",
  REMEDIATION: "border-signal text-signal",
  RETEST: "border-signal text-signal",
  CLOSED: "border-ok text-ok",
  REJECTED: "border-line text-muted line-through",
  DUPLICATE: "border-line text-muted",
};

export default function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 font-mono text-[11px] ${tone[status] ?? "border-line"}`}>
      {status.replace("_", " ")}
    </span>
  );
}
