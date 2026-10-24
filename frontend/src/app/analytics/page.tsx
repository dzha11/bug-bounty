"use client";

import { useEffect, useState } from "react";
import { useSession } from "@/components/Nav";
import { api, kzt, TIERS } from "@/lib/api";

export default function Analytics() {
  const { session } = useSession();
  const [s, setS] = useState<any>(null);
  const [audit, setAudit] = useState<any>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!session) return;
    api("/analytics/summary").then(setS).catch((e) => setErr(e.message));
    if (session.role !== "AGENCY") api("/audit/verify").then(setAudit).catch(() => {});
  }, [session]);

  if (err) return <p className="text-sm text-signal">{err}</p>;
  if (!s) return <p className="text-sm text-muted">Loading…</p>;
  const stat = (label: string, value: React.ReactNode) => (
    <div className="card">
      <div className="label">{label}</div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
    </div>
  );

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">Analytics</h1>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {stat("Reports", s.total)}
        {stat("Valid", s.valid)}
        {stat("Duplicates", s.duplicates)}
        {stat("Rejected", s.rejected)}
        {stat("Avg triage", s.avgTriageHours == null ? "—" : `${s.avgTriageHours.toFixed(2)} h`)}
        {stat("MTTR", s.mttrDays == null ? "—" : `${s.mttrDays.toFixed(2)} d`)}
        {stat("Paid out", kzt(s.totalPaidKzt))}
        {audit && stat("Audit chain", audit.valid ? <span className="text-ok">intact · {audit.entries}</span> : <span className="text-signal">broken at #{audit.brokenAt}</span>)}
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="card text-sm">
          <span className="label">By status</span>
          {Object.entries(s.byStatus).map(([k, v]) => (
            <div key={k} className="flex justify-between border-t border-line py-1.5 first:border-0"><span className="font-mono text-xs">{k}</span><span>{v as number}</span></div>
          ))}
        </div>
        <div className="card text-sm">
          <span className="label">By final tier</span>
          {TIERS.map((t) => (
            <div key={t} className="flex justify-between border-t border-line py-1.5 first:border-0"><span>{t}</span><span>{s.byTier[t] ?? 0}</span></div>
          ))}
        </div>
      </div>
    </div>
  );
}
