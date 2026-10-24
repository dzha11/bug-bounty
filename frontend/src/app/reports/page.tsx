"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useSession } from "@/components/Nav";
import StatusBadge from "@/components/StatusBadge";
import { api, kzt } from "@/lib/api";

export default function Reports() {
  const { session, ready } = useSession();
  const [rows, setRows] = useState<any[] | null>(null);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState("ALL");

  useEffect(() => {
    if (session) api("/reports").then(setRows).catch((e) => setErr(e.message));
  }, [session]);

  if (ready && !session) return <p className="text-sm text-muted"><Link className="text-brand underline" href="/login">Sign in</Link> to see reports.</p>;
  const staff = session?.role === "OPERATOR" || session?.role === "ADMIN";
  const statuses = ["ALL", ...Array.from(new Set((rows ?? []).map((r) => r.status)))];
  const shown = (rows ?? []).filter((r) => filter === "ALL" || r.status === filter);

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {session?.role === "RESEARCHER" ? "My reports" : session?.role === "AGENCY" ? "Reports on our assets" : "Triage queue"}
          </h1>
          <p className="text-sm text-muted">{rows ? `${rows.length} report(s)` : "Loading…"}</p>
        </div>
        <select className="field w-auto" value={filter} onChange={(e) => setFilter(e.target.value)}>
          {statuses.map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      {err && <p className="mt-4 text-sm text-signal">{err}</p>}
      <div className="card mt-5 overflow-x-auto p-0">
        <table className="w-full min-w-[640px] text-sm">
          <thead className="text-left text-xs uppercase tracking-wide text-muted">
            <tr className="border-b border-line">
              <th className="px-4 py-2.5">Report</th>
              <th className="px-4 py-2.5">Title</th>
              <th className="px-4 py-2.5">CVSS</th>
              {staff && <th className="px-4 py-2.5">Checks</th>}
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5 text-right">Reward</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id} className="border-b border-line last:border-0 hover:bg-paper">
                <td className="px-4 py-2.5 font-mono text-xs"><Link className="text-brand underline" href={`/reports/${r.id}`}>{r.id}</Link></td>
                <td className="px-4 py-2.5">{r.title}<div className="text-xs text-muted">{r.program} · {r.vulnType}</div></td>
                <td className="px-4 py-2.5 tabular-nums">{r.cvssScore.toFixed(1)}</td>
                {staff && (
                  <td className="px-4 py-2.5 text-xs">
                    {r.scopeMatch === false && <div className="text-signal">scope?</div>}
                    {r.possibleDuplicates > 0 ? <div className="text-signal">{r.possibleDuplicates} similar</div> : <div className="text-muted">no similar</div>}
                  </td>
                )}
                <td className="px-4 py-2.5"><StatusBadge status={r.status} /></td>
                <td className="px-4 py-2.5 text-right tabular-nums">{r.tier ? <>{kzt(r.reward)}<div className="text-xs text-muted">{r.tier}</div></> : "—"}</td>
              </tr>
            ))}
            {rows && shown.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-muted">Nothing here yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
