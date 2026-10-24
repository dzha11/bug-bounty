"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, kzt, TIERS } from "@/lib/api";

export default function Home() {
  const [programs, setPrograms] = useState<any[] | null>(null);
  const [board, setBoard] = useState<any[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    api("/programs").then(setPrograms).catch((e) => setErr(e.message));
    api("/leaderboard").then(setBoard).catch(() => {});
  }, []);

  return (
    <div className="grid gap-8 lg:grid-cols-[1fr_280px]">
      <section>
        <h1 className="text-2xl font-semibold tracking-tight">Bug bounty programs</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">
          Scope, rules and the full reward range are published before you start testing. Testing inside scope
          after accepting Safe Harbor is authorised research.
        </p>
        {err && <p className="mt-4 text-sm text-signal">{err}</p>}
        {!programs && !err && <p className="mt-6 text-sm text-muted">Loading…</p>}
        <div className="mt-6 grid gap-4">
          {programs?.map((p) => (
            <Link key={p.id} href={`/programs/${p.id}`} className="card block transition hover:border-brand">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 className="text-lg font-medium">{p.name}</h2>
                <span className="font-mono text-xs text-muted">
                  {p.asset_type} · criticality {p.asset_criticality} · rules {p.rules_version}
                </span>
              </div>
              <p className="mt-1 text-sm text-muted">{p.organization}</p>
              <p className="mt-3 text-sm">
                <span className="text-muted">In scope: </span>
                <span className="font-mono text-xs">{p.in_scope.join(", ")}</span>
              </p>
              <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
                {TIERS.map((t) => (
                  <div key={t} className="rounded border border-line px-2 py-1.5">
                    <div className="text-[10px] font-medium uppercase tracking-wide text-muted">{t}</div>
                    <div className="text-xs tabular-nums">
                      {kzt(p.reward_matrix[t].min)}
                      <br />– {kzt(p.reward_matrix[t].max)}
                    </div>
                  </div>
                ))}
              </div>
            </Link>
          ))}
        </div>
      </section>
      <aside>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">Leaderboard</h2>
        <ol className="card mt-3 space-y-2 text-sm">
          {board.length === 0 && <li className="text-muted">No paid findings yet.</li>}
          {board.map((r, i) => (
            <li key={r.researcher_id} className="flex justify-between gap-2">
              <span>
                {i + 1}. <span className="font-mono">{r.researcher_id}</span>{" "}
                <span className="text-xs text-muted">{r.level}</span>
              </span>
              <span className="tabular-nums">{r.points}</span>
            </li>
          ))}
        </ol>
        <p className="mt-2 text-xs text-muted">Researchers appear only by pseudonymous ID.</p>
      </aside>
    </div>
  );
}
