"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { useSession } from "@/components/Nav";
import StatusBadge from "@/components/StatusBadge";
import { api, kzt, TIERS } from "@/lib/api";

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const { session } = useSession();
  const [r, setR] = useState<any>(null);
  const [err, setErr] = useState("");
  const [assessResult, setAssessResult] = useState<any>(null);

  const load = useCallback(() => {
    api(`/reports/${id}`).then(setR).catch((e) => setErr(e.message));
  }, [id]);
  useEffect(() => {
    if (session) load();
  }, [session, load]);

  async function act(fn: () => Promise<any>) {
    setErr("");
    try {
      const out = await fn();
      if (out?.id) setR(out);
      else load();
    } catch (e: any) {
      setErr(e.message);
    }
  }
  const move = (to: string, extra: Record<string, unknown> = {}) =>
    act(() => api(`/reports/${id}/transition`, { method: "POST", body: { to, ...extra } }));

  if (!r) return <p className="text-sm text-muted">{err || "Loading…"}</p>;
  const role = session?.role;

  return (
    <div className="grid gap-8 lg:grid-cols-[1.4fr_1fr]">
      <article className="space-y-5">
        <div>
          <Link href="/reports" className="text-sm text-muted hover:text-ink">← Reports</Link>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">{r.title}</h1>
            <StatusBadge status={r.status} />
          </div>
          <p className="mt-1 font-mono text-xs text-muted">{r.id} · {r.program.name} · {r.vulnType}</p>
        </div>
        <div className="card space-y-4 text-sm">
          <Block label="Affected target" mono>{r.target}</Block>
          <Block label="Description">{r.description}</Block>
          <Block label="Steps to reproduce">{r.steps}</Block>
          <Block label="Impact">{r.impact}</Block>
          {r.poc && <Block label="Proof of concept (access is logged)" mono>{r.poc}</Block>}
          <Block label="CVSS v3.1" mono>{r.cvssVector} → {r.cvssScore.toFixed(1)}</Block>
        </div>
        {r.assessment && <Assessment a={r.assessment} />}
        {r.remediation && (
          <div className="card text-sm">
            <span className="label">Remediation</span>
            <p>Responsible: {r.remediation.responsible} · deadline {String(r.remediation.deadline).slice(0, 10)}</p>
            {r.remediation.fix_note && <p className="mt-1 text-muted">Fix: {r.remediation.fix_note}</p>}
            {r.remediation.retest_result && <p className="mt-1">Retest: <b>{r.remediation.retest_result}</b></p>}
          </div>
        )}
      </article>

      <aside className="space-y-5">
        {err && <p className="rounded border border-signal p-3 text-sm text-signal">{err}</p>}
        {r.autoChecks && (
          <div className="card text-sm">
            <span className="label">Automatic checks</span>
            <p>Scope: {r.autoChecks.scopeMatch ? <span className="text-ok">matches program scope</span> : <span className="text-signal">not matched — verify manually</span>}</p>
            <p className="mt-2">Possible duplicates:</p>
            {r.autoChecks.possibleDuplicates.length === 0 && <p className="text-muted">none above threshold</p>}
            <ul className="mt-1 space-y-1">
              {r.autoChecks.possibleDuplicates.map((d: any) => (
                <li key={d.reportId} className="flex justify-between font-mono text-xs">
                  <Link className="text-brand underline" href={`/reports/${d.reportId}`}>{d.reportId}</Link>
                  <span>{d.score.toFixed(2)}{d.sameTarget ? " · same target" : ""}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <Actions r={r} role={role} move={move} act={act} id={id} onAssessed={setAssessResult} />
        {assessResult && (
          <div className="card text-sm">
            <span className="label">Model comparison</span>
            <p>Baseline (CVSS only): {assessResult.baseline.tier} · {kzt(assessResult.baseline.reward)}</p>
            <p>Multi-factor: {assessResult.multiFactor.tier} · score {assessResult.multiFactor.score} · {kzt(assessResult.multiFactor.reward)}</p>
          </div>
        )}

        <div className="card text-sm">
          <span className="label">History</span>
          <ol className="space-y-1.5">
            {r.transitions.map((t: any, i: number) => (
              <li key={i} className="flex justify-between gap-2">
                <span><span className="font-mono text-xs">{t.to_status}</span> <span className="text-xs text-muted">by {t.actor_role}</span></span>
                <span className="text-xs text-muted tabular-nums">{new Date(t.at).toLocaleString()}</span>
              </li>
            ))}
          </ol>
        </div>
      </aside>
    </div>
  );
}

function Block({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <span className="label">{label}</span>
      <p className={`whitespace-pre-wrap ${mono ? "font-mono text-xs" : ""}`}>{children}</p>
    </div>
  );
}

function Assessment({ a }: { a: any }) {
  return (
    <div className="card text-sm">
      <span className="label">Assessment</span>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1">
        <span className="text-muted">Real impact</span><span>{a.real_impact}</span>
        <span className="text-muted">Exploitability</span><span>{a.exploitability}</span>
        <span className="text-muted">Scale</span><span>{a.scale}</span>
        <span className="text-muted">Report quality</span><span>{Number(a.report_quality).toFixed(2)}</span>
        <span className="text-muted">Multi-factor score</span><span>{Number(a.multifactor_score).toFixed(2)}</span>
        <span className="text-muted">Baseline (CVSS only)</span><span>{a.baseline_tier} · {kzt(a.baseline_reward)}</span>
        <span className="text-muted">Model tier</span><span>{a.multifactor_tier}</span>
        <span className="text-muted">Final tier</span><span className="font-medium">{a.final_tier}{a.override_reason ? " (override)" : ""}</span>
        <span className="text-muted">Recommended reward</span><span className="font-medium">{kzt(a.recommended_reward)}</span>
        <span className="text-muted">Paid</span><span>{a.paid_at ? new Date(a.paid_at).toLocaleDateString() : "not yet"}</span>
      </div>
      {a.override_reason && <p className="mt-2 text-muted">Override reason: {a.override_reason}</p>}
    </div>
  );
}

function Actions({ r, role, move, act, id, onAssessed }: any) {
  const [reason, setReason] = useState("");
  const [dupOf, setDupOf] = useState(r.autoChecks?.possibleDuplicates?.[0]?.reportId ?? "");
  const [resp, setResp] = useState("");
  const [deadline, setDeadline] = useState("");
  const [fixNote, setFixNote] = useState("");
  const s = r.status;
  const box = (children: React.ReactNode) => <div className="card space-y-3 text-sm"><span className="label">Actions</span>{children}</div>;

  if (role === "OPERATOR") {
    if (s === "SUBMITTED") return box(<button className="btn" onClick={() => move("TRIAGE")}>Start triage</button>);
    if (s === "TRIAGE")
      return box(<>
        <button className="btn" onClick={() => move("VALIDATED")}>Validated: in scope & reproducible</button>
        <input className="field" placeholder="Reason for rejection" value={reason} onChange={(e) => setReason(e.target.value)} />
        <button className="btn-ghost" onClick={() => move("REJECTED", { comment: reason })}>Reject</button>
      </>);
    if (s === "VALIDATED")
      return box(<>
        <button className="btn" onClick={() => move("ACCEPTED")}>Accept (not a duplicate)</button>
        <input className="field font-mono" placeholder="CHR-…" value={dupOf} onChange={(e) => setDupOf(e.target.value)} />
        <button className="btn-ghost" onClick={() => move("DUPLICATE", { duplicateOf: dupOf })}>Mark as duplicate of this report</button>
      </>);
    if (s === "ACCEPTED") return <AssessForm r={r} act={act} id={id} onAssessed={onAssessed} />;
    if (s === "RETEST")
      return box(<>
        <button className="btn" onClick={() => move("CLOSED", { comment: "Retest passed" })}>Retest passed — close</button>
        <button className="btn-ghost" onClick={() => move("REMEDIATION", { comment: "Retest failed" })}>Retest failed — back to remediation</button>
      </>);
  }
  if (role === "ADMIN") {
    if (s === "SEVERITY_ASSIGNED") return box(<button className="btn" onClick={() => move("REWARD_APPROVED")}>Approve reward (second approver)</button>);
    if (s === "REWARD_APPROVED") return box(<button className="btn" onClick={() => move("PAID")}>Mark as paid from bounty fund</button>);
  }
  if (role === "AGENCY") {
    if (s === "PAID")
      return box(<>
        <input className="field" placeholder="Responsible person / team" value={resp} onChange={(e) => setResp(e.target.value)} />
        <input className="field" type="date" value={deadline} onChange={(e) => setDeadline(e.target.value)} />
        <button className="btn" onClick={() => act(() => api(`/reports/${id}/remediation`, { method: "POST", body: { responsible: resp, deadline } }))}>Start remediation</button>
      </>);
    if (s === "REMEDIATION")
      return box(<>
        <textarea className="field" placeholder="What was fixed" value={fixNote} onChange={(e) => setFixNote(e.target.value)} />
        <button className="btn" onClick={() => act(() => api(`/reports/${id}/remediation/fixed`, { method: "POST", body: { fixNote } }))}>Submit fix for retest</button>
      </>);
  }
  return null;
}

function AssessForm({ r, act, id, onAssessed }: any) {
  const [f, setF] = useState({ cvssVector: r.cvssVector, realImpact: "SIGNIFICANT", exploitability: "RELIABLE_POC", scale: "USER_SUBSET", finalTier: "", overrideReason: "" });
  const [q, setQ] = useState({ reproducible: true, clearSteps: true, workingPoc: !!r.poc, impactExplained: true, remediationAdvice: false });
  const sel = (k: keyof typeof f, opts: string[]) => (
    <select className="field" value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })}>
      {opts.map((o) => <option key={o} value={o}>{o || "(model decides)"}</option>)}
    </select>
  );
  return (
    <div className="card space-y-3 text-sm">
      <span className="label">Severity assessment</span>
      <input className="field font-mono text-xs" value={f.cvssVector} onChange={(e) => setF({ ...f, cvssVector: e.target.value })} />
      <label className="block text-xs text-muted">Real impact{sel("realImpact", ["NONE", "LIMITED", "SIGNIFICANT", "SEVERE"])}</label>
      <label className="block text-xs text-muted">Exploitability{sel("exploitability", ["THEORETICAL", "CONDITIONAL_POC", "RELIABLE_POC", "TRIVIAL_AUTOMATABLE"])}</label>
      <label className="block text-xs text-muted">Scale{sel("scale", ["SINGLE_USER", "USER_SUBSET", "ALL_USERS", "CROSS_SYSTEM"])}</label>
      <fieldset className="space-y-1">
        <span className="text-xs text-muted">Report quality</span>
        {(Object.keys(q) as (keyof typeof q)[]).map((k) => (
          <label key={k} className="flex items-center gap-2">
            <input type="checkbox" checked={q[k]} onChange={(e) => setQ({ ...q, [k]: e.target.checked })} /> {k}
          </label>
        ))}
      </fieldset>
      <label className="block text-xs text-muted">Final tier (override){sel("finalTier", ["", ...TIERS])}</label>
      {f.finalTier && <input className="field" placeholder="Justification for override" value={f.overrideReason} onChange={(e) => setF({ ...f, overrideReason: e.target.value })} />}
      <button
        className="btn"
        onClick={() =>
          act(async () => {
            const body: any = { cvssVector: f.cvssVector, realImpact: f.realImpact, exploitability: f.exploitability, scale: f.scale, quality: q };
            if (f.finalTier) { body.finalTier = f.finalTier; body.overrideReason = f.overrideReason; }
            const out = await api(`/reports/${id}/assess`, { method: "POST", body });
            onAssessed(out);
            return null;
          })
        }
      >
        Assign severity & compute reward
      </button>
    </div>
  );
}
