"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { useSession } from "@/components/Nav";
import { api, kzt, TIERS } from "@/lib/api";

const METRICS: [string, string, [string, string][]][] = [
  ["AV", "Attack vector", [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]]],
  ["AC", "Attack complexity", [["L", "Low"], ["H", "High"]]],
  ["PR", "Privileges required", [["N", "None"], ["L", "Low"], ["H", "High"]]],
  ["UI", "User interaction", [["N", "None"], ["R", "Required"]]],
  ["S", "Scope", [["U", "Unchanged"], ["C", "Changed"]]],
  ["C", "Confidentiality", [["H", "High"], ["L", "Low"], ["N", "None"]]],
  ["I", "Integrity", [["H", "High"], ["L", "Low"], ["N", "None"]]],
  ["A", "Availability", [["H", "High"], ["L", "Low"], ["N", "None"]]],
];
const VULN_TYPES = [
  "SQL_INJECTION", "XSS", "IDOR", "BROKEN_AUTHENTICATION", "SSRF", "RCE", "CSRF",
  "INFORMATION_DISCLOSURE", "MISCONFIGURATION", "BUSINESS_LOGIC", "OTHER",
];

export default function ProgramPage() {
  const { id } = useParams<{ id: string }>();
  const { session } = useSession();
  const [p, setP] = useState<any>(null);
  const [accepted, setAccepted] = useState(false);
  const [cvss, setCvss] = useState<Record<string, string>>({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" });
  const [form, setForm] = useState({ vulnType: "IDOR", title: "", target: "", description: "", steps: "", impact: "", poc: "" });
  const [result, setResult] = useState<any>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api(`/programs/${id}`).then(setP).catch((e) => setErr(e.message));
  }, [id]);

  const vector = useMemo(() => "CVSS:3.1/" + METRICS.map(([k]) => `${k}:${cvss[k]}`).join("/"), [cvss]);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm({ ...form, [k]: e.target.value });

  async function acceptSafeHarbor() {
    setErr("");
    try {
      await api(`/programs/${id}/safe-harbor`, { method: "POST" });
      setAccepted(true);
    } catch (e: any) {
      setErr(e.message);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const body = { ...form, programId: Number(id), cvssVector: vector, poc: form.poc || undefined };
      setResult(await api("/reports", { method: "POST", body }));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (!p) return <p className="text-sm text-muted">{err || "Loading…"}</p>;
  const isResearcher = session?.role === "RESEARCHER";

  return (
    <div className="grid gap-8 lg:grid-cols-[1fr_1.2fr]">
      <section className="space-y-5">
        <div>
          <Link href="/" className="text-sm text-muted hover:text-ink">← Programs</Link>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">{p.name}</h1>
          <p className="text-sm text-muted">{p.organization} · rules {p.rules_version} · until {String(p.ends_at).slice(0, 10)}</p>
        </div>
        <div className="card space-y-3 text-sm">
          <Row label="In scope" items={p.in_scope} mono />
          <Row label="Out of scope" items={p.out_of_scope.length ? p.out_of_scope : ["—"]} mono />
          <Row label="Allowed methods" items={p.allowed_methods} />
          <Row label="Forbidden" items={p.forbidden_methods} />
        </div>
        <div className="card">
          <span className="label">Published reward matrix</span>
          <table className="mt-2 w-full text-sm">
            <tbody>
              {TIERS.map((t) => (
                <tr key={t} className="border-t border-line first:border-0">
                  <td className="py-1.5 text-muted">{t}</td>
                  <td className="py-1.5 text-right tabular-nums">{kzt(p.reward_matrix[t].min)} – {kzt(p.reward_matrix[t].max)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold">Submit a vulnerability</h2>
        {!session && <p className="mt-2 text-sm text-muted"><Link className="text-brand underline" href="/login">Sign in</Link> as a researcher to submit.</p>}
        {session && !isResearcher && <p className="mt-2 text-sm text-muted">Only researchers submit reports.</p>}
        {isResearcher && !accepted && (
          <div className="card mt-3 space-y-3 text-sm">
            <p>
              Before testing, accept the <b>Safe Harbor</b> terms for rules version <span className="font-mono">{p.rules_version}</span>.
              Actions inside scope and these rules are treated as authorised research. The platform records the rules version,
              the time of acceptance and your researcher ID.
            </p>
            <button className="btn" onClick={acceptSafeHarbor}>Accept Safe Harbor {p.rules_version}</button>
          </div>
        )}
        {isResearcher && accepted && !result && (
          <form onSubmit={submit} className="card mt-3 space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label">Type</label>
                <select className="field" value={form.vulnType} onChange={set("vulnType")}>
                  {VULN_TYPES.map((v) => <option key={v}>{v}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Affected URL / endpoint</label>
                <input className="field" value={form.target} onChange={set("target")} required placeholder="https://portal.agency-a.test/…" />
              </div>
            </div>
            <Field label="Title" value={form.title} onChange={set("title")} />
            <Field label="Description" value={form.description} onChange={set("description")} area />
            <Field label="Steps to reproduce" value={form.steps} onChange={set("steps")} area />
            <Field label="Impact" value={form.impact} onChange={set("impact")} area />
            <Field label="Proof of concept (optional, encrypted)" value={form.poc} onChange={set("poc")} area required={false} />
            <div>
              <span className="label">CVSS v3.1 base metrics</span>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {METRICS.map(([k, name, opts]) => (
                  <label key={k} className="text-xs text-muted">
                    {name}
                    <select className="field mt-1" value={cvss[k]} onChange={(e) => setCvss({ ...cvss, [k]: e.target.value })}>
                      {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                  </label>
                ))}
              </div>
              <p className="mt-2 font-mono text-xs text-muted">{vector}</p>
            </div>
            {err && <p className="text-sm text-signal">{err}</p>}
            <button className="btn" disabled={busy}>{busy ? "Encrypting & submitting…" : "Submit report"}</button>
          </form>
        )}
        {result && (
          <div className="card mt-3 space-y-2 text-sm">
            <p className="text-ok font-medium">Report {result.publicId} submitted.</p>
            <p>CVSS base score (computed by the server): <b>{result.cvssScore}</b></p>
            <p>Automatic scope check: {result.scopeMatch ? "target is in scope" : <span className="text-signal">target may be out of scope — the operator will verify</span>}</p>
            <Link href={`/reports/${result.publicId}`} className="btn-ghost mt-2">Open report</Link>
          </div>
        )}
        {err && !accepted && <p className="mt-2 text-sm text-signal">{err}</p>}
      </section>
    </div>
  );
}

function Row({ label, items, mono }: { label: string; items: string[]; mono?: boolean }) {
  return (
    <div>
      <span className="label">{label}</span>
      <ul className={`list-disc pl-5 ${mono ? "font-mono text-xs" : ""}`}>
        {items.map((i) => <li key={i}>{i}</li>)}
      </ul>
    </div>
  );
}

function Field({ label, value, onChange, area, required = true }: {
  label: string; value: string; area?: boolean; required?: boolean;
  onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => void;
}) {
  return (
    <div>
      <label className="label">{label}</label>
      {area ? (
        <textarea className="field min-h-20" value={value} onChange={onChange} required={required} />
      ) : (
        <input className="field" value={value} onChange={onChange} required={required} />
      )}
    </div>
  );
}
