"use client";

export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3001";

export type Role = "RESEARCHER" | "OPERATOR" | "AGENCY" | "ADMIN";
export interface Session {
  token: string;
  role: Role;
  fullName: string;
}

// sessionStorage (not localStorage): the token disappears when the tab closes.
// Known limitation: an httpOnly cookie would also protect it from XSS.
const KEY = "cyberhunt.session";

export function getSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}
export function setSession(s: Session | null) {
  try {
    if (s) sessionStorage.setItem(KEY, JSON.stringify(s));
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable */
  }
  window.dispatchEvent(new Event("cyberhunt-session"));
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T = any>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const s = getSession();
  const res = await fetch(`${API}${path}`, {
    method: init.method ?? "GET",
    headers: {
      "Content-Type": "application/json",
      ...(s ? { Authorization: `Bearer ${s.token}` } : {}),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    if (res.status === 401 && s) setSession(null);
    const msg = data?.message ?? res.statusText;
    const issues = data?.message?.issues ?? data?.issues;
    throw new ApiError(
      res.status,
      issues ? `${typeof msg === "string" ? msg : "Validation failed"}: ${issues.map((i: any) => `${i.path} ${i.message}`).join("; ")}` : String(typeof msg === "string" ? msg : msg?.message ?? msg),
    );
  }
  return data as T;
}

export const kzt = (n: number | null | undefined) =>
  n == null ? "—" : new Intl.NumberFormat("en-US").format(n) + " ₸";

export const TIERS = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "EXCEPTIONAL"] as const;
