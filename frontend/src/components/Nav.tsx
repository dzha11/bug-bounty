"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getSession, Session, setSession } from "@/lib/api";

export function useSession() {
  const [s, setS] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const sync = () => setS(getSession());
    sync();
    setReady(true);
    window.addEventListener("cyberhunt-session", sync);
    return () => window.removeEventListener("cyberhunt-session", sync);
  }, []);
  return { session: s, ready };
}

export default function Nav() {
  const { session } = useSession();
  const router = useRouter();
  const links: [string, string][] = [["/", "Programs"]];
  if (session) links.push(["/reports", session.role === "RESEARCHER" ? "My reports" : "Reports"]);
  if (session && session.role !== "RESEARCHER") links.push(["/analytics", "Analytics"]);

  return (
    <header className="border-b border-line bg-surface">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="inline-block h-5 w-5 rounded-sm bg-brand" aria-hidden />
          CyberHunt KZ
        </Link>
        <nav className="flex gap-4 text-sm text-muted">
          {links.map(([href, label]) => (
            <Link key={href} href={href} className="hover:text-ink">
              {label}
            </Link>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-sm">
          {session ? (
            <>
              <span className="text-muted">
                {session.fullName} · <span className="font-mono text-xs">{session.role}</span>
              </span>
              <button
                className="btn-ghost"
                onClick={() => {
                  setSession(null);
                  router.push("/login");
                }}
              >
                Sign out
              </button>
            </>
          ) : (
            <Link href="/login" className="btn">
              Sign in
            </Link>
          )}
        </div>
      </div>
    </header>
  );
}
