import type { Metadata } from "next";
import { Suspense } from "react";
import Nav from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "CyberHunt KZ",
  description: "State bug bounty platform — research prototype",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col">
        <Nav />
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
          <Suspense fallback={<p className="text-sm text-muted">Loading…</p>}>{children}</Suspense>
        </main>
        <footer className="border-t border-line py-4 text-center text-xs text-muted">
          Research prototype · demo data on reserved .test domains only
        </footer>
      </body>
    </html>
  );
}
