import { useCallback, useEffect, useRef, useState } from "react";
import type { AnalysisSummary, AttackRow, FeedSource } from "./types";

type Db = {
  rows: AttackRow[];
  analysis: AnalysisSummary | null;
  unscanned: number;
  loading: boolean;
  error: string | null;
  scanning: boolean;
  /** the backend can run scans (local demo); false for the static snapshot */
  canScan: boolean;
  supported: boolean;
};

const SNAPSHOT_URL = `${import.meta.env.BASE_URL}demo-snapshot.json`;

/**
 * Threat-database data: every stored attack session (GET /attacks) and the latest
 * AI/ML scan (GET /analysis). Only polls while the database view is open.
 */
export function useAttackDb(apiBase: string | undefined, source: FeedSource, active: boolean, pollMs: number) {
  const supported = source === "local-demo" || source === "snapshot";
  const [db, setDb] = useState<Db>({
    rows: [],
    analysis: null,
    unscanned: 0,
    loading: true,
    error: null,
    scanning: false,
    canScan: source === "local-demo",
    supported,
  });
  const scanningRef = useRef(false);

  const load = useCallback(async () => {
    try {
      if (source === "snapshot") {
        const snap = await fetch(SNAPSHOT_URL).then((r) => r.json());
        setDb((d) => ({
          ...d,
          rows: snap.attacks?.attacks ?? [],
          analysis: snap.analysis ?? null,
          unscanned: 0,
          loading: false,
          error: null,
          canScan: false,
          supported: true,
        }));
        return;
      }
      if (source !== "local-demo" || !apiBase) {
        setDb((d) => ({ ...d, loading: false, supported: false, canScan: false }));
        return;
      }
      const [a, s] = await Promise.all([
        fetch(`${apiBase}/attacks`).then((r) => r.json()),
        fetch(`${apiBase}/analysis`).then((r) => r.json()),
      ]);
      setDb((d) => ({
        ...d,
        rows: a.attacks ?? [],
        unscanned: a.unscanned ?? 0,
        analysis: s,
        loading: false,
        error: null,
        canScan: true,
        supported: true,
      }));
    } catch (err) {
      setDb((d) => ({ ...d, loading: false, error: err instanceof Error ? err.message : "load failed" }));
    }
  }, [apiBase, source]);

  const scan = useCallback(
    async (minVisibleMs = 0) => {
      if (!apiBase || source !== "local-demo" || scanningRef.current) return;
      scanningRef.current = true;
      setDb((d) => ({ ...d, scanning: true }));
      const started = Date.now();
      try {
        const res = await fetch(`${apiBase}/analysis/scan`, { method: "POST" });
        const summary = (await res.json()) as AnalysisSummary;
        // keep the "scanning" state on screen long enough to read when the user pressed the button
        const wait = minVisibleMs - (Date.now() - started);
        if (wait > 0) await new Promise((r) => setTimeout(r, wait));
        setDb((d) => ({ ...d, analysis: summary }));
        await load();
      } finally {
        scanningRef.current = false;
        setDb((d) => ({ ...d, scanning: false }));
      }
    },
    [apiBase, source, load],
  );

  useEffect(() => {
    if (!active) return;
    void load();
    if (source === "snapshot") return;
    const id = window.setInterval(() => void load(), pollMs);
    return () => window.clearInterval(id);
  }, [active, load, pollMs, source]);

  return { ...db, supported, reload: load, scan };
}
