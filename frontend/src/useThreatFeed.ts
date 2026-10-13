import { useCallback, useEffect, useState } from "react";
import { computeStats } from "./analytics";
import type { FeedSource, RemoteEvent, SimulationStatus, Stats } from "./types";

type Feed = {
  events: RemoteEvent[];
  stats: Stats | null;
  source: FeedSource;
  loading: boolean;
  error: string | null;
  lastUpdated: string | null;
  /** live attack simulation status; null when the backend has none (AWS, snapshot) */
  simulation: SimulationStatus | null;
};

const SNAPSHOT_URL = `${import.meta.env.BASE_URL}demo-snapshot.json`;

/** Shift a snapshot's timestamps so its newest event is "now" (keeps "x min ago" meaningful). */
function rebaseTimestamps(items: RemoteEvent[]): RemoteEvent[] {
  const newest = Math.max(...items.map((e) => Date.parse(e.received_at ?? "") || 0));
  if (!newest) return items;
  const delta = Date.now() - newest;
  const shift = (iso?: string) => (iso && !Number.isNaN(Date.parse(iso)) ? new Date(Date.parse(iso) + delta).toISOString() : iso);
  return items.map((e) => ({ ...e, received_at: shift(e.received_at), sensor_timestamp: shift(e.sensor_timestamp) }));
}

/**
 * Polls GET /events (and GET /stats when the backend has it — the local demo
 * does, the AWS read API does not). With no API URL configured it falls back
 * to the bundled static snapshot so the UI never renders empty.
 */
export function useThreatFeed(
  apiBase: string | undefined,
  pollMs: number,
  limit: number,
): Feed & { refresh: () => void } {
  const [feed, setFeed] = useState<Feed>({
    events: [],
    stats: null,
    source: "none",
    loading: true,
    error: null,
    lastUpdated: null,
    simulation: null,
  });
  // Bumped by refresh() to reload immediately (e.g. right after Start/Stop).
  const [nonce, setNonce] = useState(0);
  const refresh = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let active = true;

    if (!apiBase) {
      fetch(SNAPSHOT_URL)
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`snapshot HTTP ${r.status}`))))
        .then((data: { items?: RemoteEvent[]; stats?: Stats }) => {
          if (!active) return;
          const items = rebaseTimestamps(Array.isArray(data.items) ? data.items : []);
          setFeed({
            events: items,
            stats: data.stats ?? computeStats(items),
            source: "snapshot",
            loading: false,
            error: null,
            lastUpdated: new Date().toLocaleTimeString(),
            simulation: null,
          });
        })
        .catch((err: unknown) => {
          if (!active) return;
          setFeed((f) => ({ ...f, loading: false, source: "none", error: err instanceof Error ? err.message : "No data" }));
        });
      return () => {
        active = false;
      };
    }

    let statsSupported: boolean | null = null; // unknown until first probe

    const load = async () => {
      try {
        const res = await fetch(`${apiBase}/events?limit=${limit}`);
        if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
        const data = (await res.json()) as { items?: RemoteEvent[]; source?: string; simulation?: SimulationStatus };
        const items = Array.isArray(data.items) ? data.items : [];

        let stats: Stats | null = null;
        if (statsSupported !== false) {
          try {
            const sr = await fetch(`${apiBase}/stats`);
            statsSupported = sr.ok;
            if (sr.ok) stats = (await sr.json()) as Stats;
          } catch {
            statsSupported = false;
          }
        }

        if (!active) return;
        setFeed({
          events: items,
          stats: stats ?? computeStats(items),
          source: data.source === "local-demo" ? "local-demo" : "aws",
          loading: false,
          error: null,
          lastUpdated: new Date().toLocaleTimeString(),
          simulation: data.simulation ?? null,
        });
      } catch (err: unknown) {
        if (!active) return;
        setFeed((f) => ({
          ...f,
          loading: false,
          error: err instanceof Error ? `${err.message} — is the backend running at ${apiBase}?` : "Request failed",
        }));
      }
    };

    void load();
    const id = window.setInterval(() => void load(), pollMs);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [apiBase, pollMs, limit, nonce]);

  return { ...feed, refresh };
}
