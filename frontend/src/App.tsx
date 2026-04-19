import { useEffect, useRef, useState } from "react";
import mapboxgl from "mapbox-gl";
import "mapbox-gl/dist/mapbox-gl.css";
import "./App.css";

const token = import.meta.env.VITE_MAPBOX_TOKEN?.trim();
const apiBase = import.meta.env.VITE_API_URL?.trim().replace(/\/+$/, "");

type RemoteEvent = {
  event_id?: string;
  received_at?: string;
  src_ip?: string;
  cowrie_eventid?: string;
  s3_key?: string;
  line_index?: number;
};

export default function App() {
  const mapEl = useRef<HTMLDivElement | null>(null);
  const [mapError, setMapError] = useState<string | null>(null);

  const [events, setEvents] = useState<RemoteEvent[]>([]);
  const [apiLoading, setApiLoading] = useState(() => Boolean(apiBase));
  const [apiError, setApiError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    if (!mapEl.current) return;

    mapboxgl.accessToken = token;
    setMapError(null);

    const map = new mapboxgl.Map({
      container: mapEl.current,
      style: "mapbox://styles/mapbox/dark-v11",
      projection: "globe",
      center: [20, 25],
      zoom: 1.35,
      pitch: 45,
      bearing: -18,
    });

    map.addControl(new mapboxgl.NavigationControl({ visualizePitch: true }), "top-right");
    map.on("style.load", () => {
      map.setFog({});
    });
    map.on("error", (e) => {
      setMapError(e.error?.message ?? "Map error");
    });

    return () => {
      map.remove();
    };
  }, [token]);

  useEffect(() => {
    if (!apiBase) {
      setEvents([]);
      setApiError(null);
      setApiLoading(false);
      return;
    }

    const ac = new AbortController();
    setApiLoading(true);
    setApiError(null);

    fetch(`${apiBase}/events?limit=20`, { signal: ac.signal })
      .then(async (res) => {
        if (!res.ok) {
          const text = await res.text();
          throw new Error(text || `HTTP ${res.status}`);
        }
        return res.json() as Promise<{ items?: RemoteEvent[] }>;
      })
      .then((data) => setEvents(Array.isArray(data.items) ? data.items : []))
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setApiError(err instanceof Error ? err.message : "Request failed");
        setEvents([]);
      })
      .finally(() => setApiLoading(false));

    return () => ac.abort();
  }, [apiBase]);

  return (
    <div className="shell">
      <header className="topbar">
        <div>
          <div className="title">Global Honeypot Threat Map</div>
          <div className="subtitle">Live honeypot telemetry → ML → 3D arcs (Mapbox)</div>
        </div>
        <div className="pill">read API + dashboard</div>
      </header>

      <main className="main">
        <section className="mapPanel">
          {!token ? (
            <div className="placeholder">
              <div className="placeholderTitle">Mapbox token not set</div>
              <p className="muted">
                Create <code>.env</code> in <code>frontend/</code> using <code>.env.example</code>, set{" "}
                <code>VITE_MAPBOX_TOKEN</code>, then restart <code>npm run dev</code>.
              </p>
              <p className="muted">
                The read API can still load on the right if <code>VITE_API_URL</code> is set (SAM output{" "}
                <code>HttpApiUrl</code>).
              </p>
            </div>
          ) : (
            <>
              {mapError ? <div className="banner">Map error: {mapError}</div> : null}
              <div ref={mapEl} className="map" />
            </>
          )}
        </section>

        <aside className="side">
          <div className="card">
            <div className="cardTitle">Status</div>
            <div className="kv">
              <span>Mapbox</span>
              <span>{token ? "token present" : "missing"}</span>
            </div>
            <div className="kv">
              <span>Read API</span>
              <span>
                {!apiBase ? "VITE_API_URL not set" : apiLoading ? "loading…" : apiError ? "error" : "ok"}
              </span>
            </div>
            {apiError ? <div className="inlineError">{apiError}</div> : null}
          </div>

          <div className="card">
            <div className="cardTitle">Recent events</div>
            {!apiBase ? (
              <p className="muted small">
                Set <code>VITE_API_URL</code> to your deployed HTTP API base URL (no trailing slash), then refresh.
              </p>
            ) : events.length === 0 && !apiLoading ? (
              <p className="muted small">No items returned yet (upload logs to S3 or wait for ingest).</p>
            ) : (
              <ul className="events">
                {events.map((e) => (
                  <li key={e.event_id ?? `${e.s3_key}-${e.line_index}`} className="eventRow">
                    <div className="eventTop">
                      <span className="mono">{e.src_ip ?? "—"}</span>
                      <span className="muted small">{e.received_at ?? ""}</span>
                    </div>
                    <div className="muted small mono">{e.cowrie_eventid ?? ""}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="card">
            <div className="cardTitle">Next wiring</div>
            <ul className="list">
              <li>Polling / WebSocket for fresher updates</li>
              <li>Geo-IP enrichment for arc geometry</li>
              <li>Auth + tighter CORS for production</li>
            </ul>
          </div>
        </aside>
      </main>
    </div>
  );
}
