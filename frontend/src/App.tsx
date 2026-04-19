import { useEffect, useRef, useState } from "react";
import mapboxgl from "mapbox-gl";
import "mapbox-gl/dist/mapbox-gl.css";
import "./App.css";

const token = import.meta.env.VITE_MAPBOX_TOKEN?.trim();

export default function App() {
  const mapEl = useRef<HTMLDivElement | null>(null);
  const [mapError, setMapError] = useState<string | null>(null);

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

  return (
    <div className="shell">
      <header className="topbar">
        <div>
          <div className="title">Global Honeypot Threat Map</div>
          <div className="subtitle">Live honeypot telemetry → ML → 3D arcs (Mapbox)</div>
        </div>
        <div className="pill">frontend scaffold</div>
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
                Attack arcs and live feeds will connect once the read API + DynamoDB stream are wired in.
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
              <span>API</span>
              <span>not connected yet</span>
            </div>
          </div>

          <div className="card">
            <div className="cardTitle">Next wiring</div>
            <ul className="list">
              <li>HTTP API + Lambda reads from DynamoDB</li>
              <li>WebSocket or polling for “live” updates</li>
              <li>Geo-IP enrichment for arc endpoints</li>
            </ul>
          </div>
        </aside>
      </main>
    </div>
  );
}
