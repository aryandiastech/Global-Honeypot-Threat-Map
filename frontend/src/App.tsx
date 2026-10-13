import { useCallback, useMemo, useState } from "react";
import "./App.css";
import { clusterColor, clusterTactic, countryCode, describeEvent, isBotnet, timeAgo } from "./analytics";
import ThreatMap from "./ThreatMap";
import type { FeedSource } from "./types";
import { useThreatFeed } from "./useThreatFeed";

const token = import.meta.env.VITE_MAPBOX_TOKEN?.trim();
const apiBase = import.meta.env.VITE_API_URL?.trim().replace(/\/+$/, "") || undefined;
const POLL_MS = Number(import.meta.env.VITE_POLL_MS) || 15_000;
const EVENT_LIMIT = Number(import.meta.env.VITE_EVENTS_LIMIT) || 200;

const SOURCE_BADGE: Record<FeedSource, { label: string; cls: string; hint: string }> = {
  aws: { label: "AWS · live", cls: "pill live", hint: "DynamoDB via the deployed HTTP API" },
  "local-demo": { label: "Local backend · simulated", cls: "pill demo", hint: "demo/server.py on this laptop" },
  snapshot: { label: "Offline snapshot", cls: "pill snap", hint: "Bundled demo-snapshot.json (no backend running)" },
  none: { label: "No data", cls: "pill", hint: "" },
};

const nf = new Intl.NumberFormat();

function Bars({ rows, render }: { rows: [string, number][]; render?: (k: string) => React.ReactNode }) {
  const max = Math.max(1, ...rows.map(([, v]) => v));
  if (rows.length === 0) return <p className="muted small">No data yet.</p>;
  return (
    <ul className="bars">
      {rows.map(([k, v]) => (
        <li key={k}>
          <div className="barLabel">
            <span className="mono ellipsis">{render ? render(k) : k}</span>
            <span className="muted small">{nf.format(v)}</span>
          </div>
          <div className="barTrack">
            <div className="barFill" style={{ width: `${(v / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

function Sparkline({ values }: { values: number[] }) {
  // values[0] = last hour; draw oldest → newest left to right
  const pts = [...values].reverse();
  const max = Math.max(1, ...pts);
  const w = 100;
  const h = 28;
  const d = pts.map((v, i) => `${(i / (pts.length - 1)) * w},${h - (v / max) * (h - 2) - 1}`).join(" ");
  return (
    <svg className="spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-label="events per hour, last 24h">
      <polyline points={d} fill="none" stroke="var(--accent)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export default function App() {
  const feed = useThreatFeed(apiBase, POLL_MS, EVENT_LIMIT);
  const { events, stats, source } = feed;
  const [focusCluster, setFocusCluster] = useState<number | null>(null);
  const [arcs, setArcs] = useState(0);
  const onArcCount = useCallback((n: number) => setArcs(n), []);

  const clusters = stats?.clusters ?? [];
  const badge = SOURCE_BADGE[source];
  const feedRows = useMemo(
    () => (focusCluster === null ? events : events.filter((e) => Number(e.cluster_id) === focusCluster)).slice(0, 60),
    [events, focusCluster],
  );

  const kpis: [string, string | number][] = stats
    ? [
        ["Events", nf.format(stats.total_events)],
        ["Attackers", nf.format(stats.unique_attackers)],
        ["Countries", stats.countries],
        ["Botnets (ML)", stats.botnets],
        ["Logins cracked", nf.format(stats.login_success)],
      ]
    : [];

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <div className="title">🍯 Global Honeypot Threat Map</div>
          <div className="subtitle">Cowrie SSH honeypots → serverless pipeline → geo/reputation enrichment → DBSCAN botnet detection</div>
        </div>
        <div className="kpis">
          {kpis.map(([k, v]) => (
            <div className="kpi" key={k}>
              <div className="kpiValue">{v}</div>
              <div className="kpiLabel">{k}</div>
            </div>
          ))}
          {stats?.events_last_24h ? (
            <div className="kpi wide">
              <Sparkline values={stats.events_last_24h} />
              <div className="kpiLabel">Events / hour · 24h</div>
            </div>
          ) : null}
        </div>
        <div className={badge.cls} title={badge.hint}>
          <span className="dot" /> {badge.label}
        </div>
      </header>

      <main className="main">
        <section className="mapPanel">
          <ThreatMap token={token} events={events} clusters={clusters} focusCluster={focusCluster} onArcCount={onArcCount} />
          <div className="legend">
            <div>
              <span className="swatch sensor" /> Honeypot sensor
            </div>
            <div>
              <span className="swatch" style={{ background: clusterColor(-1) }} /> Lone scanner
            </div>
            <div>
              <span className="swatch" style={{ background: clusterColor(0) }} /> Botnet (colour = cluster)
            </div>
            <div className="muted small">{arcs} attack arcs · bright = last 90s · click a dot</div>
          </div>
        </section>

        <aside className="side">
          {feed.error ? <div className="inlineError">{feed.error}</div> : null}

          <div className="card">
            <div className="cardTitle">
              Botnet clusters <span className="muted small">DBSCAN{stats?.cluster_engine ? ` · ${stats.cluster_engine}` : ""}</span>
            </div>
            {clusters.length === 0 ? (
              <p className="muted small">No clusters yet — the ML job labels events once enough attackers are seen.</p>
            ) : (
              <ul className="clusters">
                {clusters.map((c) => {
                  const active = focusCluster === c.cluster_id;
                  return (
                    <li key={c.cluster_id}>
                      <button
                        className={`clusterBtn${active ? " active" : ""}`}
                        onClick={() => setFocusCluster(active ? null : c.cluster_id)}
                        style={{ borderLeftColor: clusterColor(c.cluster_id) }}
                      >
                        <div className="clusterTop">
                          <b style={{ color: clusterColor(c.cluster_id) }}>BOTNET-{c.cluster_id}</b>
                          <span className="tag">{clusterTactic(c)}</span>
                        </div>
                        <div className="muted small">
                          {c.ips} IPs · {nf.format(c.events)} events
                          {c.top_credentials[0] ? (
                            <>
                              {" "}
                              · tries <span className="mono">{c.top_credentials[0]}</span>
                            </>
                          ) : null}
                        </div>
                        {c.top_commands[0] ? <div className="mono small cmd ellipsis">$ {c.top_commands[0]}</div> : null}
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
            {focusCluster !== null ? (
              <button className="linkBtn" onClick={() => setFocusCluster(null)}>
                ← show all traffic
              </button>
            ) : null}
          </div>

          <div className="grid2">
            <div className="card">
              <div className="cardTitle">Top origins</div>
              <Bars rows={(stats?.top_countries ?? []).slice(0, 6)} />
            </div>
            <div className="card">
              <div className="cardTitle">Top credentials</div>
              <Bars rows={(stats?.top_credentials ?? []).slice(0, 6)} />
            </div>
          </div>

          <div className="card">
            <div className="cardTitle">
              Live attack feed{" "}
              <span className="muted small">
                {source === "snapshot" ? "static" : `every ${Math.round(POLL_MS / 1000)}s`}
                {feed.lastUpdated ? ` · ${feed.lastUpdated}` : ""}
              </span>
            </div>
            {feed.loading ? (
              <p className="muted small">Loading…</p>
            ) : feedRows.length === 0 ? (
              <p className="muted small">No events yet.</p>
            ) : (
              <ul className="events">
                {feedRows.map((e) => (
                  <li key={e.event_id ?? `${e.s3_key}-${e.line_index}`} className="eventRow" style={{ borderLeftColor: clusterColor(e.cluster_id) }}>
                    <div className="eventTop">
                      <span className="mono">
                        <span className="cc">{countryCode(e.geo_country)}</span> {e.src_ip ?? "—"}
                      </span>
                      <span className="muted small">{timeAgo(e.received_at)}</span>
                    </div>
                    <div className={`small mono ellipsis ${e.cowrie_eventid === "cowrie.login.success" || e.command ? "hot" : "muted"}`}>
                      {describeEvent(e)}
                    </div>
                    <div className="muted small eventMeta">
                      <span className="ellipsis">
                        {[e.geo_city, e.geo_country_name ?? e.geo_country].filter(Boolean).join(", ") || "location pending"}
                        {e.aws_region ? ` → ${e.aws_region}` : ""}
                      </span>
                      {isBotnet(e.cluster_id) ? (
                        <b style={{ color: clusterColor(e.cluster_id) }}>BOTNET-{e.cluster_id}</b>
                      ) : typeof e.abuse_score === "number" ? (
                        <span>abuse {e.abuse_score}</span>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="card status">
            <div className="kv">
              <span>Data source</span>
              <span className="muted small">{badge.hint || "—"}</span>
            </div>
            <div className="kv">
              <span>API</span>
              <span className="muted small mono ellipsis">{apiBase ?? "VITE_API_URL not set"}</span>
            </div>
            <div className="kv">
              <span>Map</span>
              <span className="muted small">{token ? "Mapbox (token set)" : "MapLibre + OpenFreeMap (no key)"}</span>
            </div>
          </div>
        </aside>
      </main>
    </div>
  );
}
