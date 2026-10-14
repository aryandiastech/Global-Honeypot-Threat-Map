import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import AttackDetails from "./AttackDetails";
import { clusterColor, clusterTactic, countryCode, groupSessions, isBotnet, summarizeSession, timeAgo } from "./analytics";
import ThreatDatabase from "./ThreatDatabase";
import ThreatMap, { REGION_NODES } from "./ThreatMap";
import type { AttackSession, FeedSource, SimulationStatus } from "./types";
import { useThreatFeed } from "./useThreatFeed";

const token = import.meta.env.VITE_MAPBOX_TOKEN?.trim();
const apiBase = import.meta.env.VITE_API_URL?.trim().replace(/\/+$/, "") || undefined;
const POLL_MS = Number(import.meta.env.VITE_POLL_MS) || 15_000;
/** Poll faster while the simulation runs so each attack shows up within ~2 s. */
const LIVE_POLL_MS = 2_000;
const EVENT_LIMIT = Number(import.meta.env.VITE_EVENTS_LIMIT) || 200;
const TOAST_MS = 6_000;
/** Rows newer than this get a "NEW" tag in the attack database. */
const NEW_MS = 20_000;

const SOURCE_BADGE: Record<FeedSource, { label: string; cls: string; hint: string }> = {
  aws: { label: "AWS live", cls: "pill live", hint: "DynamoDB via the deployed HTTP API" },
  "local-demo": { label: "Local backend", cls: "pill demo", hint: "Local backend (demo/server.py)" },
  snapshot: { label: "Snapshot", cls: "pill snap", hint: "Bundled demo-snapshot.json (no backend running)" },
  none: { label: "No data", cls: "pill", hint: "" },
};

const nf = new Intl.NumberFormat();
const sensorName = (region?: string) => REGION_NODES[region ?? ""]?.label.replace(/ \(.*\)$/, "") ?? region ?? "sensor";

function Bars({ rows }: { rows: [string, number][] }) {
  const max = Math.max(1, ...rows.map(([, v]) => v));
  if (rows.length === 0) return <p className="muted small">No data yet.</p>;
  return (
    <ul className="bars">
      {rows.map(([k, v]) => (
        <li key={k}>
          <div className="barLabel">
            <span className="mono ellipsis">{k}</span>
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

/** Brings the honeypot sensors online (starts capturing attacks) or takes them offline. */
function DeployButton({
  running,
  available,
  busy,
  onToggle,
}: {
  running: boolean;
  available: boolean;
  busy: boolean;
  onToggle: () => void;
}) {
  if (!available) {
    return (
      <button className="simBtn" disabled title="Start the local backend (start-demo.bat) first">
        Deploy honeypot servers
      </button>
    );
  }
  return (
    <button
      className={`simBtn ${running ? "stop" : "start"}`}
      onClick={onToggle}
      disabled={busy}
      title={running ? "Honeypot servers are online and capturing attacks" : "Put the vulnerable SSH honeypots online in Mumbai and N. Virginia"}
    >
      {running ? "■ Take servers offline" : "Deploy honeypot servers"}
    </button>
  );
}

type Toast = { id: string; session: AttackSession };

export default function App() {
  const [simRunning, setSimRunning] = useState(false);
  const feed = useThreatFeed(apiBase, simRunning ? LIVE_POLL_MS : POLL_MS, EVENT_LIMIT);
  const { events, stats, source, refresh } = feed;

  const [sim, setSim] = useState<SimulationStatus | null>(null);
  const [simBusy, setSimBusy] = useState(false);
  const [focusCluster, setFocusCluster] = useState<number | null>(null);
  const [selected, setSelected] = useState<{ ip: string; sessionKey?: string | null } | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [arcs, setArcs] = useState(0);
  const [view, setView] = useState<"map" | "database">("map");
  const [now, setNow] = useState(() => Date.now());
  const onArcCount = useCallback((n: number) => setArcs(n), []);
  const onSelectIp = useCallback((ip: string) => setSelected({ ip }), []);

  // 1 s clock for countdowns and "x s ago" labels
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  // Server status arrives with every poll.
  useEffect(() => {
    if (feed.simulation) setSim(feed.simulation);
  }, [feed.simulation]);
  useEffect(() => setSimRunning(Boolean(sim?.running)), [sim?.running]);

  const toggleSimulation = async () => {
    if (!apiBase) return;
    setSimBusy(true);
    try {
      const res = await fetch(`${apiBase}/simulation/${sim?.running ? "stop" : "start"}`, { method: "POST" });
      if (res.ok) setSim((await res.json()) as SimulationStatus);
      refresh();
    } finally {
      setSimBusy(false);
    }
  };

  const clusters = stats?.clusters ?? [];
  const badge = SOURCE_BADGE[source];
  const sessions = useMemo(() => groupSessions(events), [events]);
  const logRows = useMemo(
    () => (focusCluster === null ? sessions : sessions.filter((s) => Number(s.cluster_id) === focusCluster)).slice(0, 40),
    [sessions, focusCluster],
  );

  // Toast for every attack session that appears after the first load (which may be empty).
  const seen = useRef<Set<string> | null>(null);
  useEffect(() => {
    if (seen.current === null) {
      if (!feed.lastUpdated) return; // first load not done yet
      seen.current = new Set(sessions.map((s) => s.key));
      return;
    }
    const fresh = sessions.filter((s) => !seen.current!.has(s.key));
    fresh.forEach((s) => seen.current!.add(s.key));
    if (fresh.length === 0) return;
    const added = fresh.slice(0, 3).map((s) => ({ id: `${s.key}-${Date.now()}`, session: s }));
    setToasts((t) => [...added, ...t].slice(0, 4));
    for (const t of added) window.setTimeout(() => setToasts((all) => all.filter((x) => x.id !== t.id)), TOAST_MS);
  }, [sessions, feed.lastUpdated]);

  const kpis: [string, string | number, string?][] = stats
    ? [
        ["Attacks", nf.format(stats.total_attacks ?? sessions.length), "Attack sessions: one per intruder connection"],
        ["Log events", nf.format(stats.total_events), "Raw honeypot log lines: every attack writes several (connect, each password tried, each command, disconnect)"],
        ["Attackers", nf.format(stats.unique_attackers)],
        ["Countries", stats.countries],
        ["Botnets", stats.botnets, "Coordinated attacker groups found by the ML (DBSCAN on shared passwords/commands)"],
        ["Cracked", nf.format(stats.login_success), "Successful logins: attackers who guessed a password"],
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
          {kpis.map(([k, v, hint]) => (
            <div className="kpi" key={k} title={hint}>
              <div className="kpiValue">{v}</div>
              <div className="kpiLabel">{k}</div>
            </div>
          ))}
        </div>
        <div className="topActions">
          <div className="viewSwitch" role="tablist" aria-label="View">
            <button role="tab" aria-selected={view === "map"} className={view === "map" ? "on" : ""} onClick={() => setView("map")}>
              Map
            </button>
            <button role="tab" aria-selected={view === "database"} className={view === "database" ? "on" : ""} onClick={() => setView("database")}>
              Database · AI/ML
            </button>
          </div>
          {source !== "aws" ? (
            <DeployButton running={Boolean(sim?.running)} available={source === "local-demo" && Boolean(sim)} busy={simBusy} onToggle={toggleSimulation} />
          ) : null}
          {source !== "local-demo" ? (
            <div className={badge.cls} title={badge.hint}>
              <span className="dot" /> {badge.label}
            </div>
          ) : null}
        </div>
      </header>

      <div className="body">
      {view === "database" ? (
        <div className="dbOverlay">
          <ThreatDatabase
            apiBase={apiBase}
            source={source}
            pollMs={simRunning ? LIVE_POLL_MS : POLL_MS}
            events={events}
            onShowOnMap={(ip) => {
              setView("map");
              setSelected({ ip });
            }}
          />
        </div>
      ) : null}
      <main className="main" aria-hidden={view === "database"}>
        <section className="mapPanel">
          <ThreatMap
            token={token}
            events={events}
            clusters={clusters}
            focusCluster={focusCluster}
            onArcCount={onArcCount}
            selectedIp={selected?.ip ?? null}
            onSelect={onSelectIp}
          />

          {selected ? (
            <AttackDetails
              key={selected.ip /* fresh state per attacker: no stale rows while the next one loads */}
              ip={selected.ip}
              sessionKey={selected.sessionKey}
              apiBase={apiBase}
              source={source}
              events={events}
              clusters={clusters}
              refreshKey={feed.lastUpdated}
              onClose={() => setSelected(null)}
            />
          ) : (
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
              <div className="muted small">{arcs} attack arcs · pulsing = last 90s · click a dot for details</div>
            </div>
          )}

          <div className="toasts" aria-live="polite">
            {toasts.map(({ id, session: s }) => (
              <button
                key={id}
                className="toast"
                style={{ borderLeftColor: clusterColor(s.cluster_id) }}
                onClick={() => setSelected({ ip: s.src_ip, sessionKey: s.key })}
              >
                <div className="toastTitle">
                  ⚠ New attack on {sensorName(s.aws_region)}
                </div>
                <div className="small">
                  <span className="cc">{countryCode(s.head.geo_country)}</span>{" "}
                  <span className="mono">{s.src_ip}</span>
                  {s.head.geo_city ? ` · ${s.head.geo_city}` : ""}
                </div>
                <div className={`small ${s.success ? "hot" : "muted"}`}>{summarizeSession(s)}</div>
              </button>
            ))}
          </div>
        </section>

        <aside className="side">
          {feed.error ? <div className="inlineError">{feed.error}</div> : null}

          <div className="card">
            <div className="cardTitle">
              Attack database{" "}
              <span className="muted small">
                {source === "snapshot" ? "static snapshot" : `refresh ${Math.round((simRunning ? LIVE_POLL_MS : POLL_MS) / 1000)}s`}
                {feed.lastUpdated ? ` · ${feed.lastUpdated}` : ""}
              </span>
            </div>
            <p className="muted small dbHint">Each row is one stored attack session. Click a row for full details.</p>
            {feed.loading ? (
              <p className="muted small">Loading…</p>
            ) : logRows.length === 0 ? (
              <p className="muted small">
                {source === "local-demo" && !sim?.running
                  ? "No attacks yet. Press Deploy honeypot servers to put the sensors online."
                  : focusCluster !== null
                    ? "No stored attacks from this botnet yet."
                    : "No attacks stored yet — waiting for the first one…"}
              </p>
            ) : (
              <ul className="events">
                {logRows.map((s) => {
                  const isNew = now - (Date.parse(s.end) || 0) < NEW_MS;
                  const active = selected?.ip === s.src_ip;
                  return (
                    <li key={s.key}>
                      <button
                        className={`eventRow${active ? " active" : ""}${isNew ? " new" : ""}`}
                        style={{ borderLeftColor: clusterColor(s.cluster_id) }}
                        onClick={() => setSelected({ ip: s.src_ip, sessionKey: s.key })}
                      >
                        <div className="eventTop">
                          <span className="mono">
                            <span className="cc">{countryCode(s.head.geo_country)}</span> {s.src_ip}
                          </span>
                          <span className="muted small">
                            {isNew ? <span className="newTag">NEW</span> : null} {timeAgo(s.end)}
                          </span>
                        </div>
                        <div className={`small ellipsis ${s.success ? "hot" : "muted"}`}>{summarizeSession(s)}</div>
                        <div className="muted small eventMeta">
                          <span className="ellipsis">
                            {[s.head.geo_city, s.head.geo_country_name ?? s.head.geo_country].filter(Boolean).join(", ") || "location pending"}
                            {` → ${sensorName(s.aws_region)}`}
                          </span>
                          {isBotnet(s.cluster_id) ? (
                            <b style={{ color: clusterColor(s.cluster_id) }}>BOTNET-{s.cluster_id}</b>
                          ) : (
                            <span>lone scanner</span>
                          )}
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="card">
            <div className="cardTitle">
              Botnet clusters{" "}
              <span className="muted small">
                DBSCAN{stats?.cluster_engine && stats.cluster_engine !== "none" ? ` · ${stats.cluster_engine}` : ""}
              </span>
            </div>
            {clusters.length === 0 ? (
              <p className="muted small">
                No botnets detected yet. The ML groups attackers once at least 3 IPs show the same behaviour
                (same password list, same commands).
              </p>
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
    </div>
  );
}
