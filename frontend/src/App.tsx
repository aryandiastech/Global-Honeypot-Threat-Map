import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import AttackDetails from "./AttackDetails";
import { clusterColor, clusterTactic, countryCode, groupSessions, isBotnet, summarizeSession, timeAgo } from "./analytics";
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
  aws: { label: "AWS · live", cls: "pill live", hint: "DynamoDB via the deployed HTTP API" },
  "local-demo": { label: "Local backend · simulated", cls: "pill demo", hint: "demo/server.py on this laptop" },
  snapshot: { label: "Offline snapshot", cls: "pill snap", hint: "Bundled demo-snapshot.json (no backend running)" },
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

function SimulationButton({
  status,
  available,
  busy,
  now,
  onToggle,
}: {
  status: SimulationStatus | null;
  available: boolean;
  busy: boolean;
  now: number;
  onToggle: () => void;
}) {
  if (!available) {
    return (
      <button className="simBtn" disabled title="Start the local backend (start-demo.bat) to run the live attack simulation">
        ▶ Start attack simulation
      </button>
    );
  }
  const running = Boolean(status?.running);
  const nextIn = status?.next_attack_at ? Math.max(0, Math.ceil((Date.parse(status.next_attack_at) - now) / 1000)) : null;
  return (
    <div className="simWrap">
      <button className={`simBtn ${running ? "stop" : "start"}`} onClick={onToggle} disabled={busy}>
        {running ? "■ Stop simulation" : "▶ Start attack simulation"}
      </button>
      <div className="simMeta muted small">
        {running
          ? `${status?.attacks ?? 0} attack${status?.attacks === 1 ? "" : "s"} · next in ${nextIn ?? "…"}s`
          : `1 attack every ${status?.min_interval ?? 4}–${status?.max_interval ?? 9}s`}
      </div>
    </div>
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

  // Toast for every attack session that appears after the first load.
  const seen = useRef<Set<string> | null>(null);
  useEffect(() => {
    if (sessions.length === 0) return;
    if (seen.current === null) {
      seen.current = new Set(sessions.map((s) => s.key));
      return;
    }
    const fresh = sessions.filter((s) => !seen.current!.has(s.key));
    fresh.forEach((s) => seen.current!.add(s.key));
    if (fresh.length === 0) return;
    const added = fresh.slice(0, 3).map((s) => ({ id: `${s.key}-${Date.now()}`, session: s }));
    setToasts((t) => [...added, ...t].slice(0, 4));
    for (const t of added) window.setTimeout(() => setToasts((all) => all.filter((x) => x.id !== t.id)), TOAST_MS);
  }, [sessions]);

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
        <div className="topActions">
          {source !== "aws" ? (
            <SimulationButton status={sim} available={source === "local-demo" && Boolean(sim)} busy={simBusy} now={now} onToggle={toggleSimulation} />
          ) : null}
          <div className={badge.cls} title={badge.hint}>
            <span className="dot" /> {badge.label}
          </div>
        </div>
      </header>

      <main className="main">
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
              <p className="muted small">No attacks stored yet.</p>
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
