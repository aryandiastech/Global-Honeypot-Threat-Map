import { useEffect, useMemo, useRef, useState } from "react";
import { PALETTE, clusterColor, countryCode, describeEvent, isBotnet, timeAgo } from "./analytics";
import { REGION_NODES } from "./ThreatMap";
import type { AttackRow, FeedSource, RemoteEvent } from "./types";
import { useAttackDb } from "./useAttackDb";

/** Colour per attack type (stable, independent of scan order). */
export const TYPE_COLOR: Record<string, string> = {
  recon_scan: "#8fa3c7",
  brute_force: "#ffb347",
  credential_compromise: "#ff924c",
  discovery: "#c77dff",
  malware_dropper: "#ff595e",
  persistence: "#f15bb5",
  iot_botnet: "#00bbf9",
};
const SEVERITY_COLOR: Record<string, string> = { low: "#8fa3c7", medium: "#ffb347", high: "#ff924c", critical: "#ff4d4d" };
const STAGES: [string, string][] = [
  ["feature_extraction", "Feature extraction"],
  ["classification", "Naive Bayes classification"],
  ["clustering", "k-means clustering"],
  ["projection", "PCA projection"],
];
const PAGE = 60;

/** Naive Bayes posteriors saturate near 1 — never claim 100 %. */
const confText = (c: number) => (c >= 0.999 ? ">99.9%" : `${(c * 100).toFixed(c >= 0.99 ? 1 : 0)}%`);
const pct = (x?: number | null) => (x === null || x === undefined ? "—" : `${Math.round(x * 100)}%`);
const sensorName = (r?: string) => REGION_NODES[r ?? ""]?.label.replace(/ \(.*\)$/, "") ?? r ?? "—";
const clock = (iso?: string) => {
  const t = Date.parse(iso ?? "");
  return Number.isNaN(t) ? "" : new Date(t).toLocaleTimeString();
};
const clusterTint = (c?: number) => (c === undefined ? "#5b6b85" : PALETTE[c % PALETTE.length]);
const jitter = (id: string, salt: number) => {
  let h = salt;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0;
  return ((h % 1000) / 1000) * 2.4 - 1.2;
};

type Props = {
  apiBase?: string;
  source: FeedSource;
  pollMs: number;
  /** events the dashboard already has (session timelines in snapshot mode) */
  events: RemoteEvent[];
  onShowOnMap: (ip: string) => void;
};

export default function ThreatDatabase({ apiBase, source, pollMs, events, onShowOnMap }: Props) {
  const db = useAttackDb(apiBase, source, true, pollMs);
  const [autoScan, setAutoScan] = useState(true);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [clusterFilter, setClusterFilter] = useState<number | null>(null);
  const [colorBy, setColorBy] = useState<"cluster" | "type">("cluster");
  const [openId, setOpenId] = useState<string | null>(null);
  const [limit, setLimit] = useState(PAGE);
  const [hover, setHover] = useState<AttackRow | null>(null);
  const tableRef = useRef<HTMLDivElement | null>(null);

  // Auto-scan: classify new attacks as soon as they are stored.
  useEffect(() => {
    if (autoScan && db.canScan && !db.scanning && db.rows.length > 0 && (db.unscanned > 0 || !db.analysis?.scanned)) {
      void db.scan();
    }
  }, [autoScan, db.canScan, db.scanning, db.unscanned, db.rows.length, db.analysis?.scanned, db.scan]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return db.rows.filter((r) => {
      if (typeFilter && r.ml?.attack_type !== typeFilter) return false;
      if (clusterFilter !== null && r.ml?.ml_cluster !== clusterFilter) return false;
      if (!q) return true;
      const hay = [r.src_ip, r.geo_city, r.geo_country_name, r.geo_org, r.ml?.attack_label, r.success_credential,
        ...r.commands, ...r.credentials_tried].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [db.rows, query, typeFilter, clusterFilter]);

  const scanned = db.rows.filter((r) => r.ml);
  const a = db.analysis;
  const m = a?.model;

  const openRow = (id: string) => {
    setOpenId(id);
    const idx = filtered.findIndex((r) => r.id === id);
    if (idx >= limit) setLimit(idx + 10);
    window.setTimeout(() => tableRef.current?.querySelector(`[data-row="${CSS.escape(id)}"]`)?.scrollIntoView({ behavior: "smooth", block: "center" }), 50);
  };

  if (!db.supported) {
    return (
      <div className="dbView">
        <div className="card dbEmpty">
          <b>The threat database runs on the local demo backend.</b>
          <p className="muted small">Start it with <code>start-demo.bat</code> to store attacks and run the AI/ML scan.</p>
        </div>
      </div>
    );
  }

  // ---- PCA scatter geometry
  const pts = scanned.map((r) => ({ r, x: r.ml!.pca[0], y: r.ml!.pca[1] }));
  const xs = pts.map((p) => p.x);
  const ys = pts.map((p) => p.y);
  const [x0, x1, y0, y1] = [Math.min(...xs, 0), Math.max(...xs, 0.01), Math.min(...ys, 0), Math.max(...ys, 0.01)];
  const sx = (x: number) => 6 + ((x - x0) / (x1 - x0 || 1)) * 88;
  const sy = (y: number) => 94 - ((y - y0) / (y1 - y0 || 1)) * 88;

  return (
    <div className="dbView">
      {/* ------------------------------------------------------------ model card */}
      <div className="dbTop">
        <section className="card mlCard">
          <div className="cardTitle">
            AI/ML attack analysis
            <span className="muted small">{a?.scanned_at ? `last scan ${clock(a.scanned_at)}` : "not scanned yet"}</span>
          </div>
          <div className="scanRow">
            <button className="scanBtn" onClick={() => void db.scan(1200)} disabled={!db.canScan || db.scanning || db.rows.length === 0}>
              {db.scanning ? "Scanning…" : "🧠 Run AI/ML scan"}
            </button>
            <label className="small muted autoScan">
              <input type="checkbox" checked={autoScan} onChange={(e) => setAutoScan(e.target.checked)} disabled={!db.canScan} />
              auto-scan new attacks
            </label>
          </div>
          <ol className={`stages${db.scanning ? " running" : ""}`}>
            {STAGES.map(([key, label], i) => (
              <li key={key} style={{ animationDelay: `${i * 0.25}s` }}>
                <span>{label}</span>
                <span className="muted small mono">{a?.timings_ms?.[key] !== undefined ? `${a.timings_ms[key]} ms` : "—"}</span>
              </li>
            ))}
          </ol>
          <div className="metrics">
            <div title="Leave-one-out accuracy of the Naive Bayes classifier on its labelled training corpus">
              <b>{pct(m?.loo_accuracy)}</b>
              <span>classifier accuracy</span>
            </div>
            <div title="How well-separated the k-means clusters are (-1 to 1, higher is better)">
              <b>{m?.silhouette ?? "—"}</b>
              <span>silhouette</span>
            </div>
            <div title="Share of attacks whose unsupervised cluster agrees with the supervised attack type">
              <b>{pct(m?.cluster_type_agreement)}</b>
              <span>cluster/type agreement</span>
            </div>
            <div>
              <b>{m?.k ?? "—"}</b>
              <span>clusters (k)</span>
            </div>
          </div>
          <p className="muted small modelNote">
            {m
              ? `${m.classifier} trained on ${m.training_examples} labelled attacks · ${m.classes} classes · ${m.features} features · ${m.clustering} · ${m.projection}.`
              : "Classifies every stored attack, then clusters attacks by behaviour without labels."}
            {db.unscanned > 0 ? ` ${db.unscanned} new attack${db.unscanned === 1 ? "" : "s"} not scanned yet.` : ""}
          </p>
        </section>

        {/* -------------------------------------------------------- type mix */}
        <section className="card">
          <div className="cardTitle">
            Attack types <span className="muted small">{scanned.length} classified</span>
          </div>
          <ul className="typeBars">
            {(a?.types ?? []).map((t) => {
              const max = Math.max(1, ...(a?.types ?? []).map((x) => x.count));
              const active = typeFilter === t.type;
              return (
                <li key={t.type}>
                  <button className={`typeBtn${active ? " active" : ""}`} onClick={() => setTypeFilter(active ? null : t.type)} title={t.description}>
                    <div className="barLabel">
                      <span>
                        <span className="dotSwatch" style={{ background: TYPE_COLOR[t.type] }} /> {t.label}
                      </span>
                      <span className="muted small">{t.count}</span>
                    </div>
                    <div className="barTrack">
                      <div className="barFill" style={{ width: `${(t.count / max) * 100}%`, background: TYPE_COLOR[t.type] }} />
                    </div>
                    <div className="mitreLine small muted">
                      <span className="sev" style={{ color: SEVERITY_COLOR[t.severity] }}>{t.severity}</span> ·{" "}
                      {t.mitre.map(([id]) => id).join(", ")}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </section>

        {/* -------------------------------------------------------- PCA scatter */}
        <section className="card scatterCard">
          <div className="cardTitle">
            Attack clusters (PCA)
            <span className="seg small">
              <button className={colorBy === "cluster" ? "on" : ""} onClick={() => setColorBy("cluster")}>by cluster</button>
              <button className={colorBy === "type" ? "on" : ""} onClick={() => setColorBy("type")}>by type</button>
            </span>
          </div>
          {pts.length === 0 ? (
            <p className="muted small">Run a scan to project every attack into 2-D. Similar attacks land close together.</p>
          ) : (
            <div className="scatterWrap">
              <svg viewBox="0 0 100 100" className="scatter" role="img" aria-label="PCA projection of attacks">
                <line x1="6" y1="94" x2="94" y2="94" className="axis" />
                <line x1="6" y1="6" x2="6" y2="94" className="axis" />
                {pts.map(({ r, x, y }) => {
                  const dim =
                    (typeFilter && r.ml!.attack_type !== typeFilter) || (clusterFilter !== null && r.ml!.ml_cluster !== clusterFilter);
                  const color = colorBy === "cluster" ? clusterTint(r.ml!.ml_cluster) : TYPE_COLOR[r.ml!.attack_type];
                  return (
                    <circle
                      key={r.id}
                      cx={sx(x) + jitter(r.id, 1)}
                      cy={sy(y) + jitter(r.id, 7)}
                      r={openId === r.id ? 2.4 : 1.5}
                      fill={color}
                      opacity={dim ? 0.12 : 0.85}
                      stroke={openId === r.id ? "#fff" : "none"}
                      strokeWidth={0.5}
                      onMouseEnter={() => setHover(r)}
                      onMouseLeave={() => setHover(null)}
                      onClick={() => openRow(r.id)}
                      className="pt"
                    />
                  );
                })}
              </svg>
              <div className="scatterInfo small">
                {hover ? (
                  <>
                    <span className="mono">{hover.src_ip}</span> · {hover.ml?.attack_label} · cluster C{hover.ml?.ml_cluster}
                  </>
                ) : (
                  <span className="muted">PC1 → · PC2 ↑ · hover a dot, click to open the attack</span>
                )}
              </div>
            </div>
          )}
        </section>
      </div>

      {/* ------------------------------------------------------------ clusters */}
      {a?.clusters?.length ? (
        <div className="clusterStrip">
          {a.clusters.map((c) => {
            const active = clusterFilter === c.cluster;
            return (
              <button
                key={c.cluster}
                className={`clusterChip${active ? " active" : ""}`}
                style={{ borderTopColor: clusterTint(c.cluster) }}
                onClick={() => setClusterFilter(active ? null : c.cluster)}
              >
                <div className="clusterTop">
                  <b style={{ color: clusterTint(c.cluster) }}>C{c.cluster}</b>
                  <span className="muted small">{c.size} attacks · {pct(c.purity)} pure</span>
                </div>
                <div className="small">{c.label}</div>
                <div className="muted small mono ellipsis">{c.top_features.length ? c.top_features.join(" · ") : c.behaviour.join(" · ")}</div>
              </button>
            );
          })}
        </div>
      ) : null}

      {/* ------------------------------------------------------------ table */}
      <section className="card tableCard" ref={tableRef}>
        <div className="tableHead">
          <div className="cardTitle">
            Stored attacks <span className="muted small">{filtered.length} of {db.rows.length}</span>
          </div>
          <div className="tableTools">
            {typeFilter || clusterFilter !== null ? (
              <button className="linkBtn" onClick={() => { setTypeFilter(null); setClusterFilter(null); }}>
                clear filters ✕
              </button>
            ) : null}
            <input className="search" placeholder="Search IP, country, command, password…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
        </div>
        {db.rows.length === 0 ? (
          <p className="muted small">
            {db.loading ? "Loading…" : "No attacks stored yet. Start the attack simulation; every attack lands here and is classified automatically."}
          </p>
        ) : (
          <div className="tableScroll">
            <table className="attackTable">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Attacker</th>
                  <th>Origin</th>
                  <th>Sensor</th>
                  <th>AI/ML attack type</th>
                  <th>Cluster</th>
                  <th>Botnet</th>
                  <th>Logins</th>
                  <th>Cmds</th>
                  <th>Dur.</th>
                  <th>Abuse</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, limit).map((r) => (
                  <AttackTableRow
                    key={r.id}
                    r={r}
                    open={openId === r.id}
                    onToggle={() => setOpenId(openId === r.id ? null : r.id)}
                    apiBase={apiBase}
                    source={source}
                    events={events}
                    onShowOnMap={onShowOnMap}
                  />
                ))}
              </tbody>
            </table>
            {filtered.length > limit ? (
              <button className="linkBtn more" onClick={() => setLimit(limit + PAGE)}>
                show {Math.min(PAGE, filtered.length - limit)} more
              </button>
            ) : null}
          </div>
        )}
      </section>
    </div>
  );
}

function AttackTableRow({
  r,
  open,
  onToggle,
  apiBase,
  source,
  events,
  onShowOnMap,
}: {
  r: AttackRow;
  open: boolean;
  onToggle: () => void;
  apiBase?: string;
  source: FeedSource;
  events: RemoteEvent[];
  onShowOnMap: (ip: string) => void;
}) {
  const [timeline, setTimeline] = useState<RemoteEvent[] | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (source === "local-demo" && apiBase) {
      fetch(`${apiBase}/attacks/${encodeURIComponent(r.id)}`)
        .then((res) => (res.ok ? res.json() : null))
        .then((d) => setTimeline(d?.events ?? []))
        .catch(() => setTimeline([]));
    } else {
      setTimeline(events.filter((e) => e.session && e.session === r.session).reverse());
    }
  }, [open, r.id, r.session, apiBase, source, events]);

  const ml = r.ml;
  const t0 = timeline?.length ? Date.parse(timeline[0].sensor_timestamp ?? timeline[0].received_at ?? "") : NaN;
  return (
    <>
      <tr className={`aRow${open ? " open" : ""}`} onClick={onToggle} data-row={r.id}>
        <td className="small">
          {clock(r.start)}
          <div className="muted tiny">{timeAgo(r.end)}</div>
        </td>
        <td className="mono small">
          <span className="cc">{countryCode(r.geo_country)}</span> {r.src_ip}
        </td>
        <td className="small ellipsis">{[r.geo_city, r.geo_country_name].filter(Boolean).join(", ")}</td>
        <td className="small">{sensorName(r.aws_region)}</td>
        <td>
          {ml ? (
            <span className="typeBadge" style={{ borderColor: TYPE_COLOR[ml.attack_type], color: TYPE_COLOR[ml.attack_type] }}>
              {ml.attack_label} <span className="conf">{confText(ml.confidence)}</span>
            </span>
          ) : (
            <span className="typeBadge pending">pending scan</span>
          )}
        </td>
        <td className="small">{ml ? <b style={{ color: clusterTint(ml.ml_cluster) }}>C{ml.ml_cluster}</b> : "—"}</td>
        <td className="small">
          {isBotnet(r.botnet_id) ? <b style={{ color: clusterColor(r.botnet_id) }}>B-{r.botnet_id}</b> : <span className="muted">—</span>}
        </td>
        <td className="small">
          {r.login_attempts}
          {r.login_success ? <span className="hot"> ✔</span> : null}
        </td>
        <td className="small">{r.commands.length}</td>
        <td className="small muted">{r.duration_s ?? "—"}s</td>
        <td className="small">{r.abuse_score ?? "—"}</td>
      </tr>
      {open ? (
        <tr className="aDetail">
          <td colSpan={11}>
            <div className="detailGrid">
              <div>
                <div className="dTitle">Session</div>
                <div className="kv"><span>Session id</span><span className="mono small">{r.session ?? r.id}</span></div>
                <div className="kv"><span>SSH client</span><span className="mono small ellipsis">{r.client_version ?? "—"}</span></div>
                <div className="kv"><span>Network</span><span className="small ellipsis">{r.geo_org ?? "—"}</span></div>
                <div className="kv"><span>Logins</span><span className="small">{r.failed_logins} failed{r.login_success ? `, cracked ${r.success_credential}` : ""}</span></div>
                <div className="kv"><span>Downloads</span><span className="small">{r.downloads}</span></div>
                {r.credentials_tried.length ? (
                  <>
                    <div className="dTitle sub">Passwords tried</div>
                    <div className="chips">
                      {r.credentials_tried.map((c, i) => (
                        <span key={i} className="chip mono">{c}</span>
                      ))}
                    </div>
                  </>
                ) : null}
                <button className="linkBtn" onClick={() => onShowOnMap(r.src_ip)}>🌍 show attacker on the map</button>
              </div>

              <div>
                <div className="dTitle">AI/ML verdict</div>
                {ml ? (
                  <>
                    <div className="verdict" style={{ borderLeftColor: TYPE_COLOR[ml.attack_type] }}>
                      <b style={{ color: TYPE_COLOR[ml.attack_type] }}>{ml.attack_label}</b>
                      <span className="sev small" style={{ color: SEVERITY_COLOR[ml.severity] }}>{ml.severity}</span>
                    </div>
                    <div className="kv"><span>Confidence</span><span>{confText(ml.confidence)}</span></div>
                    <div className="barTrack"><div className="barFill" style={{ width: `${ml.confidence * 100}%`, background: TYPE_COLOR[ml.attack_type] }} /></div>
                    <div className="kv"><span>Runner-up</span><span className="small muted">{ml.runner_up.replace(/_/g, " ")}</span></div>
                    <div className="kv"><span>Behaviour cluster</span><b style={{ color: clusterTint(ml.ml_cluster) }}>C{ml.ml_cluster}</b></div>
                    <div className="dTitle sub">Why (top features)</div>
                    <div className="chips">
                      {ml.explanation.length ? ml.explanation.map((f) => <span key={f} className="chip mono">{f}</span>) : <span className="muted small">behaviour only</span>}
                    </div>
                    <div className="dTitle sub">MITRE ATT&amp;CK</div>
                    <ul className="mitre">
                      {ml.mitre.map(([id, name]) => (
                        <li key={id}>
                          <a href={`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>
                            {id}
                          </a>{" "}
                          <span className="small">{name}</span>
                        </li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <p className="muted small">Not scanned yet. Run the AI/ML scan.</p>
                )}
              </div>

              <div>
                <div className="dTitle">
                  Event timeline
                  <button className="linkBtn rawToggle" onClick={() => setShowRaw(!showRaw)}>{showRaw ? "timeline" : "raw records"}</button>
                </div>
                {timeline === null ? (
                  <p className="muted small">Loading…</p>
                ) : timeline.length === 0 ? (
                  <p className="muted small">Event rows not available in this view.</p>
                ) : showRaw ? (
                  <pre className="mono rawBox">{JSON.stringify(timeline, null, 2)}</pre>
                ) : (
                  <ol className="timeline">
                    {timeline.map((e, i) => {
                      const t = Date.parse(e.sensor_timestamp ?? e.received_at ?? "");
                      const hot = e.cowrie_eventid === "cowrie.login.success" || e.command || e.cowrie_eventid === "cowrie.session.file_download";
                      return (
                        <li key={e.event_id ?? i} className="tlRow">
                          <span className="tlTime mono">{Number.isNaN(t) || Number.isNaN(t0) ? "" : `+${((t - t0) / 1000).toFixed(1)}s`}</span>
                          <span className={`mono small ${hot ? "hot" : ""}`}>{describeEvent(e)}</span>
                        </li>
                      );
                    })}
                  </ol>
                )}
              </div>
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}
