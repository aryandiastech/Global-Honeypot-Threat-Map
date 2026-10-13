import { useEffect, useMemo, useState } from "react";
import { clusterColor, clusterTactic, countryCode, describeEvent, groupSessions, isBotnet, summarizeSession, timeAgo } from "./analytics";
import { REGION_NODES } from "./ThreatMap";
import type { ClusterSummary, FeedSource, RemoteEvent } from "./types";

type Props = {
  ip: string;
  /** session to expand first (when opened from a database row or toast) */
  sessionKey?: string | null;
  apiBase?: string;
  source: FeedSource;
  /** events already loaded by the dashboard (fallback when the backend has no /attackers endpoint) */
  events: RemoteEvent[];
  clusters: ClusterSummary[];
  /** changes on every poll so the panel picks up new attacks from this IP */
  refreshKey: string | null;
  onClose: () => void;
};

const sensorLabel = (region?: string) => (region && REGION_NODES[region]?.label) || region || "unknown sensor";

const abuseColor = (score: number) => (score >= 75 ? "#ff5d5d" : score >= 40 ? "#ffb347" : "#7dd87d");

const clock = (iso?: string) => {
  const t = Date.parse(iso ?? "");
  return Number.isNaN(t) ? "" : new Date(t).toLocaleTimeString();
};

/** Hide storage plumbing in the raw-record view; everything else is shown as stored. */
const RAW_HIDDEN = new Set(["timeline_pk", "s3_bucket"]);

export default function AttackDetails({ ip, sessionKey, apiBase, source, events, clusters, refreshKey, onClose }: Props) {
  const [remote, setRemote] = useState<RemoteEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(sessionKey ?? null);

  useEffect(() => setOpen(sessionKey ?? null), [ip, sessionKey]);

  // The local backend can return every stored event for this IP; elsewhere use what the dashboard has.
  useEffect(() => {
    if (source !== "local-demo" || !apiBase) {
      setRemote(null);
      return;
    }
    let active = true;
    fetch(`${apiBase}/attackers/${encodeURIComponent(ip)}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: { events?: RemoteEvent[] }) => {
        if (active) {
          setRemote(Array.isArray(d.events) ? d.events : []);
          setError(null);
        }
      })
      .catch((e: unknown) => active && setError(e instanceof Error ? e.message : "lookup failed"));
    return () => {
      active = false;
    };
  }, [ip, apiBase, source, refreshKey]);

  const rows = useMemo(() => remote ?? events.filter((e) => e.src_ip === ip), [remote, events, ip]);
  const sessions = useMemo(() => groupSessions(rows), [rows]);
  const head = sessions[0]?.head ?? rows[0];
  const latest = rows[0];

  useEffect(() => {
    if (open === null && sessions[0]) setOpen(sessions[0].key);
  }, [open, sessions]);

  if (!head) {
    return (
      <div className="details">
        <div className="detailsHead">
          <span className="mono detailsIp">{ip}</span>
          <button className="iconBtn" onClick={onClose} aria-label="Close details">
            ✕
          </button>
        </div>
        <p className="muted small">{error ?? "Loading…"}</p>
      </div>
    );
  }

  const cid = latest?.cluster_id;
  const cluster = isBotnet(cid) ? clusters.find((c) => c.cluster_id === Number(cid)) : undefined;
  const abuse = typeof head.abuse_score === "number" ? head.abuse_score : null;
  const sensorsHit = [...new Set(rows.map((e) => e.aws_region).filter(Boolean))] as string[];
  const firstSeen = rows[rows.length - 1]?.received_at;
  const raw = latest
    ? Object.fromEntries(Object.entries(latest).filter(([k, v]) => !RAW_HIDDEN.has(k) && v !== undefined && v !== null && v !== ""))
    : {};

  return (
    <div className="details" style={{ borderTopColor: clusterColor(cid) }}>
      <div className="detailsHead">
        <div>
          <div className="detailsKicker">Attacker</div>
          <span className="mono detailsIp">
            <span className="cc">{countryCode(head.geo_country)}</span> {ip}
          </span>
        </div>
        <button className="iconBtn" onClick={onClose} aria-label="Close details">
          ✕
        </button>
      </div>

      <section className="dSection">
        <div className="dTitle">Origin</div>
        <div className="kv">
          <span>Location</span>
          <span>{[head.geo_city, head.geo_country_name ?? head.geo_country].filter(Boolean).join(", ") || "unknown"}</span>
        </div>
        <div className="kv">
          <span>Network</span>
          <span className="muted ellipsis">{head.geo_org ?? "—"}</span>
        </div>
        {typeof head.geo_lat === "number" ? (
          <div className="kv">
            <span>Coordinates</span>
            <span className="mono muted small">
              {Number(head.geo_lat).toFixed(2)}, {Number(head.geo_lon).toFixed(2)}
            </span>
          </div>
        ) : null}
      </section>

      <section className="dSection">
        <div className="dTitle">Threat intel</div>
        {abuse !== null ? (
          <div className="abuse">
            <div className="kv">
              <span>Abuse confidence</span>
              <b style={{ color: abuseColor(abuse) }}>{abuse} / 100</b>
            </div>
            <div className="barTrack">
              <div className="barFill" style={{ width: `${abuse}%`, background: abuseColor(abuse) }} />
            </div>
          </div>
        ) : null}
        <div className="kv">
          <span>Reports (AbuseIPDB)</span>
          <span>{head.abuse_total_reports ?? "—"}</span>
        </div>
        <div className="kv">
          <span>Activity</span>
          <span>
            {sessions.length} attack{sessions.length === 1 ? "" : "s"} · {rows.length} events
          </span>
        </div>
        <div className="kv">
          <span>First / last seen</span>
          <span className="muted small">
            {timeAgo(firstSeen)} / {timeAgo(latest?.received_at)}
          </span>
        </div>
        <div className="kv">
          <span>Sensors hit</span>
          <span className="small">{sensorsHit.map(sensorLabel).join(", ") || "—"}</span>
        </div>
      </section>

      <section className="dSection">
        <div className="dTitle">ML classification</div>
        {isBotnet(cid) ? (
          <div className="classBox" style={{ borderLeftColor: clusterColor(cid) }}>
            <div className="clusterTop">
              <b style={{ color: clusterColor(cid) }}>BOTNET-{cid}</b>
              {cluster ? <span className="tag">{clusterTactic(cluster)}</span> : null}
            </div>
            {cluster ? (
              <div className="muted small">
                One of {cluster.ips} IPs sharing the same credential list
                {cluster.top_commands.length ? " and payload" : ""} · {cluster.events} events in total
              </div>
            ) : null}
          </div>
        ) : (
          <div className="classBox" style={{ borderLeftColor: clusterColor(-1) }}>
            <b>Lone scanner</b>
            <div className="muted small">DBSCAN found no other IP behaving like this one (noise).</div>
          </div>
        )}
      </section>

      <section className="dSection">
        <div className="dTitle">Attack sessions</div>
        <ul className="sessions">
          {sessions.slice(0, 12).map((s) => {
            const expanded = open === s.key;
            const t0 = Date.parse(s.events[0]?.sensor_timestamp ?? s.events[0]?.received_at ?? "");
            return (
              <li key={s.key} className={`sessionItem${expanded ? " open" : ""}`}>
                <button className="sessionBtn" onClick={() => setOpen(expanded ? "" : s.key)}>
                  <div className="eventTop">
                    <span className="small">
                      {expanded ? "▾" : "▸"} {clock(s.start)} → {sensorLabel(s.aws_region)}
                    </span>
                    <span className={s.success ? "hot small" : "muted small"}>{s.success ? "breached" : "blocked"}</span>
                  </div>
                  <div className="muted small ellipsis">{summarizeSession(s)}</div>
                </button>
                {expanded ? (
                  <ol className="timeline">
                    {s.session ? (
                      <li className="muted small mono">session {s.session}{s.client ? ` · ${s.client}` : ""}</li>
                    ) : null}
                    {s.events.map((e, i) => {
                      const t = Date.parse(e.sensor_timestamp ?? e.received_at ?? "");
                      const offset = Number.isNaN(t) || Number.isNaN(t0) ? "" : `+${((t - t0) / 1000).toFixed(1)}s`;
                      const hot = e.cowrie_eventid === "cowrie.login.success" || e.command || e.cowrie_eventid === "cowrie.session.file_download";
                      return (
                        <li key={e.event_id ?? i} className="tlRow">
                          <span className="tlTime mono">{offset}</span>
                          <span className={`mono small ${hot ? "hot" : ""}`}>{describeEvent(e)}</span>
                        </li>
                      );
                    })}
                  </ol>
                ) : null}
              </li>
            );
          })}
        </ul>
      </section>

      <details className="dSection raw">
        <summary className="dTitle">Stored record (latest event, as in DynamoDB)</summary>
        <pre className="mono">{JSON.stringify(raw, null, 2)}</pre>
      </details>
    </div>
  );
}
