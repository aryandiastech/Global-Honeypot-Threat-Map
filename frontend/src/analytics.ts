import type { AttackSession, ClusterSummary, RemoteEvent, Stats } from "./types";

const PALETTE = ["#ff595e", "#ffca3a", "#8ac926", "#1982c4", "#c77dff", "#f15bb5", "#00bbf9", "#ff924c"];
export const NOISE_COLOR = "#5b8def";

export const isBotnet = (id: RemoteEvent["cluster_id"]) =>
  id !== undefined && id !== null && id !== "" && Number(id) !== -1 && !Number.isNaN(Number(id));

/** Stable colour per cluster id (noise / unclustered = muted blue). */
export const clusterColor = (id: RemoteEvent["cluster_id"]) =>
  isBotnet(id) ? PALETTE[Number(id) % PALETTE.length] : NOISE_COLOR;

/** Human tag for a cluster, inferred from what its members actually did. */
export function clusterTactic(c: Pick<ClusterSummary, "top_credentials" | "top_commands">): string {
  const cmds = c.top_commands.join(" ").toLowerCase();
  if (cmds.includes("authorized_keys")) return "SSH-key backdoor";
  if (cmds.includes("busybox") || cmds.includes("enable")) return "IoT worm (Mirai-like)";
  if (cmds.includes("wget") || cmds.includes("curl")) return "Malware dropper";
  if (cmds.length > 0) return "Brute-force + recon";
  if (c.top_credentials.length > 0) return "Credential brute-force";
  return "Port / banner scanner";
}

/** Two-letter country code for display (flag emojis don't render on Windows). */
export const countryCode = (cc?: string) => (cc && /^[A-Za-z]{2,3}$/.test(cc) ? cc.toUpperCase() : "??");

export function describeEvent(e: RemoteEvent): string {
  switch (e.cowrie_eventid) {
    case "cowrie.login.failed":
      return `login failed  ${e.username ?? ""} / ${e.password ?? ""}`;
    case "cowrie.login.success":
      return `LOGIN OK  ${e.username ?? ""} / ${e.password ?? ""}`;
    case "cowrie.command.input":
      return `$ ${e.command ?? ""}`;
    case "cowrie.session.connect":
      return "connection opened";
    case "cowrie.session.closed":
      return "connection closed";
    case "cowrie.client.version":
      return `client ${e.client_version ?? ""}`;
    case "cowrie.session.file_download":
      return "file download (payload)";
    default:
      return e.cowrie_eventid?.replace(/^cowrie\./, "") ?? "event";
  }
}

export function timeAgo(iso?: string): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const top = (m: Map<string, number>, n: number): [string, number][] =>
  [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);

const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);

/**
 * Aggregate stats from the events we have. Used when the backend has no /stats
 * endpoint (the AWS read API only serves /events).
 */
export function computeStats(events: RemoteEvent[]): Stats {
  const ips = new Map<string, RemoteEvent>();
  const countries = new Map<string, number>();
  const creds = new Map<string, number>();
  const cmds = new Map<string, number>();
  const sensors = new Map<string, number>();
  const clusters = new Map<number, { ips: Set<string>; events: number; creds: Map<string, number>; cmds: Map<string, number> }>();
  let ok = 0;
  let failed = 0;

  for (const e of events) {
    if (e.src_ip && !ips.has(e.src_ip)) {
      ips.set(e.src_ip, e);
      bump(countries, e.geo_country_name ?? e.geo_country ?? "Unknown");
    }
    if (e.cowrie_eventid === "cowrie.login.success") ok++;
    if (e.cowrie_eventid === "cowrie.login.failed") failed++;
    if (e.cowrie_eventid?.startsWith("cowrie.login.") && (e.username || e.password)) {
      bump(creds, `${e.username ?? ""}:${e.password ?? ""}`);
    }
    if (e.command) bump(cmds, e.command);
    bump(sensors, e.aws_region || "unknown");

    if (isBotnet(e.cluster_id)) {
      const id = Number(e.cluster_id);
      const c = clusters.get(id) ?? { ips: new Set(), events: 0, creds: new Map(), cmds: new Map() };
      c.events++;
      if (e.src_ip) c.ips.add(e.src_ip);
      if (e.username || e.password) bump(c.creds, `${e.username ?? ""}:${e.password ?? ""}`);
      if (e.command) bump(c.cmds, e.command);
      clusters.set(id, c);
    }
  }

  const clusterList: ClusterSummary[] = [...clusters.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([id, c]) => ({
      cluster_id: id,
      ips: c.ips.size,
      events: c.events,
      top_credentials: top(c.creds, 3).map(([k]) => k),
      top_commands: top(c.cmds, 2).map(([k]) => k),
    }));

  return {
    total_events: events.length,
    unique_attackers: ips.size,
    countries: countries.size,
    login_success: ok,
    login_failed: failed,
    botnets: clusterList.length,
    top_countries: top(countries, 8),
    top_credentials: top(creds, 8),
    top_commands: top(cmds, 6),
    events_by_sensor: top(sensors, 10),
    clusters: clusterList,
  };
}

const eventTime = (e: RemoteEvent) => e.sensor_timestamp ?? e.received_at ?? "";

/**
 * Group raw events into attack sessions, newest first. Cowrie tags every event with a
 * session id; rows without one fall back to (ip, minute).
 */
export function groupSessions(events: RemoteEvent[]): AttackSession[] {
  const byKey = new Map<string, RemoteEvent[]>();
  for (const e of events) {
    if (!e.src_ip) continue;
    const key = `${e.src_ip}|${e.session ?? (e.received_at ?? "").slice(0, 16)}`;
    const list = byKey.get(key);
    if (list) list.push(e);
    else byKey.set(key, [e]);
  }
  const sessions: AttackSession[] = [];
  for (const [key, list] of byKey) {
    const ordered = [...list].sort((a, b) => eventTime(a).localeCompare(eventTime(b)));
    const success = ordered.find((e) => e.cowrie_eventid === "cowrie.login.success");
    const head = ordered.find((e) => typeof e.geo_lat === "number") ?? ordered[0];
    const latest = list.reduce((m, e) => ((e.received_at ?? "") > (m.received_at ?? "") ? e : m), list[0]);
    sessions.push({
      key,
      session: head.session,
      src_ip: head.src_ip!,
      start: ordered[0].received_at ?? "",
      end: latest.received_at ?? "",
      aws_region: head.aws_region,
      sensor: head.sensor,
      client: ordered.find((e) => e.client_version)?.client_version,
      failed: ordered.filter((e) => e.cowrie_eventid === "cowrie.login.failed").length,
      success: Boolean(success),
      credential: success ? `${success.username ?? ""} / ${success.password ?? ""}` : undefined,
      commands: ordered.filter((e) => e.command).map((e) => e.command!),
      downloads: ordered.filter((e) => e.cowrie_eventid === "cowrie.session.file_download").length,
      cluster_id: latest.cluster_id,
      head,
      events: ordered,
    });
  }
  return sessions.sort((a, b) => b.end.localeCompare(a.end) || b.start.localeCompare(a.start));
}

export function summarizeSession(s: AttackSession): string {
  const parts: string[] = [];
  if (s.failed) parts.push(`${s.failed} failed login${s.failed > 1 ? "s" : ""}`);
  if (s.success) parts.push(`cracked ${s.credential}`);
  if (s.commands.length) parts.push(`${s.commands.length} command${s.commands.length > 1 ? "s" : ""}`);
  if (s.downloads) parts.push("payload download");
  return parts.join(" · ") || "port scan / banner grab";
}
