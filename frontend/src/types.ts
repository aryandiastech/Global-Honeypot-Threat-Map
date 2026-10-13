/** One row of the events table, as returned by GET /events (AWS read API or local demo). */
export type RemoteEvent = {
  event_id?: string;
  received_at?: string;
  sensor_timestamp?: string;
  src_ip?: string;
  cowrie_eventid?: string;
  s3_key?: string;
  line_index?: number;
  aws_region?: string;
  sensor?: string;
  session?: string;
  username?: string;
  password?: string;
  command?: string;
  client_version?: string;
  // enrichment (enrich Lambda / local demo intel table)
  geo_lat?: number;
  geo_lon?: number;
  geo_city?: string;
  geo_country?: string;
  geo_country_name?: string;
  geo_org?: string;
  abuse_score?: number;
  abuse_total_reports?: number;
  // ML (cluster Lambda)
  cluster_id?: number | string;
};

export type ClusterSummary = {
  cluster_id: number;
  ips: number;
  events: number;
  top_credentials: string[];
  top_commands: string[];
  ssh_clients?: string[];
};

export type Stats = {
  total_events: number;
  unique_attackers: number;
  countries: number;
  login_success: number;
  login_failed: number;
  botnets: number;
  top_countries: [string, number][];
  top_credentials: [string, number][];
  top_commands: [string, number][];
  events_by_sensor: [string, number][];
  /** index 0 = last hour */
  events_last_24h?: number[];
  clusters: ClusterSummary[];
  cluster_engine?: string;
};

/** Where the dashboard's data came from. */
export type FeedSource = "aws" | "local-demo" | "snapshot" | "none";

/** Live attack simulation status (local demo backend only). */
export type SimulationStatus = {
  running: boolean;
  min_interval: number;
  max_interval: number;
  attacks: number;
  started_at: string | null;
  next_attack_at: string | null;
  last_attack: {
    src_ip?: string;
    session?: string;
    aws_region?: string;
    geo_city?: string;
    geo_country?: string;
    at?: string;
  } | null;
};

/** One attack = one Cowrie session (connect → logins → commands → close). */
export type AttackSession = {
  key: string;
  session?: string;
  src_ip: string;
  start: string;
  end: string;
  aws_region?: string;
  sensor?: string;
  client?: string;
  failed: number;
  success: boolean;
  credential?: string;
  commands: string[];
  downloads: number;
  cluster_id?: number | string;
  /** representative row (carries geo / reputation fields) */
  head: RemoteEvent;
  /** oldest → newest */
  events: RemoteEvent[];
};
