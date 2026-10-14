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
  /** attack sessions (one attack = connect → logins → commands → disconnect) */
  total_attacks?: number;
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

/** AI/ML verdict for one attack session (ml/attack_analysis.py). */
export type MlLabel = {
  attack_type: string;
  attack_label: string;
  confidence: number;
  runner_up: string;
  explanation: string[];
  severity: "low" | "medium" | "high" | "critical";
  mitre: [string, string][];
  ml_cluster: number;
  pca: [number, number];
};

/** One row of the threat database (GET /attacks). */
export type AttackRow = {
  id: string;
  session?: string | null;
  src_ip: string;
  start: string;
  end: string;
  duration_s: number | null;
  aws_region?: string;
  sensor?: string;
  client_version?: string | null;
  geo_city?: string;
  geo_country?: string;
  geo_country_name?: string;
  geo_org?: string;
  abuse_score?: number;
  login_attempts: number;
  failed_logins: number;
  login_success: boolean;
  success_credential?: string | null;
  credentials_tried: string[];
  commands: string[];
  downloads: number;
  events: number;
  botnet_id?: number | string;
  ml: MlLabel | null;
};

export type AttackTypeInfo = {
  type: string;
  label: string;
  severity: string;
  description: string;
  mitre: [string, string][];
  count: number;
};

export type AnalysisSummary = {
  scanned: boolean;
  scanned_sessions?: number;
  scanned_at?: string;
  model?: {
    classifier: string;
    training_examples: number;
    classes: number;
    loo_accuracy: number;
    clustering: string;
    k: number;
    silhouette: number | null;
    cluster_type_agreement: number | null;
    projection: string;
    features: number;
  };
  timings_ms?: Record<string, number>;
  types: AttackTypeInfo[];
  clusters?: {
    cluster: number;
    size: number;
    dominant_type: string;
    label: string;
    purity: number;
    type_mix: Record<string, number>;
    top_features: string[];
    behaviour: string[];
  }[];
};
