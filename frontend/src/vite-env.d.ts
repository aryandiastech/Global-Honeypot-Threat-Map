/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Mapbox public token (pk.…). Leave empty to run without the globe. */
  readonly VITE_MAPBOX_TOKEN?: string;
  /** Backend base URL, no trailing slash: SAM output HttpApiUrl, or http://localhost:8000 for demo/server.py. Empty = bundled offline snapshot. */
  readonly VITE_API_URL?: string;
  /** Poll interval in ms (default 15000). */
  readonly VITE_POLL_MS?: string;
  /** Events requested per poll (default 200; the AWS read API caps at 100). */
  readonly VITE_EVENTS_LIMIT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
