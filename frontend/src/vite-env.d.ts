/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_MAPBOX_TOKEN?: string;
  /** SAM output HttpApiUrl (no trailing slash), e.g. https://abc123.execute-api.us-east-1.amazonaws.com */
  readonly VITE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
