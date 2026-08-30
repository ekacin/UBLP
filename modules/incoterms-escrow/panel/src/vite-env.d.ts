/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AGENT_BASE_URL: string;
  readonly VITE_INDEXER_WS_URL: string;
  readonly VITE_NETWORK_ID: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
