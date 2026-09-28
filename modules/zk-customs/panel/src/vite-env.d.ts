/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SERVICE_ROLE: 'ministry' | 'broker';
  readonly VITE_AGENT_BASE_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
