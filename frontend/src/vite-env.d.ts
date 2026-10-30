/// <reference types="vite/client" />

// Backend base URL. Leave unset to let the app pick automatically:
// the Vite dev server targets http://localhost:8000, while a production build
// served by the FastAPI backend calls its own origin (works on any LAN host).
// Set it only to pin an explicit backend, e.g. http://192.168.1.25:8000
interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
