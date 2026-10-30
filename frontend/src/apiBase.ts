// Backend base URL resolution shared by the axios client, the chat stream
// fetch, and the sidebar display.
//
// - VITE_API_URL set: that value is used verbatim (pin an explicit backend,
//   e.g. http://192.168.1.25:8000).
// - VITE_API_URL unset in dev: the Vite dev server talks to localhost:8000.
// - VITE_API_URL unset in a production build: an empty base means "same
//   origin", so the dashboard served by the FastAPI backend keeps working
//   from any LAN host or port without being rebuilt.
export const API_BASE_URL: string =
  import.meta.env.VITE_API_URL ?? (import.meta.env.DEV ? 'http://localhost:8000' : '');

// Readable backend address for the sidebar. Falls back to the page origin when
// running same-origin, where API_BASE_URL is intentionally empty.
export const API_DISPLAY_URL: string =
  API_BASE_URL || (typeof window !== 'undefined' ? window.location.origin : '');
