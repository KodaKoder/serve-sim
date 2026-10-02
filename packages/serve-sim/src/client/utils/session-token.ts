// The per-session token the server injects into the preview page (and nowhere
// else). Every request that changes state has to present it.

export function sessionToken(): string {
  return (typeof window === "undefined" ? undefined : window.__SIM_PREVIEW__?.execToken) ?? "";
}

/** Headers for a JSON request to one of the server's token-gated routes. */
export function authHeaders(): Record<string, string> {
  return { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken()}` };
}

/** Browsers can't set headers on a WebSocket upgrade, so sockets carry the token in the URL. */
export function withSessionToken(url: string): string {
  const token = sessionToken();
  if (!token) return url;
  return `${url}${url.includes("?") ? "&" : "?"}token=${encodeURIComponent(token)}`;
}
