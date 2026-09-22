// Runtime configuration. The bridge token is held in MEMORY ONLY.
// It is never written to localStorage, sessionStorage, cookies, or the
// JS bundle. It is provided at runtime by the Owner (e.g. paste-once
// prompt) and is lost on reload by design.
export const runtimeConfig = {
  baseUrl: (globalThis.__CYBERSENTINEL_BASE_URL__ || "").replace(/\/$/, ""),
  bridgeToken: "",
  owner: { token: "", sessionId: "", challenge: "" },
};

/** Set the bridge token for this page session (memory only). */
export function setBridgeToken(token) {
  runtimeConfig.bridgeToken = String(token || "");
}

/** Set owner credentials for this page session (memory only). */
export function setOwnerCredentials({ token, sessionId, challenge } = {}) {
  if (token !== undefined) runtimeConfig.owner.token = String(token || "");
  if (sessionId !== undefined) runtimeConfig.owner.sessionId = String(sessionId || "");
  if (challenge !== undefined) runtimeConfig.owner.challenge = String(challenge || "");
}

export function clearCredentials() {
  runtimeConfig.bridgeToken = "";
  runtimeConfig.owner = { token: "", sessionId: "", challenge: "" };
}

export function isConfigured() {
  return Boolean(runtimeConfig.baseUrl && runtimeConfig.bridgeToken);
}
