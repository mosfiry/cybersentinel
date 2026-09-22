// Owner session flow — built ON TOP of the verified backend contract.
// The frontend is NOT the authority: it sends headers, the backend decides.
// Typing the word "Owner" in the UI grants nothing.
import { post } from "./client.js";
import { runtimeConfig, setOwnerCredentials } from "./config.js";

/**
 * POST /api/owner/session (VERIFIED).
 * Sends the owner token in the X-CyberSentinel-Owner-Token header and stores
 * the returned session id in MEMORY ONLY. 201 => session; 403 => refused.
 */
export async function createOwnerSession(ownerToken) {
  const res = await post("/api/owner/session", {}, {
    headers: { "X-CyberSentinel-Owner-Token": String(ownerToken || "") },
  });
  const session = res.data && res.data.session;
  if (!session || !session.session_id) throw new Error("owner session response missing session_id");
  setOwnerCredentials({ sessionId: session.session_id, challenge: session.challenge || "" });
  return session;
}

export function hasOwnerSession() {
  return Boolean(runtimeConfig.owner.sessionId);
}
