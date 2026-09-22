// Unified API client over the VERIFIED bridge.py contract.
// Rules enforced here:
//  * one place builds requests (no scattered fetch calls)
//  * request id + timeout + cancellation on every call
//  * HTTP status mapping to typed errors
//  * success requires HTTP 2xx AND (when present) body.ok === true —
//    a bare 200 with ok:false is a FAILURE, never a fake success
import { runtimeConfig } from "./config.js";
import { ApiError, ErrorKind } from "./errors.js";
import { newRequestId } from "./util.js";

const DEFAULT_TIMEOUT_MS = 15000;

function authHeaders(extra = {}) {
  const h = { ...extra };
  if (runtimeConfig.bridgeToken) h["X-CyberSentinel-Token"] = runtimeConfig.bridgeToken;
  const o = runtimeConfig.owner;
  if (o.token) h["X-CyberSentinel-Owner-Token"] = o.token;
  if (o.sessionId) h["X-CyberSentinel-Owner-Session"] = o.sessionId;
  if (o.challenge) h["X-CyberSentinel-Owner-Challenge"] = o.challenge;
  return h;
}

export async function request(method, path, { body, headers, timeoutMs = DEFAULT_TIMEOUT_MS, signal, requestId } = {}) {
  const rid = requestId || newRequestId();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new ApiError(ErrorKind.TIMEOUT, 0, "request timeout", rid)), timeoutMs);
  const onOuterAbort = () => ctrl.abort(signal && signal.reason);
  if (signal) signal.addEventListener("abort", onOuterAbort, { once: true });

  let res, data;
  try {
    res = await fetch(runtimeConfig.baseUrl + path, {
      method,
      headers: authHeaders({ ...(body !== undefined ? { "Content-Type": "application/json" } : {}), "X-Request-Id": rid, ...headers }),
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
      credentials: "omit",
      cache: "no-store",
    });
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(ErrorKind.NETWORK, 0, "network error: " + (e && e.message || "unreachable"), rid);
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onOuterAbort);
  }

  const text = await res.text();
  try { data = text ? JSON.parse(text) : {}; }
  catch { throw new ApiError(ErrorKind.VALIDATION, res.status, "response is not valid JSON", rid); }

  if (res.status === 401) throw new ApiError(ErrorKind.UNAUTHORIZED, res.status, data.error || "bridge authentication required", rid);
  if (res.status === 403) throw new ApiError(ErrorKind.FORBIDDEN, res.status, data.error || "forbidden", rid);
  if (res.status === 404) throw new ApiError(ErrorKind.NOT_FOUND, res.status, data.error || "not_found", rid);
  if (res.status === 413) throw new ApiError(ErrorKind.VALIDATION, res.status, "request_too_large", rid);
  if (res.status >= 500) throw new ApiError(ErrorKind.SERVER, res.status, data.error || "server error", rid);
  if (res.status >= 400) throw new ApiError(ErrorKind.VALIDATION, res.status, data.error || "bad request", rid);
  if (data && data.ok === false) throw new ApiError(ErrorKind.VALIDATION, res.status, data.error || "ok:false from backend", rid);
  return { data, requestId: rid, status: res.status };
}

export async function get(path, opts) { return request("GET", path, opts); }
export async function post(path, body, opts) { return request("POST", path, { ...opts, body }); }
