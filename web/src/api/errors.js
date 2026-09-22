export const ErrorKind = Object.freeze({
  UNAUTHORIZED: "unauthorized",   // 401: bridge/owner auth missing or wrong
  FORBIDDEN: "forbidden",         // 403: backend refused the operation
  NOT_FOUND: "not_found",         // 404
  TIMEOUT: "timeout",
  NETWORK: "network",             // backend unreachable / disconnected
  VALIDATION: "validation",      // bad payload or ok:false
  SERVER: "server",               // 5xx
  CONTRACT: "contract",          // endpoint does not exist in backend yet
});

export class ApiError extends Error {
  constructor(kind, status, message, requestId) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.requestId = requestId;
  }
  /** Human-facing remediation hint WITHOUT leaking secrets. */
  remediation() {
    switch (this.kind) {
      case ErrorKind.UNAUTHORIZED: return "Bridge authentication missing or rejected. Set the bridge token for this session.";
      case ErrorKind.FORBIDDEN: return "The backend refused this operation (owner authorization, scope, or policy).";
      case ErrorKind.NETWORK: return "Backend unreachable. Check connection and base URL; events will resync on reconnect.";
      case ErrorKind.CONTRACT: return "This capability needs a backend endpoint that does not exist yet (see docs/WEB_API_REQUIREMENTS.md).";
      default: return "Request failed. Retry or inspect the request id in backend logs.";
    }
  }
}

/** Thrown when the UI attempts to use a capability whose backend contract is not implemented. */
export class ContractNotAvailableError extends ApiError {
  constructor(capability, missing) {
    super(ErrorKind.CONTRACT, 0, "backend contract not available: " + capability + " requires " + missing, null);
    this.capability = capability;
    this.missing = missing;
  }
}
