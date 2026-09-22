import { ApiError, ContractNotAvailableError } from "../api/errors.js";

/**
 * First-class error surface. Renders kind, message, remediation and request
 * id WITHOUT leaking secrets. Contract-blocked capabilities render an
 * explicit "backend contract not available" state — never fake success.
 */
export function ErrorState({ error, onRetry }) {
  if (!error) return null;
  const contract = error instanceof ContractNotAvailableError;
  const title = contract ? "Backend contract not available"
    : error.kind === "unauthorized" ? "Bridge authentication required"
    : error.kind === "forbidden" ? "Operation refused by backend"
    : error.kind === "network" ? "Backend unreachable"
    : error.kind === "timeout" ? "Request timed out"
    : "Request failed";
  return (
    <div className="rounded border border-rose-500/40 bg-rose-500/5 p-3 text-xs" role="alert">
      <div className="mb-1 font-semibold text-rose-200">{title}</div>
      <div className="text-slate-300">{error.message}</div>
      {error instanceof ApiError && <div className="mt-1 text-slate-400">Action: {error.remediation()}</div>}
      {error.requestId && <div className="mt-1 font-mono text-[10px] text-slate-500">request_id: {error.requestId}</div>}
      {contract && (
        <div className="mt-1 text-slate-400">
          Missing endpoint: <span className="font-mono">{error.missing}</span> — tracked in docs/WEB_API_REQUIREMENTS.md.
        </div>
      )}
      {onRetry && !contract && (
        <button onClick={onRetry} className="mt-2 rounded border border-slate-600 px-2 py-0.5 text-[11px] text-slate-200 hover:bg-slate-800">
          Retry
        </button>
      )}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }) {
  return <div className="p-4 text-xs text-slate-400" role="status">{label}</div>;
}

export function EmptyState({ title, hint }) {
  return (
    <div className="p-6 text-center text-xs text-slate-500">
      <div className="mb-1 text-slate-300">{title}</div>{hint}
    </div>
  );
}
