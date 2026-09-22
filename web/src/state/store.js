// Minimal, dependency-free state store with reducer discipline.
// Separation of concerns:
//   server state  -> task snapshots from the backend (source of truth)
//   event state   -> deduped stream events (append-only, bounded)
//   ui state      -> layout/tabs/panels (not persisted server-side)
// No mock state is ever merged into server state.
export function createStore(initial, reducer) {
  let state = initial;
  const listeners = new Set();
  return {
    getState: () => state,
    dispatch(action) {
      const next = reducer(state, action);
      if (next !== state) { state = next; for (const l of listeners) l(state, action); }
    },
    subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
  };
}

export const initialRuntimeState = {
  connection: "DISCONNECTED",      // EventTransport status
  task: null,                      // latest verified task snapshot
  taskError: null,                 // {kind, message, remediation, requestId}
  events: [],                      // bounded append-only stream events
  requests: {},                    // request_id -> lifecycle snapshot
};

const MAX_EVENTS = 2000;

export function runtimeReducer(state, action) {
  switch (action.type) {
    case "connection/status":
      return { ...state, connection: action.status };
    case "task/snapshot":
      return { ...state, task: action.task, taskError: null };
    case "task/error":
      return { ...state, taskError: action.error, task: action.task || null };
    case "event/received":
      return { ...state, events: [...state.events, action.event].slice(-MAX_EVENTS) };
    case "request/snapshot":
      return { ...state, requests: { ...state.requests, [action.requestId]: action.record } };
    default:
      return state;
  }
}
