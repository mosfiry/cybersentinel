import { useEffect, useRef } from "react";
import { EventTransport, TransportStatus } from "../events/EventTransport.js";
import { openTaskStream } from "../api/tasks.js";

/**
 * Live task event stream over the VERIFIED SSE endpoint.
 * onResync re-fetches the task snapshot after every reconnect so the UI
 * reconciles instead of assuming the last event arrived.
 */
export function useEventStream(taskId, { onEvent, onStatus, onResync } = {}) {
  const transportRef = useRef(null);
  useEffect(() => {
    if (!taskId) return;
    const transport = new EventTransport({
      openStream: () => openTaskStream(taskId),
      onEvent: onEvent || (() => {}),
      onStatus: onStatus || (() => {}),
      onResync: onResync || null,
    });
    transportRef.current = transport;
    transport.start();
    return () => { transport.stop(); transportRef.current = null; };
  }, [taskId]);
  return transportRef;
}
