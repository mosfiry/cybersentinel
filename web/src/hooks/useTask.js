import { useEffect, useState, useCallback } from "react";
import { getTask, controlTask } from "../api/tasks.js";
import { ApiError } from "../api/errors.js";
import { mapTaskState } from "../state/lifecycle.js";

/** Fetch + refresh a verified task snapshot. Errors are surfaced, never swallowed. */
export function useTask(taskId) {
  const [task, setTask] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(Boolean(taskId));

  const refresh = useCallback(async () => {
    if (!taskId) return;
    setLoading(true);
    try {
      const data = await getTask(taskId);
      setTask(data.task || data);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError("server", 0, String(e && e.message || e)));
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  useEffect(() => { refresh(); }, [refresh]);
  return { task, state: mapTaskState(task), error, loading, refresh,
    control: (action) => controlTask(taskId, action).then(() => refresh()) };
}
