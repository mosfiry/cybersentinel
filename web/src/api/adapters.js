// Integration boundary for capabilities whose backend contracts DO NOT
// EXIST yet (verified against bridge.py on main). Each adapter fails loudly
// with ContractNotAvailableError — the UI then renders an explicit
// "backend contract not available" state. NO fake data, NO fake success.
// Mission endpoints now EXIST and are consumed via api/missions.js and
// api/conversation.js (chat stream + mission lifecycle) — the MissionService
// adapter was removed rather than left throwing for a real contract.
import { ContractNotAvailableError } from "./errors.js";
import { BLOCKED } from "./endpoints.js";

const blocked = (name) => (..._args) => {
  const b = BLOCKED[name];
  throw new ContractNotAvailableError(name, b.missing);
};

export const WorkspaceServiceAdapter = {
  tree: blocked("workspaceTree"),
  readFile: blocked("workspaceFile"),
  writeFile: blocked("workspaceFile"),
  createEntry: blocked("workspaceFile"),
  renameEntry: blocked("workspaceFile"),
  deleteEntry: blocked("workspaceFile"),
  searchWorkspace: blocked("workspaceFile"),
};

export const TerminalServiceAdapter = {
  // /api/command exists for one-shot authorized command submission; a real
  // interactive terminal session (streaming stdout/stderr + cancel by
  // execution id) has no dedicated contract yet.
  openSession: blocked("terminal"),
};

export const GitServiceAdapter = {
  status: blocked("git"), diff: blocked("git"), branches: blocked("git"), commits: blocked("git"),
};

export const EvidenceServiceAdapter = {
  // Mission-scoped evidence IS available: GET /api/missions/{id}/evidence.
  // A generic evidence listing contract is not.
  list: blocked("evidence"), get: blocked("evidence"),
};

export const FindingsServiceAdapter = {
  list: blocked("findings"),
};

export const SchedulerServiceAdapter = {
  // POST /api/missions/{id}/schedule exists, but no schedule listing/management
  // contract — the UI does not invent a scheduler view around half a contract.
  list: blocked("scheduler"), create: blocked("scheduler"), pause: blocked("scheduler"), resume: blocked("scheduler"), cancel: blocked("scheduler"),
};
