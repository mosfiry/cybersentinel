// Integration boundary for capabilities whose backend contracts DO NOT
// EXIST yet (verified against bridge.py on main). Each adapter fails loudly
// with ContractNotAvailableError — the UI then renders an explicit
// "backend contract not available" state. NO fake data, NO fake success.
import { ContractNotAvailableError } from "./errors.js";
import { BLOCKED } from "./endpoints.js";

const blocked = (name) => (..._args) => {
  const b = BLOCKED[name];
  throw new ContractNotAvailableError(name, b.missing);
};

export const MissionServiceAdapter = {
  // NOTE: task endpoints exist and are used for real task lifecycle;
  // the *mission* level (scope/target/authorization snapshot per mission)
  // has no backend contract yet.
  listMissions: blocked("missions"),
  createMission: blocked("missions"),
  missionAuthorizationSnapshot: blocked("missions"),
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
  list: blocked("evidence"), get: blocked("evidence"), findByMission: blocked("evidence"),
};

export const FindingsServiceAdapter = {
  list: blocked("findings"),
};

export const SchedulerServiceAdapter = {
  list: blocked("scheduler"), create: blocked("scheduler"), pause: blocked("scheduler"), resume: blocked("scheduler"), cancel: blocked("scheduler"),
};
