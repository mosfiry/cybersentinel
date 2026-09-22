import { describe, it, expect } from "vitest";
import { MissionServiceAdapter, WorkspaceServiceAdapter, TerminalServiceAdapter,
         GitServiceAdapter, EvidenceServiceAdapter, FindingsServiceAdapter,
         SchedulerServiceAdapter } from "../src/api/adapters.js";
import { ContractNotAvailableError, ApiError, ErrorKind } from "../src/api/errors.js";

describe("contract-blocked adapters", () => {
  it("fail loudly — never fake success", () => {
    const calls = [
      () => MissionServiceAdapter.listMissions(),
      () => WorkspaceServiceAdapter.tree(),
      () => TerminalServiceAdapter.openSession(),
      () => GitServiceAdapter.status(),
      () => EvidenceServiceAdapter.list(),
      () => FindingsServiceAdapter.list(),
      () => SchedulerServiceAdapter.list(),
    ];
    for (const fn of calls) {
      expect(fn).toThrow(ContractNotAvailableError);
      try { fn(); } catch (e) {
        expect(e.kind).toBe(ErrorKind.CONTRACT);
        expect(e.missing).toMatch(/api/i);
      }
    }
  });
});

describe("ApiError remediation", () => {
  it("gives human remediation without secrets", () => {
    expect(new ApiError(ErrorKind.UNAUTHORIZED, 401, "x").remediation()).toContain("Bridge");
    expect(new ApiError(ErrorKind.CONTRACT, 0, "x").remediation()).toContain("WEB_API_REQUIREMENTS");
  });
});
