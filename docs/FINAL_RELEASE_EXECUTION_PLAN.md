# CyberSentinel Final Release — Execution Plan and Baseline

- **Mission:** CS-FINAL-RELEASE-20261003
- **Release work branch:** `release/cybersentinel-final-20261003`
- **Starting SHA:** `14810a57338bc0aec9021f08279502919fccb39f` (`task/m3-production-runtime-20261003`)

## Source baseline

The repository was cloned from `https://github.com/mosfiry/cybersentinel`. The observed `main` head is `8a3fd109c0e586db13ed48a7371ac9ad06465b74`; it is an ancestor of the M3 head, not a later production-runtime baseline. The observed M3 head is `14810a57338bc0aec9021f08279502919fccb39f`, the branch named in the mission. Release work is based on that M3 SHA to retain its worker lifecycle, durable generations and leases, execution fencing, Owner revalidation, effect ledger, reconciliation, and Compose runtime. `main` and all Vibe/Desktop branches remain outside the write scope.

At the exact M3 SHA, GitHub Actions `tests` run [37150345208](https://github.com/mosfiry/cybersentinel/actions/runs/37150345208) completed successfully. Its `test (3.13)` job passed dependency installation, compileall, pytest, hosted container build/smoke, diff hygiene, and secret/sensitive-file checks. Its separate M3 non-production cutover rehearsal job passed. The Owner Charter inventory workflow [37150345216](https://github.com/mosfiry/cybersentinel/actions/runs/37150345216) also completed successfully. These results are evidence for that SHA only, not for this release branch or a public production deployment.

## Local baseline and environment

- On `main` at `8a3fd109c0e586db13ed48a7371ac9ad06465b74`, after installing the repository-declared requirements into an external temporary virtual environment: `compileall` passed; pytest reported **704 passed, 1 skipped**.
- On M3 at the starting SHA: `compileall` passed; the full pytest suite reported **1,072 passed, 1 skipped** on the successful repeat. The first full run had one transient process-identity assertion failure (1,071 passed, 1 failed, 1 skipped); the affected process-death test then passed 20 isolated repetitions, and the subsequent full run passed. This observation is retained rather than silently erased.
- The initial system Python lacked pytest; the declared requirements were installed only into `/tmp/cybersentinel-release-venv`, outside the repository.
- This computer has no Docker, Podman, or nerdctl executable and no container-engine socket. No local Compose execution is claimed. M3's exact-SHA hosted CI did execute its container smoke and non-production rehearsal; release-branch container claims must wait for its own hosted CI evidence.
- No configured application provider credentials or live-provider authorization were established by this baseline. Provider failure/idempotency work will use deterministic simulations unless a permitted, cost-safe app provider is concretely available; no provider call is inferred from the existing CI.

## Source-grounded findings to verify and close

M3 already contains `Dockerfile`, `compose.yaml`, `scripts/run_mission_worker.py`, `agent/runtime_supervisor.py`, Owner password/session controls, mission/queue fencing, an external-effect ledger, reconciliation, evidence-chain integrity, and process-death/multi-worker tests. Its Compose target is a single-host self-hosted runtime with a persistent named volume, non-root UID, read-only root filesystem, dropped capabilities, loopback-published bridge, health checks, and a separate worker.

The source and operations material do not establish a tested backup/restore or schema-upgrade workflow: operations instruct the operator to use external approved volume backup tooling and rehearse restoration, while the repository search did not find runnable backup/restore/upgrade scripts or a migration-version gate. M3's own final audit identifies limitations around recurring unattended Owner delegation, universal cross-store atomicity, live-provider idempotency, production monitoring/rollback/HA, production deployment authority, and a local Docker engine. These are leads for direct implementation and tests, not assumed final conclusions; each will be inspected against code and closed where technically and operationally supportable. Any Cloudflare-only issue is `OUT OF SCOPE — IGNORED BY DESIGN` and will not be investigated or made a release dependency.

No credentials, public server, production database, external target, or deployment authority were added or inferred. The final release tag and publication are excluded until the V14 release gate is actually verified and the user has separately confirmed the exact tag and artifacts.

## Stage sequence

Every stage follows `INSPECT → IMPLEMENT → TEST → BREAK → RECOVER → HARDEN → CHECKPOINT → CI → VERIFY`. A stage does not advance until its change is committed and pushed on this branch and the exact-SHA CI outcome is reconciled.

| Stage | Scope |
|---|---|
| V0 | Actual source baseline, test/CI evidence, and release plan; no production-code changes. |
| V1 | Runtime startup/shutdown, worker lifecycle, health/readiness, persistent state, and configuration. |
| V2 | Owner authentication, sessions, authorization snapshots, restart reauthorization, scheduling, and resume. |
| V3 | Generation/lease/worker/queue/mission/evidence/effect fencing and multi-worker races. |
| V4 | Transactions or explicit durable intent/recovery protocol across stores and crash consistency. |
| V5 | External-effect state, ambiguity, reconciliation, and duplicate prevention. |
| V6 | Provider/tool abstraction, timeout/retry/unknown behavior, and supported local/OpenAI-compatible providers. |
| V7 | Evidence provenance/integrity and truthful reporting of partial, unknown, and recovery-required states. |
| V8 | Security boundaries and regression tests; preserve the existing authority model and defenses. |
| V9 | Complete mission path and failure/crash/restart/recovery/resume end-to-end verification. |
| V10 | Chaos, crash, race, and multi-worker failure/recovery tests. |
| V11 | Hardened self-hosted Docker Compose deployment and operational configuration. |
| V12 | Clean-environment install, mission lifecycle, backup/restore, and upgrade rehearsal. |
| V13 | Verifiable distribution artifacts, checksums, setup/backup/restore/upgrade material, and release notes. |
| V14 | Full release gate, final audit, exact-SHA CI, and a separate user-confirmed release/tag decision. |

## Checkpoint ledger

| Stage | Checkpoint / verification | Status |
|---|---|---|
| V0 | Commit `86ef8f4bfe5da93ae7b35c939749d62343cc918a`; source baseline and staged release plan. | Pushed; exact-SHA CI passed (run `37151975771`). |
| V1 | Commit `4f94ccb9760362eeb39ab82d82fe40c257b9066f`; authenticated readiness probe, bridge lifecycle integration tests, and operations documentation. | Pushed; exact-SHA CI passed (run [37152396766](https://github.com/mosfiry/cybersentinel/actions/runs/37152396766)), including pytest, hosted container build/smoke, hygiene, and sensitive-file scan. |
| V2 | Commit `8934280d1839f13c01974906fc6106201be8e9d0`; Owner reauthorization, restart quarantine, one-shot scheduler boundaries and resume were source-audited. Focused tests: **49 passed**. `compileall` passed; full local suite: **1,077 passed, 1 skipped**. This checkpoint documents verified existing implementation; no authorization behavior was broadened. | Pushed; exact-SHA `tests` CI passed (run [37152890871](https://github.com/mosfiry/cybersentinel/actions/runs/37152890871)), including pytest, hosted container build/smoke, diff hygiene, and sensitive-file scan. Owner Charter audit passed (run [37152890883](https://github.com/mosfiry/cybersentinel/actions/runs/37152890883)); non-production cutover rehearsal passed. |

## V2 authorization boundary and evidence

Owner identity and policy proof are rebound to a fresh server-side session before queueing or resuming. Restarted nonterminal work is moved to `OWNER_REAUTH_REQUIRED`/`NEEDS_INPUT`; ambiguous in-flight effects remain in `RECOVERY_REQUIRED` until reconciled. Scheduled dispatch checks the exact mission/Owner/snapshot hash, version, expiry, live Owner session and account state, and mission readiness; stale, revoked, expired, or mismatched authority is quarantined before queue promotion. Existing isolated V13 E2E tests perform a test-only username/password login over the loopback bridge and exercise expired-session denial, worker restart, and Owner reconciliation.

Recurring execution and scheduled retries are intentionally rejected by both the service and scheduler, with regression tests. The Owner policy does not authorize unattended recurring delegation; the user-provided scheduler requirements say that when unattended execution is not permitted, the mission must stop in an Owner-input/reauthorization state rather than execute. Therefore no recurring grant or automatic high-risk approval is inferred here. A previously valid scheduled mission is not resurrected after restart; fresh Owner reauthorization is required. This is a documented fail-closed boundary, not an unverified capability.

**No final release tag is to be created by this plan.** V14 will stop for a separate confirmation containing the exact proposed tag and artifacts if and only if all release gates are evidenced.
