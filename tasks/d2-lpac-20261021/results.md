# D2 checkpoint: native failure reproduced, backend remains blocked

**Overall D2/Mission status: BLOCKED. Investigation: PARTIALLY VERIFIED.** The precise missing Windows object is still unknown. No production sandbox backend was enabled and no security policy was relaxed.

## Saved work and tested revision

Diagnostic commit: [`feeb6236c70520931bb9e92c022b517aef77dd58`](https://github.com/mosfiry/cybersentinel/commit/feeb6236c70520931bb9e92c022b517aef77dd58), on `fix/blocker-d2-lpac-20261021`, directly based on D4 `77515ed87435b051faf0d16a04ee89246eeff1aa`.

Changes are limited to failure-only native-probe diagnostics, three portable source guards, and allowing this exact D2 branch through the unchanged strict Windows contract gate. The existing workflow source assertion was updated to the exact two-branch allowlist. No production launcher, fallback, AppContainer profile, capability grant, ACL grant, MissionRuntime, ToolRegistry, or D4 verifier change was made. The documentation checkpoint containing this record is not a newly tested native executable revision; the native evidence below belongs specifically to `feeb623`.

The backend design and acceptance plan are in [the investigation report](../../docs/architecture/D2_LPAC_ROOT_CAUSE_2026-10-21_AR.md).

## Windows: direct native evidence

[Windows contract run 39579691012](https://github.com/mosfiry/cybersentinel/actions/runs/39579691012), attempt 1, tested `feeb623`:

| Job | Actual result | What it proves |
|---|---|---|
| AppContainer workspace | **FAIL: 4 failed, 17 passed** | All four original native LPAC tests still fail at CreateProcessW; no child isolation acceptance |
| Job lifecycle / governed refusal | **PASS: 19 native tests** | Trusted-harness lifecycle and fail-closed refusal only |
| Fixed-capacity VHD | **PASS: 6 native tests**, gate PASS | Fixed-capacity storage primitive only |

The LPAC/VHD artifact reports Windows `10.0.26100`, image `win25-vs2026`, version `20261007.264.1`. The separate Job-contract artifact reports image version `20261018.275.1`; these are separate runners, not evidence of a single combined LPAC+Job+VHD environment.

MSVC `/W4 /WX /MT` successfully built and ran the trusted probe far enough to reach CreateProcessW. Each failed launch reported:

```json
{"version":1,"win32_error":2,"image_is_file":true,"image_attributes_error":0,"cwd_is_directory":true,"cwd_attributes_error":0,"module_matches_image":true,"ntstatus_available":true,"ntstatus_advisory":"0xC000000F"}
```

The system message was **“The system cannot find the file specified.”** The launcher exits 20 by design; it is not a child exit code. `0xC000000F` is [STATUS_NO_SUCH_FILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55), but the last NTSTATUS is explicitly advisory and may not identify the causal internal operation.

These observations narrow the investigation: the broker sees a real executable matching its own running module and an existing working directory after failure. They do **not** prove LPAC access to that executable, rule out a race at the precise syscall instant, identify a missing dependency/profile/namespace object, or prove the fault is a CI restriction. No child token was verified, no child was resumed, and no child ACL/network test ran successfully. All artifacts retain `mission_acceptance=BLOCKED` and `backend_enabled_by_slice=false`.

A filtered filesystem/registry/process trace and effective-access inspection on a suitable Windows runner/VM remain the next diagnostic step. Creating a default profile as a guessed fix would violate the existing bounded-write assumptions unless its full storage effects were confined and proven first.

## Linux CI: exact failure, not hidden

[Linux run 39579691217](https://github.com/mosfiry/cybersentinel/actions/runs/39579691217), attempt 1, Python 3.13.16, tested `feeb623`: **1 failed, 2329 passed, 53 skipped, 4 warnings**.

The failure is `tests/test_acceptance_process_tree.py::test_fixture_stop_terminates_owned_process_group_and_removes_readiness_file`, line 52:

```text
child_pid = int(child_pid_file.read_text(encoding="ascii"))
ValueError: invalid literal for int() with base 10: ''
```

The readiness helper at lines 27–33 returns when `path.is_file()` becomes true. The writer at line 43 opens/truncates the PID file before writing its PID. Existence is therefore not a publication barrier: the reader can observe an empty file. The failure occurs **before** `_stop_fixture` and its process-tree assertions, so this CI run does not prove a cleanup failure or success for that test.

A deterministic local mechanism reproduction used a real child that opened the file, paused before publication, and then wrote a valid integer. The unchanged `_wait_for_file` returned while the file was empty; `int('')` produced the same ValueError; the child subsequently published the integer. This demonstrates the legal race window, not the exact scheduling history of the original CI process. The unchanged focused process-tree file also passed locally: **2 passed**.

This file and its production helpers are byte-identical to D4. No unrelated Linux fix or test relaxation was folded into D2. A separate fix should use atomic publication or wait for a valid bounded PID payload, with its own regression test and unchanged process-cleanup assertions.

GitHub step cards marked pytest as success after continue-on-error handling, but the preserved `PYTEST_OUTCOME` was `failure`, and the final gate explicitly failed with `Required Linux gate 'pytest' ended as 'failure'`. Thus the overall workflow correctly stayed red. Playwright download logs contained DNS `ENOTFOUND` retries, but the installation/container steps ultimately reported success; those retries are not the failing final gate. Owner charter audit [39579691135](https://github.com/mosfiry/cybersentinel/actions/runs/39579691135) passed on `feeb623`.

## Local verification and all earlier failures

| Check | Actual result |
|---|---|
| Frozen D4 baseline, separate worktree | **2327 passed, 53 skipped, 4 warnings** |
| Final full diagnostic tree, no source changes during run | **2330 passed, 53 skipped, 4 warnings** |
| Final focused D4/workflow/source guards | **459 passed** |
| Earlier broader focused sandbox/acceptance selection | **486 passed, 4 skipped** |
| Final unchanged process-tree tests | **2 passed** |
| MinGW cross-compilation | PASS; not native execution evidence |
| MSVC native compilation | PASS in Windows CI; LPAC launch still FAIL |
| compileall / diff check / staged credential-pattern scan | PASS |
| D4 changed-file blob comparison | `scripts/windows_desktop_acceptance.py` and `tests/test_windows_acceptance_harness.py` unchanged |

The 53 skips remain skips, not acceptance evidence. Four warnings concern forking from a multithreaded process. There was no reduction of the existing test selection.

Earlier failures are preserved rather than discarded:

- Red phase: all **3** new source guards failed before diagnostic/branch changes, as intended.
- A preliminary full run overlapped source edits and is **not a valid frozen baseline**: **2 failed, 2325 passed, 53 skipped**. One failure was the stale exact branch-list assertion; one was Chromium `Page.captureScreenshot: Unable to capture screenshot`. The screenshot failure did not recur in the frozen D4 or final run; no browser code was changed and no specific transient cause is claimed.
- The next pre-correction full run: **1 failed, 2329 passed, 53 skipped** for the same stale branch-list assertion. The assertion was updated to the exact authorized two-branch list; native expected-case, no-skip, and fail-closed guards remain intact.
- A focused command named nonexistent `tests/test_windows_vhd_ci_workflow.py`, returned exit 4, and ran **no tests**. The corrected existing-file selection produced 459 passes above.
- Independent review flagged a possible MSVC C4127 constant-size condition under `/W4 /WX`; it was removed before commit. Final independent review found no blockers. Actual subsequent MSVC compilation passed.
- The first commit attempt failed because Git author identity was unset; the following push failed for lack of plain Git credentials, publishing nothing. Commit identity was then supplied per command from the verified existing GitHub identity, and the push used the configured GitHub connector credential helper. No global Git configuration was changed and no saved token was printed or needed.

## Acceptance matrix

| Requirement | Status |
|---|---|
| Reproduce original Windows LPAC launch failure | VERIFIED on native CI |
| Capture Win32/system message and broker image/cwd facts | VERIFIED on native CI |
| Identify exact missing Windows object / definitive root cause | **UNRESOLVED** |
| Native LPAC tests pass and identity/denials proven | **FAIL / NOT PROVEN** |
| Production backend applied to Mission tools | **NOT IMPLEMENTED; fail-closed preserved** |
| Real local-model Mission reaches GOAL_COMPLETED | **NOT RUN on this branch; prior D4 run RESOURCE_BLOCKED** |
| Restart/resume with authorization and complete evidence | **NOT ACCEPTED on this branch** |
| D4 rejects missing/stale evidence | Existing guards passed locally; source unchanged; no new interactive acceptance claim |
| Full local regression | PASS with skips/warnings recorded |
| Full Linux CI | **FAIL**, PID publication race recorded above |
| Native Windows interactive acceptance | **UNAVAILABLE**; only Linux Sandbox devices were available |

No merge, release, protected-ref update, Skill Routing merge, Cloudflare change, or Workers Builds setting change was performed. Remediation is intentionally not guessed: first identify the missing Windows object, then implement and prove the complete backend contract described in the report.
