# Investigation C: exact LPAC launch failure

Baseline: b6bdf94c23b7e05642f64f7ce86ad63a3852f6da. Existing general task plans are preserved; this continues the scoped D2 investigation.

Assumptions: hosted Windows CI is authorized for bounded trusted diagnostic execution; no interactive Windows access, admin rights, or tracing capability is assumed. Public-repository artifacts contain only ephemeral runner activity, not user-computer traces. Original native capture is preserved separately from a sanitized summary.

## Ordered tasks and acceptance checks

- [x] Inspect native C probe, strict workflow, Python fixtures and previous evidence; verify branch/protected refs. Device discovery found no Windows device; repository runner API returned zero self-hosted runners.
- [ ] Add bounded Microsoft-signature-verified ProcMon capture around the unchanged native test command, retain immediate Win32 diagnostics, preserve original PML/CSV/hashes and measured capability results. Capture setup failure must not soften the LPAC test status.
- [ ] Correlate launch PID and event sequence, identify a causal resource only when justified. Test image, loader/dependencies, token/configuration, environment/cwd/flags and harness hypotheses separately with one-variable experiments if evidence warrants them. Never relax ACLs or add capabilities.
- [ ] Run repeated PID regression (existing 10 x 11), focused checks, full Linux suite, Owner Charter audit, strict Windows LPAC and native Job/VHD suites on exact pushed HEAD.
- [ ] Review diff, normal-push only existing investigation branch, verify remote HEAD and protected references, report PASS/PARTIALLY VERIFIED/BLOCKED honestly. Production backend, D4 logic, MissionRuntime, ToolRegistry, owner authorization and network policy are out of scope.

## Hypothesis decision criteria

| Hypothesis | Support | Falsifier / limitation |
|---|---|---|
| Incorrect image path | Failing image open in native launch sequence | Successful image open/section mapping at the same launch; broker existence alone insufficient |
| Missing transitive import | Fatal loader import resolution for specific DLL | Successful corresponding load; four broker DLL checks do not falsify |
| LPAC token/configuration resource | Failed native object lookup/access correlated with process-creation failure | Resource successfully resolved in otherwise identical attempt |
| Environment/cwd/handle/flags | One-variable native control changes earliest failure | Same failure/resource with each isolated change; no child execution without verified LPAC token |
| Probe/harness assumption | API contract defect or fixture omission linked to native failure | Trace and controls reproduce independently of the suspect assumption |

Native trace documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon . No security policy changes are authorized by diagnostic success.
