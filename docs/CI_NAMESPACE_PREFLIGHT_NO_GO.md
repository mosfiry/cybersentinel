# GitHub-hosted namespace preflight: no-go at `ecbdbb3`

## Decision

Do not change either GitHub Actions workflow at this base. The standard hosted-runner configuration recorded for this repository fails the required OS namespace preflight, and no workflow-only fix has been proven both safe and effective on that host. This is a no-go for the current `ubuntu-latest` configuration—not a claim that all GitHub-hosted runner types are intrinsically incapable of namespaces.

The minimum owner choice to resume is to provide a trusted, disposable Linux runner on which the exact `bubblewrap --unshare-all` user/PID/network preflight passes. If the owner specifically wants to retain GitHub-hosted runners, the alternative is to authorize and validate a narrowly scoped AppArmor policy for `/usr/bin/bwrap` on the actual runner image before changing CI.

## Evidence

At the requested base `ecbdbb36669a8366dbc60777537a92ee7fb69452`:

- `.github/workflows/tests.yml` and `.github/workflows/pytest-diagnostics.yml` both use `ubuntu-latest`, install `bubblewrap` and `util-linux` (`prlimit`), and run the namespace preflight before compilation or pytest. They do not set a namespace sysctl, use a privileged container, or change the host security policy.
- After that guard, the current `Run tests` step invokes `python -m pytest -q` directly on the host rather than calling `tools.registry._run_project_tests()`. That raw-host step is not an acceptable substitute for the confined runner; it was not executed in this investigation. Any future compliant workflow must route the complete suite through the existing project runner and keep the preflight fail-closed.
- `tools/registry.py::_probe_project_test_sandbox()` asks `prlimit` to run `bwrap --unshare-all` and import `pytest` in the isolated environment. `_sandbox_preflight_failure_reason()` maps permission/namespace failures to `Unavailable: host denied required OS namespace isolation`. `_run_project_tests()` fails closed when the probe is unavailable; it does not fall back to an ordinary subprocess.
- `tests/test_project_test_sandbox.py::test_sandbox_preflight_failure_reason_is_normalized` preserves this failure mapping. The runner, when available, uses the existing secret-filtered, read-only project snapshot, cleared environment, `--unshare-all`, and `prlimit` bounds.
- `docs/CURRENT_RUNTIME_TRUTH.md` records that GitHub Actions run [#468](https://github.com/mosfiry/cybersentinel/actions/runs/36641927114) and diagnostics run [#114](https://github.com/mosfiry/cybersentinel/actions/runs/36641926965), both for commit `593811e`, failed at the namespace preflight; compilation, frontend checks, and pytest did not run. The public run pages confirm the failed statuses.

Installing the binaries is not enough to grant a Linux process permission to create the needed namespaces. GitHub documents the hosted Linux environment and its administrative privileges, but does not document a per-workflow switch that guarantees unprivileged namespace creation. The `actions/runner-images` report [#10443](https://github.com/actions/runner-images/issues/10443) also records `unshare(...): Operation not permitted` on standard Ubuntu 24.04 hosted runners.

## Why no AppArmor workflow change is included

Ubuntu documents that a dedicated AppArmor profile can selectively permit `bwrap` to create user namespaces while leaving the global restriction in place ([Ubuntu explanation](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)). The upstream [`bwrap-userns-restrict` profile](https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor/profiles/extras/bwrap-userns-restrict) is a real candidate, but it is not a small permission-free setting: the profile comments say it allows almost everything for `bwrap`, permits capabilities and namespace operations there, and stacks child processes under a profile intended to strip capabilities. Ubuntu cautions that installing such a profile is system-administrator work and may interact with future updates.

This computer exposes no AppArmor kernel interface or AppArmor profile loader, so I cannot exercise that policy here. The recorded Actions pages establish failed run status but do not expose the detailed job log through the available read-only access. Therefore I cannot prove that the actual hosted image has the required AppArmor support, that the profile loads and confines the test child as intended, or that the complete workflow passes under it. Adding a broad or untested profile, globally enabling unprivileged namespaces, using privileged execution, replacing the confined runner with host pytest, or skipping the tests would violate the stated constraints or weaken the assurance.

## Owner decision required

1. **Preferred minimum:** provide a trusted, disposable Linux runner whose owner confirms and maintains the required namespace capability. The owner must verify the exact `prlimit` + `bwrap --unshare-all` preflight and then run both existing workflows with the complete test suite through the confined project runner.
2. **If standard GitHub-hosted runners are required:** explicitly authorize qualification of a pinned, reviewed AppArmor profile for the installed `bwrap` binary. Before adopting it, prove on the actual hosted image that the profile loads, the preflight succeeds, the test child has no effective capabilities, no network, and only the read-only snapshot plus bounded tmpfs, then run both workflows and the complete suite. Keep the global namespace restriction enabled; do not use a privileged container or raw host pytest.

Until one of these choices is validated, preserve the current fail-closed preflight and treat the hosted CI result as blocked—not as a passing test result.
