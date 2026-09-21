# Failure Recovery

Failures enter the Mission loop through an observation and are classified into `FailureClass`: transient, dependency, compilation, test failure, network, provider, tool, authorization, scope, resource, logic, or unknown.

`RecoveryPolicy` maps the classification and retry count to a bounded action:

| Failure | Recovery |
|---|---|
| Authorization | `OWNER_INPUT_REQUIRED` |
| Scope | `SCOPE_BLOCKED` |
| Resource | `RESOURCE_BLOCKED` |
| Transient/network/provider within budget | `RETRY` |
| Compilation/test/logic within budget | `REPLAN` |
| Exhausted or unknown | explicit failure |

Malformed, empty, unknown, and invalid tool proposals are observations, not silent success. Provider failure is distinguished from malformed proposal so it receives the correct bounded policy. Replanning receives the observation and must preserve `mission.objective`; an attempted objective change produces `SAFETY_BLOCKED`.

Repeated plan/action signatures are tracked. A repeated strategy beyond the threshold becomes `FAILED_RETRY_EXHAUSTED` with a recorded diagnosis instead of an infinite loop.
