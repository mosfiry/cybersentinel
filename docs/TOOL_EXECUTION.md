# Tool Execution

A model proposal becomes a `PlanStep`; it is not an execution capability. Before a tool runs, the runtime validates the registry entry and arguments, reconstructs the typed `AuthorizationContext`, obtains an authorization decision, and passes scope context to the tool runtime.

The execution boundary is:

```text
model proposal
  -> registry/schema validation
  -> AuthorizationContext / AuthorizationDecision
  -> scope validation
  -> tools.registry execution
  -> typed Observation
  -> evidence/state update
```

Unknown tools, extra arguments, invalid schemas, missing parameters, and unauthorized or out-of-scope calls produce explicit failure observations. Tool results are never policy. The registry remains the single source of tool metadata and handlers; the Agent Core does not introduce a second authority path.

## Capability availability

Registry entries explicitly report availability. `scoped_http_probe` is **Unavailable / Not supported by current backend contract**: scope authorization and URL validation exist, but there is no HTTP transport implementation. It is omitted from model-facing tool schemas and the Owner tool budget; the internal tool catalog may report its unavailable reason. Direct execution fails closed and cannot emit a successful placeholder observation. Do not treat scope-validation tests as evidence that a network request was made.

`run_project_tests` executes only when startup has verified `bubblewrap` and `prlimit` can create the required user/PID/network namespaces and import the isolated pytest interpreter. It copies the selected project into a size-bounded temporary snapshot; excludes environment files (except safe templates), common credential stores (`.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.config`, `.ssh`, `.gnupg`, `.terraform`, `.pulumi`, `.vercel`, `secrets`, and `credentials`), private-key/certificate files, service-account JSON, Terraform state, and databases; binds the snapshot read-only at `/workspace`; clears the environment; disables user-site and pytest-plugin autoload; and runs without network access. The invocation is bounded by 60 CPU seconds, 2 GiB address space, 64 MiB per-file output, 256 open files, 1,024 processes, a 256 MiB `/tmp`, 20,000 snapshot entries, 256 MiB snapshot bytes, and a 128-level path depth. If sandbox preflight fails, the capability is marked unavailable, hidden from model schemas, and rejected before execution. The `project_tests_pass` criterion also checks the recorded command and signed workspace execution event; a generic tool result is not completion evidence.
