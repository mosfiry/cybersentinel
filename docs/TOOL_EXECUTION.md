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
