# CyberSentinel X Agent Intelligence Audit

Generated at: `2026-09-21T16:54:18.542109+00:00`
Commit: `de5c2c513648de7f552225681e39364717d1549f`
Baseline: `25307b88960d7e9a04cb9ce14c3b00b8fbcee41e` with 276 tests before this upgrade.

## Scope

This report records the adaptive-loop audit. It does not claim production readiness, full autonomy, or super-intelligence. External knowledge, model output, memory, and tool results remain untrusted data or proposals; Owner Instruction and deterministic enforcement remain authoritative.

## Real provider

```json
{
  "configured": true,
  "status": [
    {
      "name": "default",
      "model": "gpt-5-mini",
      "base_url": "https://api.manus.im/api/llm-proxy/v1",
      "configured": true,
      "failure_count": 0,
      "last_error": "",
      "priority": 1000,
      "capabilities": {
        "generate": true,
        "stream": false,
        "tool_calling": false,
        "structured_output": false,
        "chat": true
      }
    }
  ],
  "provider": "default",
  "model": "gpt-5-mini",
  "probe": "PASS",
  "response_content": "{\"probe\":\"ok\"}"
}
```

## Real AgentCore mission

```json
{
  "status": "GOAL_COMPLETED",
  "mission_id": "e4634a0568e7469fb818d50470a4d03b",
  "provider": [
    {
      "name": "default",
      "model": "gpt-5-mini",
      "base_url": "https://api.manus.im/api/llm-proxy/v1",
      "configured": true,
      "failure_count": 0,
      "last_error": "",
      "priority": 1000,
      "capabilities": {
        "generate": true,
        "stream": false,
        "tool_calling": false,
        "structured_output": false,
        "chat": true
      }
    }
  ],
  "plan_versions": [
    2
  ],
  "observations": 1,
  "interpretations": 1,
  "replans": 0,
  "verification": {
    "verified": true,
    "missing_criteria": [],
    "evidence_count": 1
  },
  "trajectory_events": [
    "MissionStarted",
    "PlanCreated",
    "StepSelected",
    "AuthorizationChecked",
    "ObservationReceived",
    "ToolExecuted",
    "ObservationInterpreted",
    "StrategyDecided",
    "EvidenceAdded",
    "GoalVerificationStarted",
    "GoalVerified",
    "MissionCompleted"
  ]
}
```

## Safe end-to-end trajectory

```json
{
  "status": "GOAL_COMPLETED",
  "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
  "plan_versions": [
    2,
    3,
    4
  ],
  "observations": 3,
  "hypothesis_updates": 2,
  "replans": 2,
  "transitions": [
    {
      "from": "CREATED",
      "to": "PLANNING",
      "reason": "mission created",
      "data": {},
      "iteration": 0
    },
    {
      "from": "PLANNING",
      "to": "READY",
      "reason": "plan persisted",
      "data": {},
      "iteration": 0
    },
    {
      "from": "READY",
      "to": "RUNNING",
      "reason": "step started",
      "data": {
        "step_id": "initial"
      },
      "iteration": 1
    },
    {
      "from": "RUNNING",
      "to": "OBSERVING",
      "reason": "action returned observation",
      "data": {
        "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:2:initial:0"
      },
      "iteration": 1
    },
    {
      "from": "OBSERVING",
      "to": "REPLANNING",
      "reason": "observation changed mission understanding",
      "data": {},
      "iteration": 1
    },
    {
      "from": "REPLANNING",
      "to": "READY",
      "reason": "informative observation caused replan",
      "data": {
        "plan_version": 3
      },
      "iteration": 1
    },
    {
      "from": "READY",
      "to": "RUNNING",
      "reason": "step started",
      "data": {
        "step_id": "investigation-2"
      },
      "iteration": 2
    },
    {
      "from": "RUNNING",
      "to": "OBSERVING",
      "reason": "action returned observation",
      "data": {
        "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:3:investigation-2:0"
      },
      "iteration": 2
    },
    {
      "from": "OBSERVING",
      "to": "REPLANNING",
      "reason": "hypothesis state changed; strategy must be reevaluated",
      "data": {},
      "iteration": 2
    },
    {
      "from": "REPLANNING",
      "to": "READY",
      "reason": "informative observation caused replan",
      "data": {
        "plan_version": 4
      },
      "iteration": 2
    },
    {
      "from": "READY",
      "to": "RUNNING",
      "reason": "step started",
      "data": {
        "step_id": "investigation-3"
      },
      "iteration": 3
    },
    {
      "from": "RUNNING",
      "to": "OBSERVING",
      "reason": "action returned observation",
      "data": {
        "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:4:investigation-3:0"
      },
      "iteration": 3
    },
    {
      "from": "OBSERVING",
      "to": "READY",
      "reason": "observation accepted",
      "data": {},
      "iteration": 3
    },
    {
      "from": "READY",
      "to": "VERIFYING",
      "reason": "all plan steps observed",
      "data": {},
      "iteration": 4
    },
    {
      "from": "VERIFYING",
      "to": "GOAL_COMPLETED",
      "reason": "required verification evidence present",
      "data": {},
      "iteration": 4
    }
  ],
  "authorization_decisions": [
    {
      "event": "AuthorizationChecked",
      "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
      "request_id": "",
      "step_id": "initial",
      "timestamp": "2026-09-21T16:53:41.458173+00:00",
      "provenance": {},
      "data": {
        "allowed": true,
        "reason": "authorized"
      }
    },
    {
      "event": "AuthorizationChecked",
      "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
      "request_id": "",
      "step_id": "investigation-2",
      "timestamp": "2026-09-21T16:53:41.461915+00:00",
      "provenance": {},
      "data": {
        "allowed": true,
        "reason": "authorized"
      }
    },
    {
      "event": "AuthorizationChecked",
      "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
      "request_id": "",
      "step_id": "investigation-3",
      "timestamp": "2026-09-21T16:53:41.467303+00:00",
      "provenance": {},
      "data": {
        "allowed": true,
        "reason": "authorized"
      }
    }
  ],
  "scope_decisions": [],
  "recovery_events": [],
  "verification": {
    "verified": true,
    "missing_criteria": [],
    "evidence_count": 4
  },
  "knowledge_objects": 4,
  "calls": [
    "search",
    "search",
    "search"
  ],
  "passed": true
}
```

### Trajectory

```json
[
  {
    "event": "MissionStarted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "",
    "timestamp": "2026-09-21T16:53:41.454645+00:00",
    "provenance": {},
    "data": {
      "objective": "Investigate whether CVE-X was the initial access vector for Incident-A"
    }
  },
  {
    "event": "PlanCreated",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "",
    "timestamp": "2026-09-21T16:53:41.454707+00:00",
    "provenance": {},
    "data": {
      "version": 2,
      "fingerprint": "68db55c233642aa5e37ebfced1cce2125f23e9988952a5ceed5b6fe1f5c27b77"
    }
  },
  {
    "event": "StepSelected",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.458109+00:00",
    "provenance": {},
    "data": {
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:2:initial:0",
      "plan_version": 2
    }
  },
  {
    "event": "AuthorizationChecked",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.458173+00:00",
    "provenance": {},
    "data": {
      "allowed": true,
      "reason": "authorized"
    }
  },
  {
    "event": "ObservationReceived",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.459625+00:00",
    "provenance": {},
    "data": {
      "status": true,
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:2:initial:0"
    }
  },
  {
    "event": "ToolExecuted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.459640+00:00",
    "provenance": {},
    "data": {
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:2:initial:0",
      "status": "completed"
    }
  },
  {
    "event": "ObservationInterpreted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.459837+00:00",
    "provenance": {},
    "data": {
      "observation_id": "obs-18b043fa76648f1723a0",
      "summary": "target version is not vulnerable",
      "facts": [],
      "new_evidence": [],
      "contradictions": [
        {
          "evidence_id": "E17",
          "claim": "version outside vulnerable range"
        }
      ],
      "supporting_evidence_ids": [],
      "counter_evidence_ids": [
        "E17"
      ],
      "hypothesis_updates": [
        {
          "hypothesis_id": "H1",
          "status": "WEAKENED"
        },
        {
          "hypothesis_id": "H2",
          "statement": "external remote service was initial access",
          "status": "ACTIVE"
        }
      ],
      "unknowns": [],
      "new_dependencies": [],
      "recommended_strategy_change": "investigate alternate initial access",
      "replan_reason": "observation changed mission understanding",
      "confidence_changes": [
        {
          "hypothesis_id": "H1",
          "delta": -0.3,
          "reason": "target version is outside vulnerable range",
          "supporting_evidence_ids": [],
          "counter_evidence_ids": [
            "E17"
          ],
          "provenance": {
            "source": "observation"
          }
        }
      ],
      "required_next_evidence": [],
      "information_gain": "HIGH",
      "triggers": [
        "CONTRADICTORY_EVIDENCE",
        "HYPOTHESIS_CHANGE"
      ],
      "provenance": {
        "source": "deterministic_observation_interpreter",
        "action": "search",
        "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7"
      }
    }
  },
  {
    "event": "HypothesisUpdated",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.459843+00:00",
    "provenance": {},
    "data": {
      "updates": [
        {
          "hypothesis_id": "H1",
          "status": "WEAKENED",
          "confidence": 0.5,
          "reason": "target version is outside vulnerable range"
        }
      ]
    }
  },
  {
    "event": "StrategyDecided",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.459873+00:00",
    "provenance": {},
    "data": {
      "decision": "REPLAN",
      "reason": "observation changed mission understanding",
      "triggers": [
        "CONTRADICTORY_EVIDENCE",
        "HYPOTHESIS_CHANGE"
      ],
      "information_gain": "HIGH",
      "required_evidence": [],
      "next_strategy": "investigate alternate initial access",
      "provenance": {
        "source": "deterministic_strategy_engine"
      }
    }
  },
  {
    "event": "EvidenceAdded",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.459882+00:00",
    "provenance": {},
    "data": {
      "criterion_id": "first-observation"
    }
  },
  {
    "event": "ReplanTriggered",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "initial",
    "timestamp": "2026-09-21T16:53:41.459900+00:00",
    "provenance": {},
    "data": {
      "decision": "REPLAN",
      "reason": "observation changed mission understanding",
      "triggers": [
        "CONTRADICTORY_EVIDENCE",
        "HYPOTHESIS_CHANGE"
      ],
      "information_gain": "HIGH",
      "required_evidence": [],
      "next_strategy": "investigate alternate initial access",
      "provenance": {
        "source": "deterministic_strategy_engine"
      }
    }
  },
  {
    "event": "PlanRevised",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "",
    "timestamp": "2026-09-21T16:53:41.459968+00:00",
    "provenance": {},
    "data": {
      "version": 3,
      "fingerprint": "cf9eb90e6926658c56c95c299a217c13c72ea0ff70176c37d3029711d439aee8",
      "reason": "observation changed mission understanding"
    }
  },
  {
    "event": "StepSelected",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.461842+00:00",
    "provenance": {},
    "data": {
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:3:investigation-2:0",
      "plan_version": 3
    }
  },
  {
    "event": "AuthorizationChecked",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.461915+00:00",
    "provenance": {},
    "data": {
      "allowed": true,
      "reason": "authorized"
    }
  },
  {
    "event": "ObservationReceived",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.463475+00:00",
    "provenance": {},
    "data": {
      "status": true,
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:3:investigation-2:0"
    }
  },
  {
    "event": "ToolExecuted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.463491+00:00",
    "provenance": {},
    "data": {
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:3:investigation-2:0",
      "status": "completed"
    }
  },
  {
    "event": "ObservationInterpreted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.463660+00:00",
    "provenance": {},
    "data": {
      "observation_id": "obs-ac82dec2fc0999c8d4e2",
      "summary": "IOC and remote-service evidence support the alternate path",
      "facts": [],
      "new_evidence": [
        {
          "evidence_id": "E18",
          "claim": "IOC preceded the first confirmed session"
        }
      ],
      "contradictions": [],
      "supporting_evidence_ids": [
        "E18"
      ],
      "counter_evidence_ids": [],
      "hypothesis_updates": [],
      "unknowns": [],
      "new_dependencies": [],
      "recommended_strategy_change": "",
      "replan_reason": "",
      "confidence_changes": [
        {
          "hypothesis_id": "H2",
          "delta": 0.25,
          "reason": "independent IOC timing supports alternate path",
          "supporting_evidence_ids": [
            "E18"
          ],
          "counter_evidence_ids": [],
          "provenance": {
            "source": "observation"
          }
        }
      ],
      "required_next_evidence": [],
      "information_gain": "MEDIUM",
      "triggers": [
        "NEW_EVIDENCE"
      ],
      "provenance": {
        "source": "deterministic_observation_interpreter",
        "action": "search",
        "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7"
      }
    }
  },
  {
    "event": "HypothesisUpdated",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.463667+00:00",
    "provenance": {},
    "data": {
      "updates": [
        {
          "hypothesis_id": "H2",
          "status": "STRENGTHENED",
          "confidence": 0.25,
          "reason": "independent IOC timing supports alternate path"
        }
      ]
    }
  },
  {
    "event": "StrategyDecided",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.463693+00:00",
    "provenance": {},
    "data": {
      "decision": "CHANGE_HYPOTHESIS",
      "reason": "hypothesis state changed; strategy must be reevaluated",
      "triggers": [
        "NEW_EVIDENCE"
      ],
      "information_gain": "MEDIUM",
      "required_evidence": [],
      "next_strategy": "",
      "provenance": {
        "source": "deterministic_strategy_engine"
      }
    }
  },
  {
    "event": "EvidenceAdded",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.463704+00:00",
    "provenance": {},
    "data": {
      "criterion_id": "second-observation"
    }
  },
  {
    "event": "ReplanTriggered",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-2",
    "timestamp": "2026-09-21T16:53:41.463712+00:00",
    "provenance": {},
    "data": {
      "decision": "CHANGE_HYPOTHESIS",
      "reason": "hypothesis state changed; strategy must be reevaluated",
      "triggers": [
        "NEW_EVIDENCE"
      ],
      "information_gain": "MEDIUM",
      "required_evidence": [],
      "next_strategy": "",
      "provenance": {
        "source": "deterministic_strategy_engine"
      }
    }
  },
  {
    "event": "PlanRevised",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "",
    "timestamp": "2026-09-21T16:53:41.464768+00:00",
    "provenance": {},
    "data": {
      "version": 4,
      "fingerprint": "e311dc7f1647c11457ecac448076b22cbca194cda9919c5d07ea8924530f8764",
      "reason": "hypothesis state changed; strategy must be reevaluated"
    }
  },
  {
    "event": "StepSelected",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-3",
    "timestamp": "2026-09-21T16:53:41.467226+00:00",
    "provenance": {},
    "data": {
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:4:investigation-3:0",
      "plan_version": 4
    }
  },
  {
    "event": "AuthorizationChecked",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-3",
    "timestamp": "2026-09-21T16:53:41.467303+00:00",
    "provenance": {},
    "data": {
      "allowed": true,
      "reason": "authorized"
    }
  },
  {
    "event": "ObservationReceived",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-3",
    "timestamp": "2026-09-21T16:53:41.469159+00:00",
    "provenance": {},
    "data": {
      "status": true,
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:4:investigation-3:0"
    }
  },
  {
    "event": "ToolExecuted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-3",
    "timestamp": "2026-09-21T16:53:41.469175+00:00",
    "provenance": {},
    "data": {
      "action_id": "d9a411893dbf40ba9624bf0b59e62dc7:4:investigation-3:0",
      "status": "completed"
    }
  },
  {
    "event": "ObservationInterpreted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-3",
    "timestamp": "2026-09-21T16:53:41.469324+00:00",
    "provenance": {},
    "data": {
      "observation_id": "obs-eda6d9a33ae534a6d815",
      "summary": "required evidence reconciled",
      "facts": [],
      "new_evidence": [],
      "contradictions": [],
      "supporting_evidence_ids": [],
      "counter_evidence_ids": [],
      "hypothesis_updates": [],
      "unknowns": [],
      "new_dependencies": [],
      "recommended_strategy_change": "",
      "replan_reason": "",
      "confidence_changes": [],
      "required_next_evidence": [],
      "information_gain": "NO_CHANGE",
      "triggers": [],
      "provenance": {
        "source": "deterministic_observation_interpreter",
        "action": "search",
        "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7"
      }
    }
  },
  {
    "event": "StrategyDecided",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-3",
    "timestamp": "2026-09-21T16:53:41.469353+00:00",
    "provenance": {},
    "data": {
      "decision": "CONTINUE_PLAN",
      "reason": "observation did not materially invalidate the current strategy",
      "triggers": [],
      "information_gain": "NO_CHANGE",
      "required_evidence": [],
      "next_strategy": "",
      "provenance": {
        "source": "deterministic_strategy_engine"
      }
    }
  },
  {
    "event": "EvidenceAdded",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "investigation-3",
    "timestamp": "2026-09-21T16:53:41.469365+00:00",
    "provenance": {},
    "data": {
      "criterion_id": "goal"
    }
  },
  {
    "event": "GoalVerificationStarted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "",
    "timestamp": "2026-09-21T16:53:41.472007+00:00",
    "provenance": {},
    "data": {}
  },
  {
    "event": "GoalVerified",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "",
    "timestamp": "2026-09-21T16:53:41.472160+00:00",
    "provenance": {},
    "data": {
      "evidence_count": 4
    }
  },
  {
    "event": "MissionCompleted",
    "mission_id": "d9a411893dbf40ba9624bf0b59e62dc7",
    "request_id": "",
    "step_id": "",
    "timestamp": "2026-09-21T16:53:41.472170+00:00",
    "provenance": {},
    "data": {
      "verification": {
        "verified": true,
        "missing_criteria": [],
        "evidence_count": 4
      }
    }
  }
]
```

## Architecture paths

Knowledge Sources → Typed Knowledge Store → BM25/typed Retriever → RetrievalResult with provenance → ContextEngine → ModelRouter.

Observation → ObservationInterpreter → typed proposal → HypothesisEngine → StrategyDecision → deterministic objective/scope/authorization checks → replanning or continuation → persistence → verification.

## Limitations

- The real-provider and real-AgentCore mission results are reported exactly as observed; a missing or failing provider prevents the real-model acceptance claim.
- The synthetic fixture is safe and does not execute attack tooling. It validates long-horizon state transitions, counter-evidence, multiple observations, and replanning through the actual MissionRuntime, persistence, typed retrieval, and deterministic controls.
- A real-provider mission audit must be rerun in an environment where the existing configured `default/gpt-5-mini` route is available; no new model or provider was introduced.
