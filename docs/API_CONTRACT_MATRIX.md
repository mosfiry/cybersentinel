# API Contract Matrix — V8 Request/API Contract Hardening

Status: VERIFIED at 2eeefc2d6ee4dcbd4674fac51d4ad5661546aa29 (CI green, check
runs 110841742566 / 110841722996 / 110841757581 / 110841719396 / 110841707821).
Every row below cites the file and the enforcing test. Rows marked NOT VERIFIED
are honest limits, not claims.

| Surface | Contract decision | Evidence |
| --- | --- | --- |
| request_id (plan path /api/missions) | Client-supplied ALLOWED under strict format: str, 1..128 chars, [A-Za-z0-9_-]; anything else ValueError(invalid_request_id) raised BEFORE authorization (fail-closed); bridge maps ValueError to 400. | agent/agent_core.py AgentCore._auth; tests/test_request_id_contract.py |
| request_id (chat path) | Same contract; run_owner_mission validates before _auth; absent -> server-generated uuid4().hex. | agent/agent_core.py run_owner_mission; tests/test_request_id_contract.py |
| request_id binding consistency | Every chat/mission response carries the mission dict incl. request_id, and conversation messages persist request_id metadata. | api/chat.py chat(); add_conversation_message metadata |
| request_id uniqueness | NOT VERIFIED / KNOWN LIMITATION: no cross-request uniqueness claim is made on the mission path (core.lifecycle.begin claim table is used only by the legacy engine). Recorded, not fixed: enforcement would be new architecture. | core/lifecycle.py begin(); mission-path absence verified by grep of agent/ |
| run_at (scheduling) | Timezone-aware ISO-8601 REQUIRED; ValueError otherwise (fail-closed); stored normalized to canonical UTC (datetime.astimezone(UTC).isoformat()). | agent/mission_worker.py normalize_run_at/_parse_instant; tests/test_run_at_contract.py |
| run_at dispatch comparison | Parsed-instant comparison in Python; NEVER raw text comparison; legacy/unparseable rows are skipped (not dispatched) — fail-closed. | MissionScheduler.dispatch_due; tests/test_run_at_contract.py |
| recurring schedules | next_run_at recomputed from the parsed instant (canonical UTC), state stays SCHEDULED; one-shot schedules complete after dispatch. | tests/test_run_at_contract.py |
| scheduler exposure | Bridge-token routes only (POST /api/missions/{id}/schedule); NO public schedule route exists. | docs/DESKTOP_BACKEND_CONTRACT.md route inventory (read from bridge.py at 71ce3c95, unchanged through 2eeefc2d) |
| mission deletion | VERIFIED ABSENT: no delete route exists in the public or internal route inventory of this lineage. Manus uncommitted delete route = UNVERIFIED, not contract. | docs/DESKTOP_BACKEND_CONTRACT.md |
| conversation_id | Server-generated uuid4().hex when absent; supplied values validated (<=128 chars, [A-Za-z0-9_-]) — characterized as existing behavior. Known quirk recorded honestly: a whitespace-only supplied value passes validation and yields an empty string (pre-existing; no claim made that it is rejected). | api/chat.py _conversation_id; tests/test_request_id_contract.py |
| SSE | Internal bridge-token routes only (/api/chat/stream, /api/tasks/{id}/stream); wire format pinned deterministic (event:/data: lines, UTF-8, trailing blank line). No public SSE route; desktop web client uses JSON chat only. | api/chat.py sse(); docs/DESKTOP_BACKEND_CONTRACT.md; tests/test_request_id_contract.py |
| provider protocol | Typed ProviderError taxonomy (CAPABILITY_UNSUPPORTED / PROVIDER_FAILURE / INVALID_MODEL_RESPONSE / TIMEOUT / AUTHENTICATION_FAILURE); classification deterministic at the router boundary; no provider failure becomes success. | docs/PROVIDER_FAILURE_MODEL.md; tests/test_provider_failure_model.py |
| tool output schema normalization | response_from_legacy: non-dict tool-call entries skipped; string arguments must parse as JSON object else {}; non-dict arguments become {}. Deterministic, no exceptions. | agent/provider_api.py; tests/test_provider_failure_model.py |

Change log (Vibe branch vibe/principal-engineering):
- 5e70f6499df074c5c0699350728ad935464baecd — V8.1 run_at contract fix + tests.
- ef440d97da833068ea877bdbd8e5556559bc95c7 — V8.2 request_id contract fix + tests.
- 92b4d39f1317968b1487aca17c2179c57f93ec97 — V8.2.1 test correction (conversation_id characterization).
- b571148f109f80fa2adfd118ae5d771e70a96f3b — V8.4 flaky parallel test made order-independent.
- 2eeefc2d6ee4dcbd4674fac51d4ad5661546aa29 — V9.1 provider failure battery.
