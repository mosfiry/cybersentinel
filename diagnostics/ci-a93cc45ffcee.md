# CI run a93cc45ffcee
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
........................................................................ [  7%]
....F................................................................... [ 14%]
........................................................................ [ 21%]
........................................................................ [ 28%]
........................................................................ [ 35%]
........................................................................ [ 43%]
.......................F................................................ [ 50%]
........................................................................ [ 57%]
........................................................................ [ 64%]
........................................................................ [ 71%]
........................................................................ [ 79%]
...FFFFFF............................................................... [ 86%]
...s.................................................................... [ 93%]
.................................................................        [100%]
=================================== FAILURES ===================================
_______ test_twenty_one_turn_trajectory_retains_observations_and_events ________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_twenty_one_turn_trajector0')

    def test_twenty_one_turn_trajectory_retains_observations_and_events(tmp_path):
        turn_count = 21
        steps = tuple(PlanStep(f"turn-{index}", f"turn {index}", action="status") for index in range(turn_count))
    
        def execute(mission, step, action_id):
            return {"success": True, "source": "retention-fixture", "criterion_id": step.step_id, "turn": mission.current_step}
    
        rt = make_runtime(tmp_path, execute)
        mission = rt.create(
            "retain trajectory",
            "retain trajectory",
            Plan.initial("retain trajectory").replan(steps=steps, reason="retention test"),
            max_iterations=turn_count + 5,
        )
        result = rt.run_to_completion(mission.mission_id, max_slices=turn_count + 5)
    
>       assert result.status is MissionStatus.GOAL_COMPLETED
E       AssertionError: assert <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'> is <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'>
E        +  where <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'> = Mission(mission_id='81097e474cb24623b09fdf7953ba181e', owner_request='retain trajectory', objective='retain trajectory...overy_events=[], semantic_intent={}, integrity_hash='edbd6930aad238089428ce36995461deda351f770a231f4e7d64833574a533d0').status
E        +  and   <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'> = MissionStatus.GOAL_COMPLETED

tests/test_agent_adaptive_loop.py:213: AssertionError
______ test_restart_e2e_persists_mission_worker_evidence_and_revalidates _______

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_restart_e2e_persists_miss0')

    def test_restart_e2e_persists_mission_worker_evidence_and_revalidates(tmp_path):
        mission_db = tmp_path / "missions.sqlite3"
        queue_db = tmp_path / "queue.sqlite3"
        evidence_db = tmp_path / "evidence.sqlite3"
        # B3-C5/B3-H3: legacy plans must use registered tools only; the stub
        # executor performs the actual workspace write itself.
        plan = Plan.initial("restart objective").replan(steps=(PlanStep("s1", "write", action="status"),), reason="test")
        evidence_store = EvidenceChainStore(evidence_db)
    
        def execute(mission, _step, _action):
            snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
            workspace = Workspace(tmp_path, authorization_snapshot=snapshot).bind(mission_id=mission.mission_id, request_id=mission.request_id, tool_id="write", authorization_snapshot=snapshot, evidence_store=evidence_store)
            workspace.write("artifact.txt", "persisted")
            return {"success": True, "criterion_id": "write", "source": "workspace"}
    
        first = MissionRuntime(MissionStore(mission_db), executor=execute, authorization_snapshot_factory=lambda mission: make_test_snapshot(mission, root=str(tmp_path)))
        mission = first.create("restart objective", "restart objective", plan, owner_identity_ref="test-owner", request_id="restart-request")
        queue = MissionQueue(queue_db)
        queue.enqueue(mission.mission_id)
        worker_item = queue.claim_next(worker_id="worker-a", lease_seconds=60)
        assert worker_item is not None
        result = first.run_to_completion(mission.mission_id, max_slices=3, heartbeat=lambda: queue.heartbeat(mission.mission_id, worker_id="worker-a"))
>       assert result.status is MissionStatus.GOAL_COMPLETED
E       AssertionError: assert <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'> is <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'>
E        +  where <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'> = Mission(mission_id='891d4489e0bb442c83b479bb82f4550e', owner_request='restart objective', objective='restart objective...overy_events=[], semantic_intent={}, integrity_hash='67e766d164d410b675c149959775b7e5d8cd5ddb04aaa5556d3156611a2037bf').status
E        +  and   <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'> = MissionStatus.GOAL_COMPLETED

tests/test_governed_execution.py:294: AssertionError
______ test_end_to_end_observation_failure_replan_verify_and_persistence _______

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_end_to_end_observation_fa0')

    def test_end_to_end_observation_failure_replan_verify_and_persistence(tmp_path):
        calls = []
    
        def execute(mission, step, action_id):
            calls.append((mission.plan.version, step.step_id))
            if len(calls) == 1:
                return {"success": False, "failure_class": "COMPILATION", "error": "compiler error", "source": "build"}
            return {"success": True, "criterion_id": "tests", "source": "pytest", "result": {"passed": 3}}
    
        plan = Plan.initial("build and verify artifact").replan(steps=(PlanStep("build", "build", action="build", verification=("tests",)),), reason="initial plan")
        rt = runtime(tmp_path, execute)
        mission = rt.create("build it", "build and verify artifact", plan, completion_criteria=[{"criterion_id": "tests", "description": "tests pass", "check": "pytest"}])
        after_failure = rt.run_slice(mission.mission_id)
        assert after_failure.status is MissionStatus.READY
        assert after_failure.plan.version == 3
>       assert after_failure.observations[0]["error"] == "compiler error"
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       IndexError: list index out of range

tests/test_phase6k7b_mission_runtime.py:30: IndexError
_______ test_new_runtime_instance_resumes_after_simulated_process_crash ________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_new_runtime_instance_resu0')

    def test_new_runtime_instance_resumes_after_simulated_process_crash(tmp_path):
        attempts = {"count": 0}
    
        def crashing_executor(mission, step, action_id):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise RuntimeError("simulated crash")
            return {"success": True, "criterion_id": "step", "source": "executor"}
    
        plan = Plan.initial("resume").replan(steps=(PlanStep("step", "step", action="run"),), reason="initial")
        first = runtime(tmp_path, crashing_executor)
        mission = first.create("resume", "resume", plan)
        crashed = first.run_slice(mission.mission_id)
>       assert crashed.status is MissionStatus.RUNNING
E       AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.RUNNING: 'RUNNING'>
E        +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='9d0e9f6c2bbe4813b49a3c0bf79a9f7b', owner_request='resume', objective='resume', status=<MissionStat...overy_events=[], semantic_intent={}, integrity_hash='c66594bf60c5d7638874ecf633b02fc456def6595f81b0e2c309054cb18a4716').status
E        +  and   <MissionStatus.RUNNING: 'RUNNING'> = MissionStatus.RUNNING

tests/test_phase6k7b_mission_runtime.py:54: AssertionError
_____ test_in_flight_receipt_reconciliation_prevents_duplicate_side_effect _____

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_in_flight_receipt_reconci0')

    def test_in_flight_receipt_reconciliation_prevents_duplicate_side_effect(tmp_path):
        calls = []
    
        def execute(mission, step, action_id):
            calls.append(action_id)
            raise RuntimeError("crash after external side effect")
    
        plan = Plan.initial("receipt").replan(steps=(PlanStep("step", "step", action="run"),), reason="initial")
        rt = runtime(tmp_path, execute)
        mission = rt.create("receipt", "receipt", plan)
        rt.run_slice(mission.mission_id)
>       assert rt.run_slice(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
E       AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'>
E        +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='8778e643cb2f4d76be42ace06a8497bf', owner_request='receipt', objective='receipt', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='4f0baebad14201f74e5623fafab60d2aa258e454a84cac8ef84a2122b836afb9').status
E        +    where Mission(mission_id='8778e643cb2f4d76be42ace06a8497bf', owner_request='receipt', objective='receipt', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='4f0baebad14201f74e5623fafab60d2aa258e454a84cac8ef84a2122b836afb9') = run_slice('8778e643cb2f4d76be42ace06a8497bf')
E        +      where run_slice = <agent.mission_runtime.MissionRuntime object at 0x7f1ddeffab70>.run_slice
E        +      and   '8778e643cb2f4d76be42ace06a8497bf' = Mission(mission_id='8778e643cb2f4d76be42ace06a8497bf', owner_request='receipt', objective='receipt', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='7f7ba48034858d45e1fac82602ce0bd3c4eb5c883a9b5a98dc81827c349555b1').mission_id
E        +  and   <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'> = MissionStatus.RECOVERY_REQUIRED

tests/test_phase6k7b_mission_runtime.py:82: AssertionError
_______ test_goal_verification_blocks_completion_until_required_evidence _______

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_goal_verification_blocks_0')

    def test_goal_verification_blocks_completion_until_required_evidence(tmp_path):
        def execute(mission, step, action_id):
            return {"success": True, "criterion_id": "implementation", "source": "builder"}
    
        plan = Plan.initial("deliver").replan(steps=(PlanStep("implementation", "implementation", action="build"),), reason="initial")
        rt = runtime(tmp_path, execute)
        mission = rt.create("deliver", "deliver", plan, completion_criteria=[
            {"criterion_id": "implementation", "required": True},
            {"criterion_id": "tests", "required": True},
        ])
        after_step = rt.run_slice(mission.mission_id)
        assert after_step.status is MissionStatus.READY
        checked = rt.run_slice(mission.mission_id)
>       assert checked.status is MissionStatus.RUNNING
E       AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.RUNNING: 'RUNNING'>
E        +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='31d30635f5b945478253fa132d8a6c14', owner_request='deliver', objective='deliver', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='283a6a8a767800e072606a1ba6c8efcac33d1189bf99bbbae48778c41e4376a3').status
E        +  and   <MissionStatus.RUNNING: 'RUNNING'> = MissionStatus.RUNNING

tests/test_phase6k7b_mission_runtime.py:103: AssertionError
__________ test_authorization_intervention_persists_and_allow_resumes __________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_authorization_interventio0')
monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x7f1ddf47bf50>

    def test_authorization_intervention_persists_and_allow_resumes(tmp_path, monkeypatch):
        executed = []
    
        def execute(mission, step, action_id):
            executed.append(action_id)
            return {"success": True, "criterion_id": "sensitive", "source": "tool"}
    
        plan = Plan.initial("sensitive").replan(steps=(PlanStep("sensitive", "sensitive", action="tool", authorization_requirement="owner"),), reason="initial")
        rt = runtime(tmp_path, execute)
        mission = rt.create("do sensitive", "sensitive", plan, completion_criteria=[{"criterion_id": "sensitive"}])
        blocked = rt.run_slice(mission.mission_id)
>       assert blocked.status is MissionStatus.OWNER_INPUT_REQUIRED
E       AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'>
E        +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='182a9e4dde3c482aa2d201e9fbd4e4c5', owner_request='do sensitive', objective='sensitive', status=<Mi...overy_events=[], semantic_intent={}, integrity_hash='b23a72d1da50b673decb91490187620e18d893b7afa6c2ab664849d3120d1686').status
E        +  and   <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'> = MissionStatus.OWNER_INPUT_REQUIRED

tests/test_phase6k7b_mission_runtime.py:119: AssertionError
_________ test_idempotency_does_not_repeat_completed_sensitive_action __________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_idempotency_does_not_repe0')

    def test_idempotency_does_not_repeat_completed_sensitive_action(tmp_path):
        calls = []
    
        def execute(mission, step, action_id):
            calls.append(action_id)
            return {"success": True, "criterion_id": "step", "source": "tool"}
    
        plan = Plan.initial("once").replan(steps=(PlanStep("step", "step", action="tool"),), reason="initial")
        rt = runtime(tmp_path, execute)
        mission = rt.create("once", "once", plan)
        rt.run_slice(mission.mission_id)
        loaded = MissionStore(Path(tmp_path) / "missions.sqlite3").load(mission.mission_id)
        loaded.current_step = 0
        loaded.status = MissionStatus.READY
        MissionStore(Path(tmp_path) / "missions.sqlite3").save(loaded)
        rt.run_slice(mission.mission_id)
>       assert len(calls) == 1
E       assert 0 == 1
E        +  where 0 = len([])

tests/test_phase6k7b_mission_runtime.py:156: AssertionError
=========================== short test summary info ============================
FAILED tests/test_agent_adaptive_loop.py::test_twenty_one_turn_trajectory_retains_observations_and_events - AssertionError: assert <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'> is <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'>
 +  where <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'> = Mission(mission_id='81097e474cb24623b09fdf7953ba181e', owner_request='retain trajectory', objective='retain trajectory...overy_events=[], semantic_intent={}, integrity_hash='edbd6930aad238089428ce36995461deda351f770a231f4e7d64833574a533d0').status
 +  and   <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'> = MissionStatus.GOAL_COMPLETED
FAILED tests/test_governed_execution.py::test_restart_e2e_persists_mission_worker_evidence_and_revalidates - AssertionError: assert <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'> is <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'>
 +  where <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'> = Mission(mission_id='891d4489e0bb442c83b479bb82f4550e', owner_request='restart objective', objective='restart objective...overy_events=[], semantic_intent={}, integrity_hash='67e766d164d410b675c149959775b7e5d8cd5ddb04aaa5556d3156611a2037bf').status
 +  and   <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'> = MissionStatus.GOAL_COMPLETED
FAILED tests/test_phase6k7b_mission_runtime.py::test_end_to_end_observation_failure_replan_verify_and_persistence - IndexError: list index out of range
FAILED tests/test_phase6k7b_mission_runtime.py::test_new_runtime_instance_resumes_after_simulated_process_crash - AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.RUNNING: 'RUNNING'>
 +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='9d0e9f6c2bbe4813b49a3c0bf79a9f7b', owner_request='resume', objective='resume', status=<MissionStat...overy_events=[], semantic_intent={}, integrity_hash='c66594bf60c5d7638874ecf633b02fc456def6595f81b0e2c309054cb18a4716').status
 +  and   <MissionStatus.RUNNING: 'RUNNING'> = MissionStatus.RUNNING
FAILED tests/test_phase6k7b_mission_runtime.py::test_in_flight_receipt_reconciliation_prevents_duplicate_side_effect - AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'>
 +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='8778e643cb2f4d76be42ace06a8497bf', owner_request='receipt', objective='receipt', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='4f0baebad14201f74e5623fafab60d2aa258e454a84cac8ef84a2122b836afb9').status
 +    where Mission(mission_id='8778e643cb2f4d76be42ace06a8497bf', owner_request='receipt', objective='receipt', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='4f0baebad14201f74e5623fafab60d2aa258e454a84cac8ef84a2122b836afb9') = run_slice('8778e643cb2f4d76be42ace06a8497bf')
 +      where run_slice = <agent.mission_runtime.MissionRuntime object at 0x7f1ddeffab70>.run_slice
 +      and   '8778e643cb2f4d76be42ace06a8497bf' = Mission(mission_id='8778e643cb2f4d76be42ace06a8497bf', owner_request='receipt', objective='receipt', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='7f7ba48034858d45e1fac82602ce0bd3c4eb5c883a9b5a98dc81827c349555b1').mission_id
 +  and   <MissionStatus.RECOVERY_REQUIRED: 'RECOVERY_REQUIRED'> = MissionStatus.RECOVERY_REQUIRED
FAILED tests/test_phase6k7b_mission_runtime.py::test_goal_verification_blocks_completion_until_required_evidence - AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.RUNNING: 'RUNNING'>
 +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='31d30635f5b945478253fa132d8a6c14', owner_request='deliver', objective='deliver', status=<MissionSt...overy_events=[], semantic_intent={}, integrity_hash='283a6a8a767800e072606a1ba6c8efcac33d1189bf99bbbae48778c41e4376a3').status
 +  and   <MissionStatus.RUNNING: 'RUNNING'> = MissionStatus.RUNNING
FAILED tests/test_phase6k7b_mission_runtime.py::test_authorization_intervention_persists_and_allow_resumes - AssertionError: assert <MissionStatus.READY: 'READY'> is <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'>
 +  where <MissionStatus.READY: 'READY'> = Mission(mission_id='182a9e4dde3c482aa2d201e9fbd4e4c5', owner_request='do sensitive', objective='sensitive', status=<Mi...overy_events=[], semantic_intent={}, integrity_hash='b23a72d1da50b673decb91490187620e18d893b7afa6c2ab664849d3120d1686').status
 +  and   <MissionStatus.OWNER_INPUT_REQUIRED: 'OWNER_INPUT_REQUIRED'> = MissionStatus.OWNER_INPUT_REQUIRED
FAILED tests/test_phase6k7b_mission_runtime.py::test_idempotency_does_not_repeat_completed_sensitive_action - assert 0 == 1
 +  where 0 = len([])
8 failed, 992 passed, 1 skipped in 12.85s
