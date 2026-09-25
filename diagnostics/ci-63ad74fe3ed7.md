# CI run 63ad74fe3ed7
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
........................................................................ [  9%]
........................................................................ [ 19%]
........................................................................ [ 28%]
........................................................................ [ 38%]
........................................................................ [ 48%]
........................................................................ [ 57%]
........................................................................ [ 67%]
........................................................................ [ 76%]
...................................................F..................F. [ 86%]
F.s..................................................................... [ 96%]
..............................                                           [100%]
=================================== FAILURES ===================================
_________ test_r1c1_invalid_model_output_falls_back_deterministically __________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_r1c1_invalid_model_output0')

    def test_r1c1_invalid_model_output_falls_back_deterministically(tmp_path):
        """CURRENT BEHAVIOR: non-JSON model output falls back to the
        deterministic parser, explicitly marked source="deterministic_fallback"
        with the raw instruction preserved as the objective.
    
        Invariant the R1 fix must preserve: the fallback is deterministic and
        never elevates a failed model turn into trusted interpretation.
        """
        core = AgentCore(
            router=StubRouter("not json at all"),
            store=MissionStore(Path(tmp_path) / "missions.sqlite3"),
        )
        intent = core.understand_mission_intent("check system status")
        assert isinstance(intent, MissionIntent)
>       assert intent.source == "deterministic_fallback"
E       AssertionError: assert 'model' == 'deterministic_fallback'
E         
E         - deterministic_fallback
E         + model

tests/test_r1_intent_characterization.py:180: AssertionError
_________________ test_r1c8_execution_class_confusion_rejected _________________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_r1c8_execution_class_conf0')
monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x7f06c2dc6c10>

    def test_r1c8_execution_class_confusion_rejected(tmp_path, monkeypatch):
        """CURRENT DEFENSE: an OWNER_DIRECT proof cannot be replayed against a
        MISSION_BOUND execution (mission_id present); class confusion fails
        closed (INV-PROOF-3).
        """
        from tools.registry import execute
    
        context = _owner_context(tmp_path, monkeypatch, request_id="req-c8b")
        decision, proof = _owner_direct_proof(context, tool="status")
        with pytest.raises(PermissionError, match="EXECUTION_CLASS_MISMATCH"):
>           execute(
                "status",
                authorization_decision=decision,
                request_id=context.request_id,
                execution_proof=proof,
                mission_id="mission-1",
            )

tests/test_r1_intent_characterization.py:540: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

name = 'status', argument = None

    def execute(name: str, argument: str | None = None, *, timeout: int | None = None, authorization_decision: Any = None, scope_context: dict[str, Any] | None = None, request_id: str | None = None, mission_authorization: Any = None, workspace: Any = None, evidence_store: Any = None, mission_id: str | None = None, target_identity: str | None = None, execution_proof: Any = None, execution_class: str | None = None):
        spec = get_tool(name)
        if spec is None:
            raise ValueError("unknown tool")
        # The registry is the last line of defense, not a policy creator. There is
        # no implicit "not mission-bound" escape hatch: a caller cannot opt out of
        # the proof boundary by omitting mission_id. Every governed execution is
        # classified (MISSION_BOUND when mission governance kwargs are present,
        # OWNER_DIRECT otherwise) and must carry an ExecutionAuthorizationProof of
        # exactly that class, derived from authorization that already exists.
        from security.execution_proof import ExecutionAuthorizationProof, ExecutionClass, RejectionCode
        mission_bound = mission_authorization is not None or workspace is not None or evidence_store is not None or bool(mission_id)
        resolved_class = str(execution_class or (ExecutionClass.MISSION_BOUND.value if mission_bound else ExecutionClass.OWNER_DIRECT.value))
        if execution_proof is None:
            raise PermissionError(f"{RejectionCode.PROOF_REQUIRED.value}: {resolved_class} execution requires an ExecutionAuthorizationProof")
        proof_ok, proof_reason, proof_code = ExecutionAuthorizationProof.verify(execution_proof, name=name, argument=argument, mission_id=mission_id, request_id=request_id)
        if not proof_ok:
>           raise PermissionError(f"{proof_code}: {proof_reason}")
E           PermissionError: PROOF_BINDING_MISMATCH: execution proof belongs to another mission

tools/registry.py:293: PermissionError

During handling of the above exception, another exception occurred:

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_r1c8_execution_class_conf0')
monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x7f06c2dc6c10>

    def test_r1c8_execution_class_confusion_rejected(tmp_path, monkeypatch):
        """CURRENT DEFENSE: an OWNER_DIRECT proof cannot be replayed against a
        MISSION_BOUND execution (mission_id present); class confusion fails
        closed (INV-PROOF-3).
        """
        from tools.registry import execute
    
        context = _owner_context(tmp_path, monkeypatch, request_id="req-c8b")
        decision, proof = _owner_direct_proof(context, tool="status")
>       with pytest.raises(PermissionError, match="EXECUTION_CLASS_MISMATCH"):
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       AssertionError: Regex pattern did not match.
E        Regex: 'EXECUTION_CLASS_MISMATCH'
E        Input: 'PROOF_BINDING_MISMATCH: execution proof belongs to another mission'

tests/test_r1_intent_characterization.py:539: AssertionError
_________________ test_r1c9_follow_up_intent_is_proposal_only __________________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_r1c9_follow_up_intent_is_0')

    def test_r1c9_follow_up_intent_is_proposal_only(tmp_path):
        """CURRENT BEHAVIOR: continue_mission_instruction records the follow-up
        intent in mission.progress as an UNVALIDATED proposal; it does not touch
        the authorization snapshot, the plan, or the lifecycle status.
    
        HAZARD NOTE: today there is no deterministic intent validator on the
        follow-up path (same R1-C3 hazard); the fix must route follow-ups
        through the deterministic validator before they influence anything.
        """
        store = MissionStore(Path(tmp_path) / "missions.sqlite3")
        runtime = MissionRuntime(store, executor=lambda mission, step, action_id: {"success": True, "source": step.action}, authorization_snapshot_factory=make_test_snapshot)
        mission = runtime.create("request", "objective", _plan(), request_id="req-c9")
        snapshot_before = dict(mission.authorization_snapshot)
        status_before = mission.status
    
        core = AgentCore(
            router=StubRouter(json.dumps({"objective": "also check the accounts"})),
            store=store,
        )
        updated = core.continue_mission_instruction(mission.mission_id, "also check the accounts")
    
        intents = updated.progress.get("mission_intents", [])
        assert len(intents) == 1
        assert intents[0]["instruction"] == "also check the accounts"
        assert intents[0]["intent"]["source"] == "model"
>       assert updated.authorization_snapshot == snapshot_before
E       AssertionError: assert {'allowed_act...1+00:00', ...} == {'allowed_act...1+00:00', ...}
E         
E         Omitting 17 identical items, use -vv to show
E         Differing items:
E         {'credential_boundary': {'allowed': []}} != {'credential_boundary': {'allowed': ()}}
E         {'data_boundary': {'allowed': ['test-target']}} != {'data_boundary': {'allowed': ('test-target',)}}
E         {'network_boundary': {'allowed': []}} != {'network_boundary': {'allowed': ()}}
E         
E         Full diff:
E           {
E               'allowed_actions': [
E                   'status',
E                   'search',
E                   'run_project_tests',
E               ],
E               'allowed_tools': [
E                   'status',
E                   'search',
E                   'run_project_tests',
E               ],
E               'authorization_hash': 'e0a877f40dc923b21da2bd5d7be506bbc7ae277433c5f083deaa64963091ce6b',
E               'created_at': '2026-09-25T12:21:50.132041+00:00',
E               'credential_boundary': {
E         -         'allowed': (),
E         ?                    ^^
E         +         'allowed': [],
E         ?                    ^^
E               },
E               'data_boundary': {
E         -         'allowed': (
E         ?                    ^
E         +         'allowed': [
E         ?                    ^
E                       'test-target',
E         -         ),
E         ?         ^
E         +         ],
E         ?         ^
E               },
E               'expires_at': '2026-09-25T13:21:50.132041+00:00',
E               'forbidden_actions': [],
E               'max_duration': 3000,
E               'mission_id': 'f5965a2bf0024f14a14af412790c2deb',
E               'network_boundary': {
E         -         'allowed': (),
E         ?                    ^^
E         +         'allowed': [],
E         ?                    ^^
E               },
E               'owner_approval': 'test-owner-approval',
E               'owner_identity': 'test-owner',
E               'policy_version': 'test-policy-v1',
E               'rate_limits': {
E                   'run_project_tests': 10,
E                   'search': 10,
E                   'status': 10,
E               },
E               'scope': [
E                   'workspace',
E               ],
E               'target_identity': 'test-target',
E               'time_window': {
E                   'timezone': 'UTC',
E               },
E               'version': 1,
E               'workspace_boundary': {
E                   'root': '/workspace/test',
E               },
E           }

tests/test_r1_intent_characterization.py:594: AssertionError
=========================== short test summary info ============================
FAILED tests/test_r1_intent_characterization.py::test_r1c1_invalid_model_output_falls_back_deterministically - AssertionError: assert 'model' == 'deterministic_fallback'
  
  - deterministic_fallback
  + model
FAILED tests/test_r1_intent_characterization.py::test_r1c8_execution_class_confusion_rejected - AssertionError: Regex pattern did not match.
 Regex: 'EXECUTION_CLASS_MISMATCH'
 Input: 'PROOF_BINDING_MISMATCH: execution proof belongs to another mission'
FAILED tests/test_r1_intent_characterization.py::test_r1c9_follow_up_intent_is_proposal_only - AssertionError: assert {'allowed_act...1+00:00', ...} == {'allowed_act...1+00:00', ...}
  
  Omitting 17 identical items, use -vv to show
  Differing items:
  {'credential_boundary': {'allowed': []}} != {'credential_boundary': {'allowed': ()}}
  {'data_boundary': {'allowed': ['test-target']}} != {'data_boundary': {'allowed': ('test-target',)}}
  {'network_boundary': {'allowed': []}} != {'network_boundary': {'allowed': ()}}
  
  Full diff:
    {
        'allowed_actions': [
            'status',
            'search',
            'run_project_tests',
        ],
        'allowed_tools': [
            'status',
            'search',
            'run_project_tests',
        ],
        'authorization_hash': 'e0a877f40dc923b21da2bd5d7be506bbc7ae277433c5f083deaa64963091ce6b',
        'created_at': '2026-09-25T12:21:50.132041+00:00',
        'credential_boundary': {
  -         'allowed': (),
  ?                    ^^
  +         'allowed': [],
  ?                    ^^
        },
        'data_boundary': {
  -         'allowed': (
  ?                    ^
  +         'allowed': [
  ?                    ^
                'test-target',
  -         ),
  ?         ^
  +         ],
  ?         ^
        },
        'expires_at': '2026-09-25T13:21:50.132041+00:00',
        'forbidden_actions': [],
        'max_duration': 3000,
        'mission_id': 'f5965a2bf0024f14a14af412790c2deb',
        'network_boundary': {
  -         'allowed': (),
  ?                    ^^
  +         'allowed': [],
  ?                    ^^
        },
        'owner_approval': 'test-owner-approval',
        'owner_identity': 'test-owner',
        'policy_version': 'test-policy-v1',
        'rate_limits': {
            'run_project_tests': 10,
            'search': 10,
            'status': 10,
        },
        'scope': [
            'workspace',
        ],
        'target_identity': 'test-target',
        'time_window': {
            'timezone': 'UTC',
        },
        'version': 1,
        'workspace_boundary': {
            'root': '/workspace/test',
        },
    }
3 failed, 746 passed, 1 skipped in 6.60s
