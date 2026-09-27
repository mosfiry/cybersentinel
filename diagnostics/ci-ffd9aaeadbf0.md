# CI run ffd9aaeadbf0
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
........................................................................ [  5%]
........................................................................ [ 10%]
.........................................................F.............. [ 16%]
........................................................................ [ 21%]
........................................................................ [ 27%]
........................................................................ [ 32%]
........................................................................ [ 38%]
........................................................................ [ 43%]
........................................................................ [ 49%]
........................................................................ [ 54%]
........................................................................ [ 60%]
........................................................................ [ 65%]
.........................................................s.............. [ 71%]
........................................................................ [ 76%]
........................................................................ [ 82%]
........................................................................ [ 87%]
........................................................................ [ 93%]
........................................................................ [ 98%]
....................                                                     [100%]
=================================== FAILURES ===================================
_____ test_owner_direct_class_cannot_be_smuggled_via_explicit_class_kwarg ______

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_owner_direct_class_cannot0')
monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x7f29d393df60>
counting_status = <test_b3_c5_second_pass_attacker_review.CountingStatus object at 0x7f29d39bb450>

    def test_owner_direct_class_cannot_be_smuggled_via_explicit_class_kwarg(tmp_path, monkeypatch, counting_status):
        """An attacker marking a no-decision call explicitly OWNER_DIRECT still fails closed (class is not authority)."""
        decision = _owner_decision(tmp_path, monkeypatch)
        proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="call_od6")
        with pytest.raises(PermissionError, match=RejectionCode.PROOF_INCOMPLETE.value):
            registry_execute("status", None, execution_proof=proof, execution_class=ExecutionClass.OWNER_DIRECT.value)
        assert counting_status.calls == 0
        # and the mission class stays mandatory for mission-bound calls
        runtime = _runtime(tmp_path)
        mission = _mission(runtime)
        with pytest.raises(PermissionError, match=RejectionCode.EXECUTION_CLASS_MISMATCH.value):
>           registry_execute(
                "status",
                None,
                mission_id=mission.mission_id,
                request_id=mission.request_id,
                mission_authorization=_snapshot(mission),
                execution_proof=proof,
                execution_class=ExecutionClass.MISSION_BOUND.value,
                execution_run_id="run-x",
            )

tests/test_b3_c5_second_pass_attacker_review.py:304: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

name = 'status', argument = None

    def execute(name: str, argument: str | None = None, *, timeout: int | None = None, authorization_decision: Any = None, scope_context: dict[str, Any] | None = None, request_id: str | None = None, mission_authorization: Any = None, workspace: Any = None, evidence_store: Any = None, mission_id: str | None = None, target_identity: str | None = None, execution_proof: Any = None, execution_class: str | None = None, execution_run_id: str | None = None):
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
        proof_ok, proof_reason, proof_code = ExecutionAuthorizationProof.verify(execution_proof, name=name, argument=argument, mission_id=mission_id, request_id=request_id, run_id=execution_run_id)
        if not proof_ok:
>           raise PermissionError(f"{proof_code}: {proof_reason}")
E           PermissionError: PROOF_BINDING_MISMATCH: execution proof belongs to another mission

tools/registry.py:590: PermissionError

During handling of the above exception, another exception occurred:

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_owner_direct_class_cannot0')
monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x7f29d393df60>
counting_status = <test_b3_c5_second_pass_attacker_review.CountingStatus object at 0x7f29d39bb450>

    def test_owner_direct_class_cannot_be_smuggled_via_explicit_class_kwarg(tmp_path, monkeypatch, counting_status):
        """An attacker marking a no-decision call explicitly OWNER_DIRECT still fails closed (class is not authority)."""
        decision = _owner_decision(tmp_path, monkeypatch)
        proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="call_od6")
        with pytest.raises(PermissionError, match=RejectionCode.PROOF_INCOMPLETE.value):
            registry_execute("status", None, execution_proof=proof, execution_class=ExecutionClass.OWNER_DIRECT.value)
        assert counting_status.calls == 0
        # and the mission class stays mandatory for mission-bound calls
        runtime = _runtime(tmp_path)
        mission = _mission(runtime)
>       with pytest.raises(PermissionError, match=RejectionCode.EXECUTION_CLASS_MISMATCH.value):
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       AssertionError: Regex pattern did not match.
E        Regex: 'EXECUTION_CLASS_MISMATCH'
E        Input: 'PROOF_BINDING_MISMATCH: execution proof belongs to another mission'

tests/test_b3_c5_second_pass_attacker_review.py:303: AssertionError
=========================== short test summary info ============================
FAILED tests/test_b3_c5_second_pass_attacker_review.py::test_owner_direct_class_cannot_be_smuggled_via_explicit_class_kwarg - AssertionError: Regex pattern did not match.
 Regex: 'EXECUTION_CLASS_MISMATCH'
 Input: 'PROOF_BINDING_MISMATCH: execution proof belongs to another mission'
1 failed, 1314 passed, 1 skipped in 18.61s
