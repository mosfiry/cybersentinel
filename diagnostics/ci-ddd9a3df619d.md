# CI run ddd9a3df619d
result: SUCCESS

## compileall output (last 100 lines)
./tools/registry.py:784: SyntaxWarning: invalid escape sequence '\e'
  ("mach_o_32", b"\xce\xfa\ed\xfe"),

## pytest output (last 400 lines)
........................................................................ [  5%]
........................................................................ [ 10%]
........................................................................ [ 15%]
........................................................................ [ 20%]
........................................................................ [ 25%]
........................................................................ [ 30%]
........................................................................ [ 35%]
............FF.F........................................................ [ 40%]
........................................................................ [ 46%]
........................................................................ [ 51%]
........................................................................ [ 56%]
........................................................................ [ 61%]
........................................................................ [ 66%]
......................s................................................. [ 71%]
........................................................................ [ 76%]
........................................................................ [ 81%]
........................................................................ [ 87%]
........................................................................ [ 92%]
........................................................................ [ 97%]
.....................................                                    [100%]
=================================== FAILURES ===================================
________________ test_tool_is_not_in_default_security_inventory ________________

    def test_tool_is_not_in_default_security_inventory():
>       from cyber.offensive import DEFAULT_SECURITY_TOOL_INVENTORY
E       ImportError: cannot import name 'DEFAULT_SECURITY_TOOL_INVENTORY' from 'cyber.offensive' (/home/runner/work/cybersentinel/cybersentinel/cyber/offensive.py)

tests/test_local_artifact_metadata.py:285: ImportError
____________________ test_live_artifact_metadata_full_chain ____________________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_live_artifact_metadata_fu0')
execute_spy = []
artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_live_artifact_metadata_fu0/artifacts')

    def test_live_artifact_metadata_full_chain(tmp_path, execute_spy, artifact_store):
        runtime = _runtime(tmp_path)
        mission = _mission(runtime, action="local_artifact_metadata")
        mission.progress["model_run_id"] = "run-1"
        _make_elf(artifact_store)
        proposal = _proposal(mission, execution_run_id="run-1")
        record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
>       assert record.status == "EXECUTED", record.result.error_state
E       AssertionError: {'code': 'INPUT_INVALID', 'phase': 'VALIDATE_INPUT', 'reason': 'local_artifact_metadata requires a string argument', 'rejection_code': '', ...}
E       assert 'REJECTED' == 'EXECUTED'
E         
E         - EXECUTED
E         ?  ^  -
E         + REJECTED
E         ? + ^

tests/test_local_artifact_metadata.py:302: AssertionError
_____________ test_live_missing_artifact_is_classified_observation _____________

tmp_path = PosixPath('/tmp/pytest-of-runner/pytest-0/test_live_missing_artifact_is_0')
execute_spy = []
artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_live_missing_artifact_is_0/artifacts')

    def test_live_missing_artifact_is_classified_observation(tmp_path, execute_spy, artifact_store):
        # A missing artifact is a deterministic handler classification (an
        # OBSERVED fact), not an authorization failure: the registry boundary is
        # reached and the handler's META_NOT_FOUND is carried as untrusted output.
        runtime = _runtime(tmp_path)
        mission = _mission(runtime, action="local_artifact_metadata")
        mission.progress["model_run_id"] = "run-1"
        proposal = _proposal(mission, execution_run_id="run-1")
        record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
>       assert record.status == "EXECUTED", record.result.error_state
E       AssertionError: {'code': 'INPUT_INVALID', 'phase': 'VALIDATE_INPUT', 'reason': 'local_artifact_metadata requires a string argument', 'rejection_code': '', ...}
E       assert 'REJECTED' == 'EXECUTED'
E         
E         - EXECUTED
E         ?  ^  -
E         + REJECTED
E         ? + ^

tests/test_local_artifact_metadata.py:337: AssertionError
=========================== short test summary info ============================
FAILED tests/test_local_artifact_metadata.py::test_tool_is_not_in_default_security_inventory - ImportError: cannot import name 'DEFAULT_SECURITY_TOOL_INVENTORY' from 'cyber.offensive' (/home/runner/work/cybersentinel/cybersentinel/cyber/offensive.py)
FAILED tests/test_local_artifact_metadata.py::test_live_artifact_metadata_full_chain - AssertionError: {'code': 'INPUT_INVALID', 'phase': 'VALIDATE_INPUT', 'reason': 'local_artifact_metadata requires a string argument', 'rejection_code': '', ...}
assert 'REJECTED' == 'EXECUTED'
  
  - EXECUTED
  ?  ^  -
  + REJECTED
  ? + ^
FAILED tests/test_local_artifact_metadata.py::test_live_missing_artifact_is_classified_observation - AssertionError: {'code': 'INPUT_INVALID', 'phase': 'VALIDATE_INPUT', 'reason': 'local_artifact_metadata requires a string argument', 'rejection_code': '', ...}
assert 'REJECTED' == 'EXECUTED'
  
  - EXECUTED
  ?  ^  -
  + REJECTED
  ? + ^
3 failed, 1401 passed, 1 skipped in 17.53s
