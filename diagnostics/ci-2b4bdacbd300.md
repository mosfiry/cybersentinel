# CI run 2b4bdacbd300
result: FAILURE

## pytest failed (exit 1)
........................................................................ [  9%]
........................................................................ [ 18%]
........................................................................ [ 28%]
........................................................................ [ 37%]
........................................................................ [ 47%]
........................................................................ [ 56%]
........................................................................ [ 66%]
........................................................................ [ 75%]
.................................................................s...... [ 85%]
...................................F.................................... [ 94%]
.........................................                                [100%]
=================================== FAILURES ===================================
______________ test_terminal_and_recovery_transitions_are_closed _______________

    def test_terminal_and_recovery_transitions_are_closed():
        mission = Mission.create("owner", "objective", Plan.initial("objective"), request_id="req-2")
        mission.transition(MissionStatus.READY, "prepared")
        mission.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous")
        with pytest.raises(ValueError, match="reconciliation"):
>           mission.transition(MissionStatus.GOAL_COMPLETED, "forged completion")

tests/test_security_integrity_adversarial.py:114: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

self = Mission(mission_id='7c36f682a8b34111a859dbda748f27d7', owner_request='owner', objective='objective', status=<MissionSt...gy_decisions=[], replan_history=[], verification_history=[], recovery_events=[], semantic_intent={}, integrity_hash='')
target = <MissionStatus.GOAL_COMPLETED: 'GOAL_COMPLETED'>
reason = 'forged completion', data = {}

    def transition(self, target: MissionStatus, reason: str, **data: Any) -> None:
        if not isinstance(target, MissionStatus):
            raise TypeError("mission transition requires MissionStatus")
        # SYSTEM INVARIANT (truthfulness T2): GOAL_COMPLETED is impossible without
        # the deterministic goal-verification state written by MissionRuntime.
        # No caller (model, API, worker, library) can complete a mission by assertion.
        if target is MissionStatus.GOAL_COMPLETED and self.verification_state.get("verified") is not True:
>           raise ValueError("GOAL_COMPLETED is a system invariant: deterministic goal verification state is required")
E           ValueError: GOAL_COMPLETED is a system invariant: deterministic goal verification state is required

agent/mission.py:108: ValueError

During handling of the above exception, another exception occurred:

    def test_terminal_and_recovery_transitions_are_closed():
        mission = Mission.create("owner", "objective", Plan.initial("objective"), request_id="req-2")
        mission.transition(MissionStatus.READY, "prepared")
        mission.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous")
>       with pytest.raises(ValueError, match="reconciliation"):
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       AssertionError: Regex pattern did not match.
E        Regex: 'reconciliation'
E        Input: 'GOAL_COMPLETED is a system invariant: deterministic goal verification state is required'

tests/test_security_integrity_adversarial.py:113: AssertionError
=========================== short test summary info ============================
FAILED tests/test_security_integrity_adversarial.py::test_terminal_and_recovery_transitions_are_closed - AssertionError: Regex pattern did not match.
 Regex: 'reconciliation'
 Input: 'GOAL_COMPLETED is a system invariant: deterministic goal verification state is required'
1 failed, 759 passed, 1 skipped in 20.53s
