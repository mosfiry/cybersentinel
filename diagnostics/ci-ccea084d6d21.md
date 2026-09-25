# CI run ccea084d6d21
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
........................................................................ [ 10%]
........................................................................ [ 20%]
........................................................................ [ 30%]
........................................................................ [ 40%]
........................................................................ [ 50%]
........................................................................ [ 60%]
........................................................................ [ 70%]
........................................................................ [ 80%]
..................................................s..................... [ 90%]
......................................................F................  [100%]
=================================== FAILURES ===================================
________________________ test_tool_timeout_is_explicit _________________________

monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x7efeef646970>

    def test_tool_timeout_is_explicit(monkeypatch):
        def slow(_):
            import time
            time.sleep(0.05)
            return {"ok": True}
        monkeypatch.setitem(registry.REGISTRY, "slow_test", ToolSpec("slow_test", "test", "read", True, None, slow))
        import security.owner_policy as owner_policy
        from security.authorization import authorize_tool
        from security.authorization_context import AuthorizationContext
        from security.execution_boundary import OwnerDirectBoundary
    
        evidence = owner_policy._issue_evidence("owner_token", "v46-timeout", "test")
        auth_context = AuthorizationContext("v46-timeout", evidence, owner_policy.capture_policy_snapshot("v46-timeout", evidence))
        decision = authorize_tool(["slow_test", None], context=auth_context)
>       assert decision.allowed
E       AssertionError: assert False
E        +  where False = AuthorizationResult(allowed=False, reason='unknown tool', name='slow_test', argument=None, risk_class=None, decision=A...on_context', arguments_hash='', decision_signature='f937afe97d681f53de570a1c491e4dd66c09b1fec71ba1958a1781cdc2ef4b17')).allowed

tests/test_v46_lifecycle.py:69: AssertionError
=========================== short test summary info ============================
FAILED tests/test_v46_lifecycle.py::test_tool_timeout_is_explicit - AssertionError: assert False
 +  where False = AuthorizationResult(allowed=False, reason='unknown tool', name='slow_test', argument=None, risk_class=None, decision=A...on_context', arguments_hash='', decision_signature='f937afe97d681f53de570a1c491e4dd66c09b1fec71ba1958a1781cdc2ef4b17')).allowed
1 failed, 717 passed, 1 skipped in 11.52s
