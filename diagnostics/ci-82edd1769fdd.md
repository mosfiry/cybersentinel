# CI run 82edd1769fdd
result: FAILURE

## pytest failed (exit 1)
........................................................................ [ 14%]
..F..................................................................... [ 29%]
........................................................................ [ 44%]
........................................................................ [ 59%]
........................................................................ [ 74%]
...........................................s............................ [ 89%]
.....................................................                    [100%]
=================================== FAILURES ===================================
___ test_explicitly_out_of_scope_asset_refuses_even_if_wildcard_would_match ____

    def test_explicitly_out_of_scope_asset_refuses_even_if_wildcard_would_match():
        snap = snapshot_with(
            program([web_asset("*.target.example")], out_of_scope=[web_asset("admin.target.example")]),
            [target("target.example")],
        )
        planner = OffensiveExecutionPlanner()
        plan = planner.plan_actions(
            [
                OffensiveAction(url="https://api.target.example/"),
                OffensiveAction(url="https://admin.target.example/"),
            ],
            snap,
        )
        urls = [a.url for a in plan["executable"]]
>       assert "https://api.target.example/" in urls
E       AssertionError: assert 'https://api.target.example/' in []

tests/test_cyber_offensive_scope.py:110: AssertionError
=========================== short test summary info ============================
FAILED tests/test_cyber_offensive_scope.py::test_explicitly_out_of_scope_asset_refuses_even_if_wildcard_would_match - AssertionError: assert 'https://api.target.example/' in []
1 failed, 483 passed, 1 skipped in 23.09s
