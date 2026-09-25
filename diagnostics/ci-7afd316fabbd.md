# CI run 7afd316fabbd
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
........................................................................ [  8%]
........................................................................ [ 17%]
........................................................................ [ 25%]
........................................................................ [ 34%]
........................................................................ [ 43%]
........................................................................ [ 51%]
........................................................................ [ 60%]
........................................................................ [ 68%]
........................................................................ [ 77%]
.....................................................s.................. [ 86%]
.................................................F...................... [ 94%]
.............................................                            [100%]
=================================== FAILURES ===================================
_____________ test_b3a_malformed_model_proposal_fails_closed[None] _____________

bad = None

    @pytest.mark.parametrize("bad", [None, "text", 42, [], [42], [{"objective": ""}], [[]], [[]]])
    def test_b3a_malformed_model_proposal_fails_closed(bad):
>       with pytest.raises(TaskIntentError):
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       Failed: DID NOT RAISE <class 'security.intent_ladder.TaskIntentError'>

tests/test_task_intent_authorization.py:82: Failed
=========================== short test summary info ============================
FAILED tests/test_task_intent_authorization.py::test_b3a_malformed_model_proposal_fails_closed[None] - Failed: DID NOT RAISE <class 'security.intent_ladder.TaskIntentError'>
1 failed, 835 passed, 1 skipped in 9.40s
