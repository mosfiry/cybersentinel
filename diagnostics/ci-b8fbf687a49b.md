# CI run b8fbf687a49b
result: FAILURE

## pytest failed (exit 1)
.......................................................................F [ 14%]
.F...................................................................... [ 28%]
........................................................................ [ 42%]
........................................................................ [ 57%]
........................................................................ [ 71%]
...............................................................s........ [ 85%]
........................................................................ [ 99%]
.                                                                        [100%]
=================================== FAILURES ===================================
______________ test_engine_finds_seeded_findings_through_evidence ______________

    def test_engine_finds_seeded_findings_through_evidence():
        result = run_lab_evaluation(effort=ReasoningEffort.DEEP)
>       assert result["seeded_findings_found"] == len(LAB_TARGETS)
E       AssertionError: assert 1 == 3
E        +  where 3 = len((SyntheticTarget(target_id='synth-commerce-1', profile='ecommerce', assets=[SyntheticAsset(asset_id='a-web', surface='..., SyntheticAsset(asset_id='u-vpn', surface='vpn gateway', details={'tech': 'synthetic-vpn'})], seeded_finding='u-sso')))

tests/test_cyber_lab.py:35: AssertionError
_____________ test_unknown_technique_critique_is_raised_for_decoys _____________

    def test_unknown_technique_critique_is_raised_for_decoys():
        result = run_lab_evaluation(effort=ReasoningEffort.DEEP)
>       assert result["unknown_technique_critiques_raised"] == len(LAB_TARGETS)
E       AssertionError: assert 0 == 3
E        +  where 3 = len((SyntheticTarget(target_id='synth-commerce-1', profile='ecommerce', assets=[SyntheticAsset(asset_id='a-web', surface='..., SyntheticAsset(asset_id='u-vpn', surface='vpn gateway', details={'tech': 'synthetic-vpn'})], seeded_finding='u-sso')))

tests/test_cyber_lab.py:50: AssertionError
=========================== short test summary info ============================
FAILED tests/test_cyber_lab.py::test_engine_finds_seeded_findings_through_evidence - AssertionError: assert 1 == 3
 +  where 3 = len((SyntheticTarget(target_id='synth-commerce-1', profile='ecommerce', assets=[SyntheticAsset(asset_id='a-web', surface='..., SyntheticAsset(asset_id='u-vpn', surface='vpn gateway', details={'tech': 'synthetic-vpn'})], seeded_finding='u-sso')))
FAILED tests/test_cyber_lab.py::test_unknown_technique_critique_is_raised_for_decoys - AssertionError: assert 0 == 3
 +  where 3 = len((SyntheticTarget(target_id='synth-commerce-1', profile='ecommerce', assets=[SyntheticAsset(asset_id='a-web', surface='..., SyntheticAsset(asset_id='u-vpn', surface='vpn gateway', details={'tech': 'synthetic-vpn'})], seeded_finding='u-sso')))
2 failed, 502 passed, 1 skipped in 7.12s
