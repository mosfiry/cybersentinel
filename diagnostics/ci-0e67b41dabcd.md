# CI run 0e67b41dabcd
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
........................................................................ [  4%]
........................................................................ [  9%]
........................................................................ [ 14%]
........................................................................ [ 19%]
........................................................................ [ 24%]
........................................................................ [ 29%]
........................................................................ [ 34%]
.............................F...........F.............................. [ 39%]
........................................................................ [ 44%]
........................................................................ [ 49%]
........................................................................ [ 54%]
........................................................................ [ 59%]
........................................................................ [ 64%]
.................................................................s...... [ 69%]
........................................................................ [ 74%]
........................................................................ [ 79%]
........................................................................ [ 84%]
........................................................................ [ 89%]
........................................................................ [ 94%]
........................................................................ [ 99%]
........                                                                 [100%]
=================================== FAILURES ===================================
________________________ test_handler_success_universal ________________________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_handler_success_universal0/artifacts')

    def test_handler_success_universal(artifact_store):
        _make_universal(artifact_store)
        result = tools.registry._binary_header_analysis("probe.universal")
        assert result["ok"] is True
        assert result["format_family"] == "mach_o_universal"
>       assert result["header_fields"]["universal_fat_arch_count"] == 2
E       assert 33554432 == 2

tests/test_local_binary_analysis.py:233: AssertionError
__________________ test_handler_parser_failure_is_classified ___________________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_handler_parser_failure_is0/artifacts')
monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x792ef3460a60>

    def test_handler_parser_failure_is_classified(artifact_store, monkeypatch):
        _make_elf64(artifact_store)
        real = tools.registry._parse_elf_header
        monkeypatch.setattr(tools.registry, "_parse_elf_header", lambda p: real(p).no_such_key())  # type: ignore[attr-defined]
        result = tools.registry._binary_header_analysis("probe.bin")
>       assert result["ok"] is False
E       assert True is False

tests/test_local_binary_analysis.py:346: AssertionError
=========================== short test summary info ============================
FAILED tests/test_local_binary_analysis.py::test_handler_success_universal - assert 33554432 == 2
FAILED tests/test_local_binary_analysis.py::test_handler_parser_failure_is_classified - assert True is False
2 failed, 1445 passed, 1 skipped in 18.06s
