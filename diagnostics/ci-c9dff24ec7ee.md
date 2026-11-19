# CI run c9dff24ec7ee
result: SUCCESS

## compileall output (last 100 lines)

## pytest output (last 400 lines)
........................................................................ [  5%]
........................................................................ [ 10%]
........................................................................ [ 16%]
........................................................................ [ 21%]
........................................................................ [ 26%]
........................................................................ [ 32%]
........................................................................ [ 37%]
........................................................................ [ 42%]
........................................................................ [ 48%]
........................................................................ [ 53%]
........................................................................ [ 58%]
........................................................................ [ 64%]
.........................................................s.............. [ 69%]
.............................................F.......................... [ 75%]
........................................................................ [ 80%]
........................................................................ [ 85%]
........................................................................ [ 91%]
........................................................................ [ 96%]
...............................................                          [100%]
=================================== FAILURES ===================================
___________________ test_banner_beyond_hard_cap_is_truncated ___________________

monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x71809b3a8b40>

    def test_banner_beyond_hard_cap_is_truncated(monkeypatch):
        big = b"x" * (SCOPED_PORT_BANNER_MAX_BYTES + 5)
        monkeypatch.setattr(tools.registry, "_port_observe", lambda *a, **k: big)
        result = _scoped_port_observation("https://target.example/")
        assert result["ok"] is True
        assert result["banner_truncated"] is True
>       assert len((result["banner_printable"] or "")) == 0
E       AssertionError: assert 128 == 0
E        +  where 128 = len(('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'))

tests/test_scoped_port_observation.py:128: AssertionError
=========================== short test summary info ============================
FAILED tests/test_scoped_port_observation.py::test_banner_beyond_hard_cap_is_truncated - AssertionError: assert 128 == 0
 +  where 128 = len(('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'))
1 failed, 1341 passed, 1 skipped in 19.04s
