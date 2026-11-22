# CI run ec93fae1cd21
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
......................................................................FF [ 39%]
FFFFFF.................................................................. [ 44%]
........................................................................ [ 49%]
........................................................................ [ 54%]
........................................................................ [ 59%]
........................................................................ [ 64%]
........................................................................ [ 69%]
..s..................................................................... [ 74%]
........................................................................ [ 79%]
........................................................................ [ 84%]
........................................................................ [ 88%]
........................................................................ [ 93%]
........................................................................ [ 98%]
.................                                                        [100%]
=================================== FAILURES ===================================
______ test_registry_gate_rejects_non_bare_names_pre_seam[sub/probe.bin] _______

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_rejects_non0/artifacts')
seam_spies = {'open': count(0), 'stat': count(0)}, bad = 'sub/probe.bin'

    @pytest.mark.parametrize("bad", ["sub/probe.bin", "../probe.bin", "a\\b.bin", "..", ".", ".hidden", ""])
    def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, seam_spies, bad):
        _make_elf64(artifact_store)
        result = tools.registry.get_tool("local_binary_analysis").handler(bad)
        assert result["ok"] is False
        assert result["error"] == "BIN_ARGUMENT_INVALID"
        assert result["operation"] == "local_binary_analysis"
        # rejected BEFORE any filesystem seam is touched
>       assert len(seam_spies["stat"]) == 0
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:571: TypeError
_______ test_registry_gate_rejects_non_bare_names_pre_seam[../probe.bin] _______

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_rejects_non1/artifacts')
seam_spies = {'open': count(0), 'stat': count(0)}, bad = '../probe.bin'

    @pytest.mark.parametrize("bad", ["sub/probe.bin", "../probe.bin", "a\\b.bin", "..", ".", ".hidden", ""])
    def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, seam_spies, bad):
        _make_elf64(artifact_store)
        result = tools.registry.get_tool("local_binary_analysis").handler(bad)
        assert result["ok"] is False
        assert result["error"] == "BIN_ARGUMENT_INVALID"
        assert result["operation"] == "local_binary_analysis"
        # rejected BEFORE any filesystem seam is touched
>       assert len(seam_spies["stat"]) == 0
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:571: TypeError
_________ test_registry_gate_rejects_non_bare_names_pre_seam[a\\b.bin] _________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_rejects_non2/artifacts')
seam_spies = {'open': count(0), 'stat': count(0)}, bad = 'a\\b.bin'

    @pytest.mark.parametrize("bad", ["sub/probe.bin", "../probe.bin", "a\\b.bin", "..", ".", ".hidden", ""])
    def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, seam_spies, bad):
        _make_elf64(artifact_store)
        result = tools.registry.get_tool("local_binary_analysis").handler(bad)
        assert result["ok"] is False
        assert result["error"] == "BIN_ARGUMENT_INVALID"
        assert result["operation"] == "local_binary_analysis"
        # rejected BEFORE any filesystem seam is touched
>       assert len(seam_spies["stat"]) == 0
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:571: TypeError
____________ test_registry_gate_rejects_non_bare_names_pre_seam[..] ____________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_rejects_non3/artifacts')
seam_spies = {'open': count(0), 'stat': count(0)}, bad = '..'

    @pytest.mark.parametrize("bad", ["sub/probe.bin", "../probe.bin", "a\\b.bin", "..", ".", ".hidden", ""])
    def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, seam_spies, bad):
        _make_elf64(artifact_store)
        result = tools.registry.get_tool("local_binary_analysis").handler(bad)
        assert result["ok"] is False
        assert result["error"] == "BIN_ARGUMENT_INVALID"
        assert result["operation"] == "local_binary_analysis"
        # rejected BEFORE any filesystem seam is touched
>       assert len(seam_spies["stat"]) == 0
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:571: TypeError
____________ test_registry_gate_rejects_non_bare_names_pre_seam[.] _____________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_rejects_non4/artifacts')
seam_spies = {'open': count(0), 'stat': count(0)}, bad = '.'

    @pytest.mark.parametrize("bad", ["sub/probe.bin", "../probe.bin", "a\\b.bin", "..", ".", ".hidden", ""])
    def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, seam_spies, bad):
        _make_elf64(artifact_store)
        result = tools.registry.get_tool("local_binary_analysis").handler(bad)
        assert result["ok"] is False
        assert result["error"] == "BIN_ARGUMENT_INVALID"
        assert result["operation"] == "local_binary_analysis"
        # rejected BEFORE any filesystem seam is touched
>       assert len(seam_spies["stat"]) == 0
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:571: TypeError
_________ test_registry_gate_rejects_non_bare_names_pre_seam[.hidden] __________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_rejects_non5/artifacts')
seam_spies = {'open': count(0), 'stat': count(0)}, bad = '.hidden'

    @pytest.mark.parametrize("bad", ["sub/probe.bin", "../probe.bin", "a\\b.bin", "..", ".", ".hidden", ""])
    def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, seam_spies, bad):
        _make_elf64(artifact_store)
        result = tools.registry.get_tool("local_binary_analysis").handler(bad)
        assert result["ok"] is False
        assert result["error"] == "BIN_ARGUMENT_INVALID"
        assert result["operation"] == "local_binary_analysis"
        # rejected BEFORE any filesystem seam is touched
>       assert len(seam_spies["stat"]) == 0
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:571: TypeError
_____________ test_registry_gate_rejects_non_bare_names_pre_seam[] _____________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_rejects_non6/artifacts')
seam_spies = {'open': count(0), 'stat': count(0)}, bad = ''

    @pytest.mark.parametrize("bad", ["sub/probe.bin", "../probe.bin", "a\\b.bin", "..", ".", ".hidden", ""])
    def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, seam_spies, bad):
        _make_elf64(artifact_store)
        result = tools.registry.get_tool("local_binary_analysis").handler(bad)
        assert result["ok"] is False
        assert result["error"] == "BIN_ARGUMENT_INVALID"
        assert result["operation"] == "local_binary_analysis"
        # rejected BEFORE any filesystem seam is touched
>       assert len(seam_spies["stat"]) == 0
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:571: TypeError
_____________ test_registry_gate_then_valid_name_executes_bounded ______________

artifact_store = PosixPath('/tmp/pytest-of-runner/pytest-0/test_registry_gate_then_valid_0/artifacts')
seam_spies = {'open': count(1), 'stat': count(1)}

    def test_registry_gate_then_valid_name_executes_bounded(artifact_store, seam_spies):
        _make_elf64(artifact_store)
        spec = tools.registry.get_tool("local_binary_analysis")
        ok = spec.handler("probe.bin")
        assert ok["ok"] is True
        assert ok["header_fields"]["elf_machine"] == 62
        # exactly ONE stat + ONE capped read
>       assert len(seam_spies["stat"]) == 1
               ^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: object of type 'itertools.count' has no len()

tests/test_local_binary_analysis.py:582: TypeError
=========================== short test summary info ============================
FAILED tests/test_local_binary_analysis.py::test_registry_gate_rejects_non_bare_names_pre_seam[sub/probe.bin] - TypeError: object of type 'itertools.count' has no len()
FAILED tests/test_local_binary_analysis.py::test_registry_gate_rejects_non_bare_names_pre_seam[../probe.bin] - TypeError: object of type 'itertools.count' has no len()
FAILED tests/test_local_binary_analysis.py::test_registry_gate_rejects_non_bare_names_pre_seam[a\\b.bin] - TypeError: object of type 'itertools.count' has no len()
FAILED tests/test_local_binary_analysis.py::test_registry_gate_rejects_non_bare_names_pre_seam[..] - TypeError: object of type 'itertools.count' has no len()
FAILED tests/test_local_binary_analysis.py::test_registry_gate_rejects_non_bare_names_pre_seam[.] - TypeError: object of type 'itertools.count' has no len()
FAILED tests/test_local_binary_analysis.py::test_registry_gate_rejects_non_bare_names_pre_seam[.hidden] - TypeError: object of type 'itertools.count' has no len()
FAILED tests/test_local_binary_analysis.py::test_registry_gate_rejects_non_bare_names_pre_seam[] - TypeError: object of type 'itertools.count' has no len()
FAILED tests/test_local_binary_analysis.py::test_registry_gate_then_valid_name_executes_bounded - TypeError: object of type 'itertools.count' has no len()
8 failed, 1448 passed, 1 skipped in 19.75s
