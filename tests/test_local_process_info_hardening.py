"""Stage C hardening battery: local_process_info external-binary handler.

Adversarial coverage for the ONLY subprocess-backed runtime tool (per the
Stage C mission checklist):

- binary identity: the handler executes the RESOLVED absolute path returned
  by shutil.which, never a bare PATH-relative name (no PATH-hijack window
  between resolution and execution).
- fail closed: an unresolvable binary raises BEFORE any process spawn.
- argv vector: the command is a fixed argument list (shell-free); tool
  output and process names are DATA, never shell syntax.
- process lifecycle: non-zero exit, empty stdout, and timeout become
  deterministic RuntimeError failures; no partial result is ever returned.
- output bounding: parsed rows and command strings are capped with explicit
  truncation flags; malformed rows are skipped deterministically.
- evidence: add_event records the same structured, local, read-only info
  (no secrets, no credentials, no authority-shaped fields).
"""

import subprocess

import pytest

import core.local_defense as local_defense
from core.local_defense import local_process_info


class _Completed:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _install(monkeypatch, *, which="/usr/bin/ps", run=None):
    """Patch which/run/add_event; return (spawn_calls, evidence_events)."""
    calls = []
    events = []
    monkeypatch.setattr(local_defense, "add_event",
                        lambda *a, **k: events.append((a, k)))
    monkeypatch.setattr("shutil.which", lambda name: which)
    if run is None:
        def run_default(*args, **kwargs):
            calls.append((args, kwargs))
            return _Completed(stdout="  1  0 root init\n")
        run = run_default
    def recording_run(*args, **kwargs):
        calls.append((args, kwargs))
        return run(*args, **kwargs)
    monkeypatch.setattr(subprocess, "run", recording_run)
    return calls, events


def test_resolved_absolute_path_is_executed(monkeypatch):
    calls, _ = _install(monkeypatch, which="/resolved/ps")
    local_process_info()
    argv = calls[0][0][0]
    assert argv[0] == "/resolved/ps"
    assert argv[0] != "ps"


def test_fail_closed_when_binary_unresolvable(monkeypatch):
    calls, _ = _install(monkeypatch, which=None)
    with pytest.raises(RuntimeError, match="not found on PATH"):
        local_process_info()
    assert calls == []


def test_fixed_argv_vector_and_no_shell(monkeypatch):
    calls, _ = _install(monkeypatch, which="/resolved/ps")
    local_process_info()
    args, kwargs = calls[0]
    assert args[0] == ["/resolved/ps", "-eo", "pid=,ppid=,user=,comm=", "--no-headers"]
    assert isinstance(args[0], list)
    assert not kwargs.get("shell")
    assert kwargs.get("timeout") == 10
    assert kwargs.get("check") is False
    assert kwargs.get("capture_output") is True


def test_nonzero_exit_fails_deterministically(monkeypatch):
    _install(monkeypatch, run=lambda *a, **k: _Completed(returncode=1, stdout="x"))
    with pytest.raises(RuntimeError, match="ps failed"):
        local_process_info()


def test_empty_stdout_fails_deterministically(monkeypatch):
    _install(monkeypatch, run=lambda *a, **k: _Completed(returncode=0, stdout=""))
    with pytest.raises(RuntimeError, match="ps failed"):
        local_process_info()


def test_timeout_is_classified_not_swallowed(monkeypatch):
    def hang(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=10)
    _install(monkeypatch, run=hang)
    with pytest.raises(RuntimeError, match="timed out"):
        local_process_info()


def test_malformed_rows_are_skipped(monkeypatch):
    stdout = "only three columns\n1 0 root\n2 0 root sh\nnot pid root cmd\n"
    _install(monkeypatch, run=lambda *a, **k: _Completed(stdout=stdout))
    info = local_process_info()
    assert info["count"] == 1
    assert info["processes"][0]["pid"] == 2


def test_row_cap_bounds_output(monkeypatch):
    stdout = "".join(f"{i} 1 root proc{i}\n" for i in range(1, 6000))
    _install(monkeypatch, run=lambda *a, **k: _Completed(stdout=stdout))
    info = local_process_info()
    assert info["count"] == 4096
    assert info["output_truncated"] is True


def test_command_strings_are_truncated(monkeypatch):
    long_cmd = "x" * 400
    stdout = f"1 0 root {long_cmd}\n"
    _install(monkeypatch, run=lambda *a, **k: _Completed(stdout=stdout))
    info = local_process_info()
    assert len(info["processes"][0]["command"]) == 256
    assert info["output_truncated"] is True


def test_no_truncation_flags_when_output_small(monkeypatch):
    _install(monkeypatch, run=lambda *a, **k: _Completed(stdout="1 0 root init\n"))
    info = local_process_info()
    assert info["output_truncated"] is False
    assert info["count"] == 1


def test_shell_metacharacters_in_output_are_data(monkeypatch):
    hostile = "sh; rm -rf / && $(reboot) `id` | cat /etc/passwd"
    stdout = f"1 0 root {hostile}\n"
    calls, _ = _install(monkeypatch, run=lambda *a, **k: _Completed(stdout=stdout))
    info = local_process_info()
    assert info["processes"][0]["command"] == hostile
    assert len(calls) == 1


def test_evidence_event_records_structured_info(monkeypatch):
    _, events = _install(monkeypatch, run=lambda *a, **k: _Completed(stdout="1 0 root init\n"))
    info = local_process_info()
    assert len(events) == 1
    args, _kwargs = events[0]
    assert args[0] == "local_check"
    recorded = args[6]
    assert recorded == info
    assert recorded["binary"] == "/usr/bin/ps"
    for key in recorded:
        assert key not in (
            "authorization", "proof", "policy", "scope", "token",
            "credential", "secret", "owner",
        )
