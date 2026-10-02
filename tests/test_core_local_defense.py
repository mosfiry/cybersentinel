from types import SimpleNamespace

import core.local_defense as defense


def test_tcp_listeners_parses_listening_rows_and_ignores_invalid_rows(monkeypatch):
    class FakeProcFile:
        def exists(self):
            return True

        def read_text(self, errors=None):
            return "\n".join(
                [
                    "sl local_address rem_address st",
                    "1: 0100007F:1F90 00000000:0000 0A",
                    "2: 00000000:0016 00000000:0000 01",
                    "3: 00000000:0050 00000000:0000 0A",
                    "4: malformed row",
                    "5: GG000000:0050 00000000:0000 0A",
                ]
            )

    monkeypatch.setattr(defense, "Path", lambda _path: FakeProcFile())

    assert defense._tcp_listeners() == [
        {"protocol": "tcp", "ip": "127.0.0.1", "port": 8080},
        {"protocol": "tcp", "ip": "0.0.0.0", "port": 80},
    ]


def test_tcp_listeners_returns_empty_when_proc_file_is_unavailable(monkeypatch):
    class MissingProcFile:
        def exists(self):
            return False

    monkeypatch.setattr(defense, "Path", lambda _path: MissingProcFile())

    assert defense._tcp_listeners() == []


def test_local_security_check_marks_non_loopback_and_records_warning(monkeypatch):
    listeners = [
        {"protocol": "tcp", "ip": "127.0.0.1", "port": 8080},
        {"protocol": "tcp", "ip": "0.0.0.0", "port": 22},
    ]
    events = []
    monkeypatch.setattr(defense, "_tcp_listeners", lambda: listeners)
    monkeypatch.setattr(defense, "add_event", lambda *args: events.append(args))
    monkeypatch.setattr(defense.os, "getuid", lambda: 1000)

    result = defense.local_security_check()

    assert result["device_scope"] == "this Termux/Android device only"
    assert result["uid"] == 1000
    assert result["count"] == 2
    assert [item["scope"] for item in result["tcp_listeners"]] == ["loopback", "non-loopback"]
    assert events[0][0:2] == ("local_check", "Local TCP listener check")
    assert events[0][4:6] == ("warning", True)


def test_local_security_check_uses_info_for_loopback_only(monkeypatch):
    events = []
    monkeypatch.setattr(
        defense,
        "_tcp_listeners",
        lambda: [{"protocol": "tcp", "ip": "127.0.0.1", "port": 3000}],
    )
    monkeypatch.setattr(defense, "add_event", lambda *args: events.append(args))

    result = defense.local_security_check()

    assert result["count"] == 1
    assert result["tcp_listeners"][0]["scope"] == "loopback"
    assert events[0][4] == "info"


def test_local_system_info_records_runtime_metadata(monkeypatch):
    events = []
    monkeypatch.setattr(
        defense.os,
        "uname",
        lambda: SimpleNamespace(sysname="TestOS", release="1.2.3", machine="test-machine"),
    )
    monkeypatch.setattr(defense.os, "getcwd", lambda: "/tmp/cybersentinel")
    monkeypatch.setattr(defense, "add_event", lambda *args: events.append(args))

    result = defense.local_system_info()

    assert result["platform"] == "TestOS"
    assert result["kernel"] == "1.2.3"
    assert result["machine"] == "test-machine"
    assert result["cwd"] == "/tmp/cybersentinel"
    assert events[0][0:2] == ("local_check", "Local system information")
    assert events[0][4:6] == ("info", True)
