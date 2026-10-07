from __future__ import annotations

import platform

from core import local_defense


def _mock_linux(monkeypatch, *, distro="Ubuntu 24.04.4 LTS"):
    monkeypatch.setattr(local_defense.platform, "system", lambda: "Linux")
    monkeypatch.setattr(local_defense.platform, "release", lambda: "6.18.38+")
    monkeypatch.setattr(
        local_defense.platform,
        "freedesktop_os_release",
        lambda: {"NAME": "Ubuntu", "PRETTY_NAME": distro},
    )
    monkeypatch.setattr(local_defense, "_has_android_runtime_marker", lambda: False)
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    monkeypatch.delenv("TERMUX_APP_PID", raising=False)
    monkeypatch.setenv("PREFIX", "/usr")


def test_ubuntu_is_reported_as_linux_distribution_not_termux(monkeypatch):
    _mock_linux(monkeypatch)

    identity = local_defense._runtime_identity()

    assert identity == {
        "platform": "Linux",
        "environment": "Ubuntu 24.04.4 LTS",
        "distribution": "Ubuntu 24.04.4 LTS",
    }


def test_android_and_real_termux_markers_are_distinguished(monkeypatch):
    _mock_linux(monkeypatch, distro="Android")
    monkeypatch.setattr(local_defense, "_has_android_runtime_marker", lambda: True)

    assert local_defense._runtime_identity()["environment"] == "Android"

    monkeypatch.setenv("TERMUX_VERSION", "0.118.0")
    assert local_defense._runtime_identity()["environment"] == "Termux"


def test_termux_variable_alone_does_not_misclassify_linux(monkeypatch):
    _mock_linux(monkeypatch)
    monkeypatch.setenv("TERMUX_VERSION", "untrusted-marker")

    assert local_defense._runtime_identity()["platform"] == "Linux"
    assert local_defense._runtime_identity()["environment"] == "Ubuntu 24.04.4 LTS"


def test_live_local_security_check_reports_real_current_host(monkeypatch):
    recorded = []
    monkeypatch.setattr(local_defense, "add_event", lambda *args: recorded.append(args))

    result = local_defense.local_security_check()

    assert result["platform"] == platform.system()
    assert result["environment"]
    assert result["device_scope"] == "this host only"
    assert "Termux/Android" not in str(result)
    assert result["listener_scan_status"] == (
        "completed" if local_defense.Path("/proc/net/tcp").is_file() else "unsupported"
    )
    assert len(recorded) == 1
    assert recorded[0][0] == "local_check"


def test_unsupported_platform_is_not_reported_as_a_clean_zero_listener_scan(monkeypatch):
    monkeypatch.setattr(
        local_defense,
        "_runtime_identity",
        lambda: {"platform": "Windows", "environment": "Windows", "distribution": None},
    )
    monkeypatch.setattr(local_defense, "_tcp_listeners", lambda: None)
    monkeypatch.setattr(local_defense, "_current_uid", lambda: None)
    monkeypatch.setattr(local_defense, "add_event", lambda *_args: None)

    result = local_defense.local_security_check()

    assert result["platform"] == "Windows"
    assert result["listener_scan_status"] == "unsupported"
    assert result["listener_scan_supported"] is False
    assert result["count"] is None
    assert result["tcp_listeners"] == []


def test_local_system_info_uses_same_platform_identity(monkeypatch):
    _mock_linux(monkeypatch)
    monkeypatch.setattr(local_defense, "add_event", lambda *_args: None)

    result = local_defense.local_system_info()

    assert result["platform"] == "Linux"
    assert result["environment"] == "Ubuntu 24.04.4 LTS"
    assert result["distribution"] == "Ubuntu 24.04.4 LTS"
