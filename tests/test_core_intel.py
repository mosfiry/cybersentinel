import json

import core.intel as intel


def test_severity_for_kev_distinguishes_known_ransomware_use():
    assert intel.severity_for_kev({"knownRansomwareUse": "Known"}) == "critical"
    assert intel.severity_for_kev({"knownRansomwareUse": "Unknown"}) == "high"
    assert intel.severity_for_kev({}) == "high"


def test_collect_cisa_kev_is_deterministic_and_skips_missing_cve(monkeypatch):
    payload = {
        "vulnerabilities": [
            {
                "cveID": " CVE-2026-0001 ",
                "vendorProject": "Vendor",
                "product": "Product",
                "shortDescription": "Exploit description",
                "knownRansomwareUse": "Known",
                "dateAdded": "2026-01-01",
                "dueDate": "2026-01-08",
                "requiredAction": "Patch",
                "vulnerabilityName": "Example",
            },
            {"vendorProject": "ignored", "shortDescription": "no identifier"},
        ]
    }
    inserted = []
    events = []
    monkeypatch.setattr(intel, "_get", lambda url: json.dumps(payload).encode())
    monkeypatch.setattr(
        intel,
        "add_intel",
        lambda *args: inserted.append(args) or True,
    )
    monkeypatch.setattr(intel, "add_event", lambda *args: events.append(args))

    result = intel.collect_cisa_kev()

    assert result == {"source": "CISA KEV", "total": 2, "new": 1}
    assert inserted == [
        (
            "CVE-2026-0001",
            "CISA KEV",
            "CVE-2026-0001 — Vendor Product",
            "Exploit description",
            "critical",
            {
                "dateAdded": "2026-01-01",
                "dueDate": "2026-01-08",
                "knownRansomwareUse": "Known",
                "requiredAction": "Patch",
                "vulnerabilityName": "Example",
            },
        )
    ]
    assert events and events[0][0:2] == ("intel", "CISA KEV collection completed")


def test_collect_cisa_advisories_uses_guid_and_truncates_description(monkeypatch):
    long_description = "x" * 4500
    xml = f"""<rss><channel>
        <item><title>Advisory one</title><link>https://example/1</link>
        <description>{long_description}</description><guid>guid-1</guid></item>
        <item><title></title><link>https://example/ignored</link>
        <description>ignored</description><guid>guid-ignored</guid></item>
        <item><title>Advisory two</title><link>https://example/2</link>
        <description>short</description></item>
    </channel></rss>"""
    inserted = []
    events = []
    monkeypatch.setattr(intel, "_get", lambda url: xml.encode())
    monkeypatch.setattr(
        intel,
        "add_intel",
        lambda *args: inserted.append(args) or (len(inserted) == 1),
    )
    monkeypatch.setattr(intel, "add_event", lambda *args: events.append(args))

    result = intel.collect_cisa_advisories()

    assert result == {"source": "CISA Advisories", "new": 1}
    assert inserted[0][0:5] == (
        "guid-1",
        "CISA Advisories",
        "Advisory one",
        "x" * 4000,
        "info",
    )
    assert inserted[0][5] == {"url": "https://example/1"}
    assert inserted[1][0] == "https://example/2"
    assert events and events[0][0:2] == ("intel", "CISA advisory collection completed")


def test_refresh_all_reports_source_error_without_hiding_success(monkeypatch):
    events = []
    monkeypatch.setattr(intel, "collect_cisa_kev", lambda: {"source": "CISA KEV", "new": 2})

    def fail():
        raise RuntimeError("feed unavailable")

    monkeypatch.setattr(intel, "collect_cisa_advisories", fail)
    monkeypatch.setattr(intel, "add_event", lambda *args: events.append(args))

    result = intel.refresh_all()

    assert result == {
        "ok": False,
        "results": [{"source": "CISA KEV", "new": 2}],
        "errors": [{"source": "fail", "error": "feed unavailable"}],
    }
    assert events == [("intel", "Intel source failed", "feed unavailable", "fail", "warning", False)]


def test_latest_intel_delegates_limit(monkeypatch):
    calls = []
    monkeypatch.setattr(intel, "intel_recent", lambda limit: calls.append(limit) or [{"id": 1}])

    assert intel.latest_intel(7) == [{"id": 1}]
    assert calls == [7]
