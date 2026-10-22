"""Trusted hosted-runner forensic capture, never a product launcher.

Run an unchanged test command under a bounded ProcMon capture. Trace failures
are recorded independently and NEVER replace or soften the test exit status.
Only ephemeral CI OS activity is captured; no credentials are passed to probes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import urllib.request
import zipfile

URL = "https://download.sysinternals.com/files/ProcessMonitor.zip"


def bounded(argv: list[str], timeout: int = 30) -> dict:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, errors="replace", timeout=timeout, check=False)
        return {"exit_code": result.returncode, "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": type(exc).__name__}


def main(command: list[str]) -> int:
    if sys.platform != "win32" or not command:
        raise SystemExit("native Windows and an explicit test command are required")
    output = Path("lpac-forensics")
    report = {"source_commit": os.environ.get("GITHUB_SHA"),
              "run_id": os.environ.get("GITHUB_RUN_ID"),
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "windows": platform.version(), "architecture": platform.machine(),
              "image": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
              "trace_source": URL, "capture_seconds_limit": 60,
              "scope": "ephemeral_hosted_runner_not_product_acceptance"}
    exe = output.resolve() / "Procmon64.exe"
    pml = output.resolve() / "launch.pml"
    capture = None
    test_code = 125
    try:
        output.mkdir(exist_ok=False)
        # Never terminate or attach to somebody else's ProcMon instance.
        existing = bounded(["tasklist", "/FI", "IMAGENAME eq Procmon64.exe", "/FO", "CSV", "/NH"])
        report["existing_procmon"] = existing
        if "Procmon64.exe" in existing.get("stdout", "") or "error" in existing:
            raise RuntimeError("existing_procmon_or_unmeasured_process_state")
        archive = output / "ProcessMonitor.zip"
        with urllib.request.urlopen(URL, timeout=30) as response:
            data = response.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise RuntimeError("download_size_limit")
        archive.write_bytes(data)
        report["download_sha256"] = hashlib.sha256(data).hexdigest()
        with zipfile.ZipFile(archive) as bundle:
            exe.write_bytes(bundle.read("Procmon64.exe"))
        # Use the workflow host: Windows PowerShell inherits pwsh's PSModulePath
        # and can fail to load its own security module before verification.
        signature = bounded(["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                             "$s=Get-AuthenticodeSignature -LiteralPath '" + str(exe) + "'; "
                             "@{status=[string]$s.Status;subject=$s.SignerCertificate.Subject;"
                             "version=(Get-Item -LiteralPath '" + str(exe) + "').VersionInfo.FileVersion} | ConvertTo-Json -Compress"])
        report["signature"] = signature
        verified = json.loads(signature.get("stdout", "{}"))
        if verified.get("status") != "Valid" or "Microsoft Corporation" not in verified.get("subject", ""):
            raise RuntimeError("signature_not_verified")
        report["start_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        capture = subprocess.Popen([str(exe), "/AcceptEula", "/Quiet", "/Minimized",
                                    "/BackingFile", str(pml), "/Runtime", "60"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        report["capture_pid"] = capture.pid
        report["wait_for_idle"] = bounded([str(exe), "/AcceptEula", "/WaitForIdle"], 15)
        report["capture_process_exit_before_tests"] = capture.poll()
    except Exception as exc:
        report["capture_setup_error"] = str(exc)[:500]
    try:
        # Keep exact argv and original test return code, including failures/skips.
        test = subprocess.run(command, stdin=subprocess.DEVNULL, timeout=180, check=False)
        test_code = test.returncode
    except subprocess.TimeoutExpired:
        report["test_timeout"] = True
        test_code = 124
    finally:
        try:
            finalize(output, report, capture, exe, pml, test_code)
        except Exception as exc:
            print("Trace finalization failed independently:", type(exc).__name__, flush=True)
    return test_code


def finalize(output, report, capture, exe, pml, test_code):
        if capture is not None:
            report["terminate"] = bounded([str(exe), "/AcceptEula", "/Terminate"], 20)
            try:
                report["capture_exit"] = capture.wait(timeout=15)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=5)
                report["capture_forced_stop"] = True
            if pml.is_file():
                report["pml_size"] = pml.stat().st_size
                report["export"] = bounded([str(exe), "/AcceptEula", "/Quiet", "/OpenLog", str(pml),
                                             "/SaveAs", str(output.resolve() / "launch.csv")], 60)
        report["end_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        report["test_exit_code"] = test_code
        report["hashes"] = {}
        for path in output.iterdir():
            if path.suffix.lower() in (".pml", ".csv", ".exe", ".zip"):
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                report["hashes"][path.name] = digest.hexdigest()
        csv_path = output / "launch.csv"
        report["trace_status"] = "CAPTURED" if (
            "capture_setup_error" not in report
            and report.get("wait_for_idle", {}).get("exit_code") == 0
            and report.get("capture_process_exit_before_tests") is None
            and not report.get("capture_forced_stop")
            and report.get("export", {}).get("exit_code") == 0
            and pml.is_file() and pml.stat().st_size > 0
            and csv_path.is_file() and csv_path.stat().st_size > 100
        ) else "UNAVAILABLE"
        (output / "capability.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("LPAC tracing capability:", json.dumps(report), flush=True)


def verify_trace():
    report = json.loads(Path("lpac-forensics/capability.json").read_text(encoding="utf-8"))
    if report.get("trace_status") != "CAPTURED":
        raise SystemExit("native_trace_evidence_unavailable: inspect capability.json; not proof tracing is prohibited")
    for name in ("launch.pml", "launch.csv"):
        path = Path("lpac-forensics") / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != report["hashes"].get(name):
            raise SystemExit("native_trace_hash_mismatch")
    print("Native trace captured and hash-verified; causal interpretation still required")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["--verify"]:
        verify_trace()
        raise SystemExit(0)
    if args[:1] == ["--"]:
        args = args[1:]
    raise SystemExit(main(args))
