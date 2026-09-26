from __future__ import annotations
import os
import socket
from pathlib import Path
from .db import add_event

def _tcp_listeners():
    path=Path("/proc/net/tcp")
    out=[]
    if not path.exists():
        return out
    for row in path.read_text(errors="replace").splitlines()[1:]:
        parts=row.split()
        if len(parts)<4 or parts[3]!="0A":
            continue
        try:
            ip_hex, port_hex=parts[1].split(":")
            ip=socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
            port=int(port_hex,16)
            out.append({"protocol":"tcp","ip":ip,"port":port})
        except Exception:
            continue
    return out

def local_security_check():
    listeners=_tcp_listeners()
    findings=[]
    for x in listeners:
        scope="loopback" if x["ip"]=="127.0.0.1" else "non-loopback"
        findings.append({**x,"scope":scope})
    result={
        "device_scope":"this Termux/Android device only",
        "uid":os.getuid(),
        "tcp_listeners":findings,
        "count":len(findings),
    }
    sev="warning" if any(x["scope"]=="non-loopback" for x in findings) else "info"
    add_event("local_check","Local TCP listener check",
              __import__("json").dumps(result,ensure_ascii=False),
              "local:/proc/net/tcp",sev,True,result)
    return result

def local_system_info():
    info={
        "platform":os.uname().sysname if hasattr(os,"uname") else "unknown",
        "kernel":os.uname().release if hasattr(os,"uname") else "unknown",
        "machine":os.uname().machine if hasattr(os,"uname") else "unknown",
        "python":__import__("sys").version.split()[0],
        "cwd":os.getcwd(),
    }
    add_event("local_check","Local system information",
              __import__("json").dumps(info,ensure_ascii=False),
              "local:runtime","info",True,info)
    return info

def local_process_info():
    import shutil
    import subprocess
    resolved=shutil.which("ps")
    if not resolved:
        raise RuntimeError("local process listing unavailable: required binary 'ps' not found on PATH (fail closed)")
    try:
        completed=subprocess.run(
            [resolved,"-eo","pid=,ppid=,user=,comm=","--no-headers"],
            capture_output=True,text=True,timeout=10,check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("local process listing timed out after 10 seconds")
    if completed.returncode!=0 or not completed.stdout:
        raise RuntimeError("local process listing unavailable: ps failed")
    stdout=completed.stdout
    processes=[]
    rows_truncated=False
    command_truncated=False
    for line in stdout.splitlines():
        parts=line.split(None,3)
        if len(parts)!=4:
            continue
        try:
            command=parts[3]
            if len(command)>256:
                command=command[:256]
                command_truncated=True
            processes.append({"pid":int(parts[0]),"ppid":int(parts[1]),"user":parts[2],"command":command})
        except ValueError:
            continue
        if len(processes)>=4096:
            rows_truncated=True
            break
    info={"processes":processes,"count":len(processes),
          "output_truncated":rows_truncated or command_truncated,
          "binary":resolved}
    add_event("local_check","Local process listing",
              __import__("json").dumps(info,ensure_ascii=False),
              "local:runtime","info",True,info)
    return info
