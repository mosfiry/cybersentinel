"""Seed knowledge corpus: a curated, real MITRE ATT&CK subset.

Provenance honesty: these technique ids/names/tactics come from the ATT&CK
public knowledge base, reproduced from offline model knowledge at seed time.
They are therefore classified PARTIAL (one source, not independently fetched
from the live feed in this run) - confidence capped, upgradeable to REAL
when the live feed is ingested over them with independent provenance.

This corpus gives the graph domain breadth; it grants no execution authority.
"""

from __future__ import annotations

from typing import Any

from cyber.intel_ingest import IntelIngest
from cyber.knowledge_model import CyberKnowledgeGraph, SourceClass

# (technique_id, name, tactic, [platform keywords], [behavior keywords])
_CORPUS: list[tuple[str, str, str, list[str], list[str]]] = [
    ("T1059", "Command and Scripting Interpreter", "execution", ["windows", "linux", "macos"], ["script", "interpreter", "shell", "command"]),
    ("T1059.001", "PowerShell", "execution", ["windows"], ["powershell", "script", "interpreter"]),
    ("T1059.003", "Windows Command Shell", "execution", ["windows"], ["cmd", "command", "shell"]),
    ("T1059.004", "Unix Shell", "execution", ["linux", "macos"], ["bash", "sh", "unix", "shell"]),
    ("T1059.009", "Cloud API", "execution", ["iaas"], ["cloud", "api", "cli"]),
    ("T1078", "Valid Accounts", "defense-evasion", ["windows", "linux", "cloud"], ["valid", "account", "credentials", "login"]),
    ("T1078.004", "Cloud Accounts", "defense-evasion", ["iaas"], ["cloud", "account", "credentials", "valid"]),
    ("T1566", "Phishing", "initial-access", ["windows", "linux", "macos"], ["phishing", "email", "lure", "attachment"]),
    ("T1566.001", "Spearphishing Attachment", "initial-access", ["windows", "linux", "macos"], ["phishing", "email", "attachment", "lure"]),
    ("T1190", "Exploit Public-Facing Application", "initial-access", ["windows", "linux"], ["exploit", "public", "web", "application", "internet"]),
    ("T1133", "External Remote Services", "initial-access", ["windows", "linux"], ["vpn", "remote", "rdp", "ssh", "external"]),
    ("T1055", "Process Injection", "defense-evasion", ["windows", "linux", "macos"], ["injection", "process", "memory", "hijack"]),
    ("T1003", "OS Credential Dumping", "credential-access", ["windows", "linux"], ["credentials", "dumping", "lsass", "hashes", "secrets"]),
    ("T1003.001", "LSASS Memory", "credential-access", ["windows"], ["lsass", "memory", "credentials", "mimikatz"]),
    ("T1110", "Brute Force", "credential-access", ["windows", "linux", "cloud"], ["brute", "force", "password", "guessing", "spraying"]),
    ("T1098", "Account Manipulation", "persistence", ["windows", "linux", "cloud"], ["account", "manipulation", "add", "permissions"]),
    ("T1136", "Create Account", "persistence", ["windows", "linux", "cloud"], ["account", "create", "new", "user"]),
    ("T1547", "Boot or Logon Autostart Execution", "persistence", ["windows", "linux"], ["autostart", "boot", "logon", "persistence"]),
    ("T1547.001", "Registry Run Keys / Startup Folder", "persistence", ["windows"], ["registry", "run", "key", "startup", "persistence"]),
    ("T1027", "Obfuscated Files or Information", "defense-evasion", ["windows", "linux", "macos"], ["obfuscation", "encoded", "packed", "encrypted", "obfuscated"]),
    ("T1036", "Masquerading", "defense-evasion", ["windows", "linux"], ["masquerade", "rename", "impersonate", "disguise"]),
    ("T1071", "Application Layer Protocol", "command-and-control", ["windows", "linux"], ["c2", "protocol", "http", "dns", "network"]),
    ("T1071.001", "Web Protocols", "command-and-control", ["windows", "linux"], ["http", "https", "web", "c2", "beacon"]),
    ("T1105", "Ingress Tool Transfer", "command-and-control", ["windows", "linux"], ["download", "transfer", "tool", "ingress", "payload"]),
    ("T1041", "Exfiltration Over C2 Channel", "exfiltration", ["windows", "linux"], ["exfiltration", "c2", "channel", "data"]),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration", ["windows", "linux"], ["exfiltration", "alternative", "protocol", "dns", "icmp"]),
    ("T1074", "Data Staged", "collection", ["windows", "linux"], ["stage", "collected", "data", "staging"]),
    ("T1486", "Data Encrypted for Impact", "impact", ["windows", "linux"], ["ransomware", "encrypt", "impact", "ransom"]),
    ("T1485", "Data Destruction", "impact", ["windows", "linux"], ["destroy", "wipe", "delete", "impact"]),
    ("T1490", "Inhibit System Recovery", "impact", ["windows"], ["recovery", "shadow", "backup", "delete", "restore"]),
    ("T1489", "Service Stop", "impact", ["windows", "linux"], ["service", "stop", "disable", "shutdown"]),
    # -- discovery ------------------------------------------------------
    ("T1087", "Account Discovery", "discovery", ["windows", "linux", "cloud"], ["account", "discovery", "enumerate", "users"]),
    ("T1083", "File and Directory Discovery", "discovery", ["windows", "linux"], ["file", "directory", "discovery", "enumerate"]),
    ("T1046", "Network Service Discovery", "discovery", ["windows", "linux"], ["network", "service", "port", "scan", "discovery"]),
    ("T1057", "Process Discovery", "discovery", ["windows", "linux", "macos"], ["process", "discovery", "enumerate", "task"]),
    ("T1069", "Permission Groups Discovery", "discovery", ["windows", "linux", "cloud"], ["permission", "group", "discovery", "enumerate"]),
    ("T1580", "Cloud Infrastructure Discovery", "discovery", ["iaas"], ["cloud", "infrastructure", "discovery", "enumerate"]),
    # -- lateral movement -------------------------------------------------
    ("T1021", "Remote Services", "lateral-movement", ["windows", "linux"], ["remote", "services", "lateral", "session"]),
    ("T1021.001", "Remote Desktop Protocol", "lateral-movement", ["windows"], ["rdp", "remote", "desktop", "lateral"]),
    ("T1550", "Use Alternate Authentication Material", "lateral-movement", ["windows"], ["authentication", "material", "token", "hash", "ticket"]),
    ("T1550.002", "Pass the Hash", "lateral-movement", ["windows"], ["pass", "hash", "ntlm", "lateral", "authentication"]),
    ("T1570", "Lateral Tool Transfer", "lateral-movement", ["windows", "linux"], ["tool", "transfer", "lateral", "copy"]),
    # -- privilege escalation ----------------------------------------------
    ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation", ["windows", "linux"], ["exploit", "privilege", "escalation", "elevation", "vulnerability"]),
    ("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation", ["windows", "linux"], ["elevation", "control", "abuse", "sudo", "uac"]),
    ("T1548.002", "Bypass User Account Control", "privilege-escalation", ["windows"], ["uac", "bypass", "elevation", "control"]),
    ("T1134", "Access Token Manipulation", "privilege-escalation", ["windows"], ["token", "manipulation", "impersonate", "privilege"]),
    # -- cloud impact/collection ---------------------------------------------
    ("T1530", "Data from Cloud Storage", "collection", ["iaas"], ["cloud", "storage", "data", "download"]),
    ("T1496", "Resource Hijacking", "impact", ["iaas", "windows", "linux"], ["resource", "hijacking", "cryptomining", "compute"]),
]

_CVE_CORPUS: list[tuple[str, float, str, str, str, str]] = [
    # (cve_id, cvss, description, vendor, product, version) - well-known historical entries
    ("CVE-2017-0144", 8.1, "SMBv1 server RCE (Eternal family)", "microsoft", "windows-smbv1", "win7"),
    ("CVE-2014-6271", 10.0, "GNU Bash command injection via environment variables (Shellshock)", "gnu", "bash", "4.3"),
    ("CVE-2019-0708", 9.8, "Remote Desktop Services RCE (BlueKeep)", "microsoft", "rdp", "server-2008"),
    ("CVE-2021-44228", 10.0, "Log4j2 JNDI lookup RCE (Log4Shell)", "apache", "log4j2", "2.14"),
    ("CVE-2017-5638", 10.0, "Apache Struts Content-Type header OGNL injection", "apache", "struts", "2.3.31"),
    ("CVE-2018-7600", 9.8, "Drupal core remote code execution (Drupalgeddon2)", "drupal", "drupal-core", "7.57"),
]


def build_seed_graph() -> tuple[CyberKnowledgeGraph, int]:
    """Ingest the ATT&CK and CVE seed corpora into a fresh graph."""
    graph = CyberKnowledgeGraph()
    ingest = IntelIngest(graph)
    # parents first then sub-techniques is handled by the two-pass ingest
    bundle_objects: list[dict[str, Any]] = []
    for tech_id, name, tactic, platforms, keywords in _CORPUS:
        bundle_objects.append({
            "type": "attack-pattern",
            "id": "seed--{}".format(tech_id),
            "name": name,
            "external_references": [{"source": "mitre-attack", "external_id": tech_id}],
            "kill_chain_phases": [{"phase_name": tactic}],
            "x_synth_platforms": list(platforms),
            "x_synth_behavior_keywords": list(keywords),
        })
    ingest.ingest_attack_stix(
        {"type": "bundle", "objects": bundle_objects},
        source="mitre-attack-seed",
        source_class=SourceClass.PARTIAL,
    )
    for cve_id, cvss, desc, vendor, product, version in _CVE_CORPUS:
        ingest.ingest_nvd_item(
            {"cve": {"id": cve_id, "cvss": cvss, "descriptions": [{"lang": "en", "value": desc}]},
             "affected": [{"vendor": vendor, "product": product, "version": version}]},
            source="nvd-seed",
            source_class=SourceClass.PARTIAL,
        )
    return graph, len(_CORPUS)


def corpus_size() -> int:
    return len(_CORPUS)


def cve_corpus_size() -> int:
    return len(_CVE_CORPUS)


def corpus_technique_ids() -> list[str]:
    return [t[0] for t in _CORPUS]


def corpus_cve_ids() -> list[str]:
    return [c[0] for c in _CVE_CORPUS]
