from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from kali.taxonomy import KaliToolCategory

# Deterministic risk classes (inputs to the authorization policy; they never
# authorize or forbid anything on their own).
RISK_CLASSES = (
    "READ_ONLY",
    "LOW_IMPACT",
    "ACTIVE_SCAN",
    "FUZZING",
    "AUTHENTICATED_TEST",
    "PRIVILEGED",
    "DESTRUCTIVE",
    "EXPLOITATION_CAPABLE",
)

# Well-known Linux capability names used in privileges_required metadata.
KNOWN_PRIVILEGES = (
    "CAP_NET_RAW",
    "CAP_NET_ADMIN",
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_DAC_OVERRIDE",
    "NONE",
)


@dataclass(frozen=True)
class KaliToolSpec:
    tool_id: str
    canonical_name: str
    executable: str
    package_name: str
    kali_category: KaliToolCategory
    description: str
    capabilities: tuple[str, ...]
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    network_required: bool = False
    privileges_required: tuple[str, ...] = ("NONE",)
    credential_required: bool = False
    target_required: bool = True
    destructive_risk: str = "LOW_IMPACT"
    scope_requirements: tuple[str, ...] = ()
    workspace_requirements: tuple[str, ...] = ()
    timeout: int = 120
    rate_limit: str = "bounded"
    evidence_support: tuple[str, ...] = ("observation",)
    execution_adapter: str = "local_cli"
    version: str = "unknown"
    inventory_provenance: str = "kali_seed_inventory_2026_09"
    # availability is a *runtime* fact, discovered by kali.discovery, never a
    # static claim. The spec only records the inventory source.
    provenance: str = "kali_seed_inventory"

    def __post_init__(self) -> None:
        if not self.tool_id or not self.executable:
            raise ValueError("kali tool spec requires tool_id and executable")
        if self.destructive_risk not in RISK_CLASSES:
            raise ValueError(f"unknown risk class: {self.destructive_risk}")
        for privilege in self.privileges_required:
            if privilege not in KNOWN_PRIVILEGES:
                raise ValueError(f"unknown privilege: {privilege}")

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "canonical_name": self.canonical_name,
            "executable": self.executable,
            "package_name": self.package_name,
            "kali_category": self.kali_category.value,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "network_required": self.network_required,
            "privileges_required": list(self.privileges_required),
            "credential_required": self.credential_required,
            "target_required": self.target_required,
            "destructive_risk": self.destructive_risk,
            "scope_requirements": list(self.scope_requirements),
            "workspace_requirements": list(self.workspace_requirements),
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "evidence_support": list(self.evidence_support),
            "execution_adapter": self.execution_adapter,
            "version": self.version,
            "inventory_provenance": self.inventory_provenance,
            "provenance": self.provenance,
        }


class KaliToolRegistry:
    """Extensible registry of Kali tool metadata.

    The registry describes *capability*, never *authorization*. Adding a tool
    here makes it technically representable; it does not make it runnable
    (availability) nor permitted (authorization).
    """

    def __init__(self, tools: Iterable[KaliToolSpec] = ()) -> None:
        self._tools: dict[str, KaliToolSpec] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: KaliToolSpec) -> KaliToolSpec:
        if tool.tool_id in self._tools:
            raise ValueError(f"duplicate tool_id: {tool.tool_id}")
        self._tools[tool.tool_id] = tool
        return tool

    def get(self, tool_id: str) -> KaliToolSpec | None:
        return self._tools.get(tool_id)

    def require(self, tool_id: str) -> KaliToolSpec:
        tool = self._tools.get(tool_id)
        if tool is None:
            raise KeyError(f"unknown kali tool: {tool_id}")
        return tool

    def all_tools(self) -> tuple[KaliToolSpec, ...]:
        return tuple(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)

    def by_category(self, category: KaliToolCategory) -> tuple[KaliToolSpec, ...]:
        return tuple(t for t in self._tools.values() if t.kali_category is category)

    def by_capability(self, capability: str) -> tuple[KaliToolSpec, ...]:
        return tuple(t for t in self._tools.values() if capability in t.capabilities)

    def search(self, *, capabilities: Iterable[str] = (), category: KaliToolCategory | None = None) -> tuple[KaliToolSpec, ...]:
        """Internal, deterministic tool selection support.

        The model (or the planner) may use this to *propose* tools; selection
        never grants authorization.
        """
        tools = self.all_tools()
        for capability in capabilities:
            tools = tuple(t for t in tools if capability in t.capabilities)
        if category is not None:
            tools = tuple(t for t in tools if t.kali_category is category)
        return tools


def _t(
    tool_id: str,
    name: str,
    executable: str,
    package: str,
    category: KaliToolCategory,
    description: str,
    capabilities: tuple[str, ...],
    *,
    network: bool = True,
    privileges: tuple[str, ...] = ("NONE",),
    credential: bool = False,
    risk: str = "ACTIVE_SCAN",
    timeout: int = 120,
    target: bool = True,
) -> KaliToolSpec:
    return KaliToolSpec(
        tool_id=tool_id,
        canonical_name=name,
        executable=executable,
        package_name=package,
        kali_category=category,
        description=description,
        capabilities=capabilities,
        input_schema={"type": "object", "properties": {"target": {"type": "string"}, "options": {"type": "array"}}},
        output_schema={"type": "object", "properties": {"stdout": {"type": "string"}, "artifacts": {"type": "array"}}},
        network_required=network,
        privileges_required=privileges,
        credential_required=credential,
        target_required=target,
        destructive_risk=risk,
        scope_requirements=("target_in_scope",) if target else (),
        workspace_requirements=(),
        timeout=timeout,
        rate_limit="bounded",
        evidence_support=("observation", "stdout_capture"),
        execution_adapter="local_cli",
        version="kali-current",
        inventory_provenance="kali_seed_inventory_2026_09",
        provenance="kali_seed_inventory",
    )


def _seed_inventory() -> tuple[KaliToolSpec, ...]:
    C = KaliToolCategory
    return (
        # --- Information Gathering ---
        _t("nmap", "Nmap", "nmap", "nmap", C.INFORMATION_GATHERING,
           "Network discovery and port scanning", ("network_scan", "port_scan", "service_detection"),
           privileges=("CAP_NET_RAW",), risk="ACTIVE_SCAN", timeout=300),
        _t("masscan", "Masscan", "masscan", "masscan", C.INFORMATION_GATHERING,
           "Fast TCP port scanner", ("network_scan", "port_scan"),
           privileges=("CAP_NET_RAW",), risk="ACTIVE_SCAN", timeout=180),
        _t("httpx", "httpx", "httpx", "httpx", C.INFORMATION_GATHERING,
           "HTTP toolkit for probing and tech detection", ("http_probe", "tech_detection"), risk="LOW_IMPACT"),
        _t("dnsrecon", "DNSRecon", "dnsrecon", "dnsrecon", C.INFORMATION_GATHERING,
           "DNS enumeration and reconnaissance", ("dns_enum", "zone_transfer"), risk="LOW_IMPACT"),
        _t("theHarvester", "theHarvester", "theHarvester", "theharvester", C.OSINT,
           "Email, subdomain and names gathering from public sources", ("osint_email_enum", "subdomain_enum"),
           risk="READ_ONLY", target=False),
        _t("subfinder", "Subfinder", "subfinder", "subfinder", C.INFORMATION_GATHERING,
           "Passive subdomain discovery", ("subdomain_enum",), risk="READ_ONLY"),
        _t("amass", "OWASP Amass", "amass", "amass", C.INFORMATION_GATHERING,
           "Attack surface mapping and asset discovery", ("subdomain_enum", "attack_surface_mapping"), risk="LOW_IMPACT"),
        _t("nikto", "Nikto", "nikto", "nikto", C.WEB_APPLICATIONS,
           "Web server scanner for known misconfigurations", ("web_scan", "server_misconfig_detection"), risk="ACTIVE_SCAN"),
        _t("dnsenum", "dnsenum", "dnsenum", "dnsenum", C.INFORMATION_GATHERING,
           "DNS enumeration", ("dns_enum",), risk="LOW_IMPACT"),
        _t("recon-ng", "Recon-ng", "recon-ng", "recon-ng", C.INFORMATION_GATHERING,
           "Web reconnaissance framework", ("osint_recon", "module_framework"), risk="READ_ONLY", target=False),
        _t("sherlock", "Sherlock", "sherlock", "sherlock", C.OSINT,
           "Username enumeration across social networks", ("osint_username_enum",), risk="READ_ONLY", target=False),

        # --- Vulnerability Analysis / Web Applications ---
        _t("nuclei", "Nuclei", "nuclei", "nuclei", C.VULNERABILITY_ANALYSIS,
           "Template-based vulnerability scanner", ("vulnerability_scan", "web_scan", "cve_detection"), risk="ACTIVE_SCAN"),
        _t("nikto2", "Nikto (alias entry)", "nikto", "nikto", C.VULNERABILITY_ANALYSIS,
           "Duplicate category coverage for web scanning pipelines", ("web_scan",), risk="ACTIVE_SCAN"),
        _t("ffuf", "FFUF", "ffuf", "ffuf", C.WEB_APPLICATIONS,
           "Fast web fuzzer for content discovery", ("content_discovery", "web_fuzz"), risk="FUZZING"),
        _t("feroxbuster", "Feroxbuster", "feroxbuster", "feroxbuster", C.WEB_APPLICATIONS,
           "Recursive content discovery", ("content_discovery", "web_fuzz"), risk="FUZZING"),
        _t("gobuster", "Gobuster", "gobuster", "gobuster", C.WEB_APPLICATIONS,
           "Directory/file/DNS busting", ("content_discovery",), risk="FUZZING"),
        _t("sqlmap", "sqlmap", "sqlmap", "sqlmap", C.DATABASE_ASSESSMENT,
           "Automatic SQL injection detection and exploitation", ("sqli_detection", "database_dump"),
           credential=False, risk="EXPLOITATION_CAPABLE", timeout=600),
        _t("wpscan", "WPScan", "wpscan", "wpscan", C.WEB_APPLICATIONS,
           "WordPress vulnerability scanner", ("web_scan", "cms_scan"), risk="ACTIVE_SCAN"),
        _t("openvas", "OpenVAS/GVM", "openvas", "openvas", C.VULNERABILITY_ANALYSIS,
           "Full vulnerability assessment scanner", ("vulnerability_scan", "authenticated_scan"),
           credential=True, risk="AUTHENTICATED_TEST", timeout=3600),
        _t("nessus_cli", "Nessus CLI (community)", "nessus", "nessus", C.VULNERABILITY_ANALYSIS,
           "Commercial scanner CLI bridge", ("vulnerability_scan",), credential=True, risk="AUTHENTICATED_TEST"),
        _t("searchsploit", "Searchsploit", "searchsploit", "exploitdb", C.VULNERABILITY_ANALYSIS,
           "Local Exploit-DB search", ("exploit_search", "cve_lookup"), risk="READ_ONLY", network=False, target=False),
        _t("legion", "Legion", "legion", "legion", C.VULNERABILITY_ANALYSIS,
           "Semi-automated network penetration testing", ("network_scan", "vulnerability_scan"), risk="ACTIVE_SCAN"),

        # --- Database Assessment ---
        _t("mdbtools", "MDB Tools", "mdb-tools", "mdbtools", C.DATABASE_ASSESSMENT,
           "Access MS Access databases", ("database_inspection",), network=False, risk="LOW_IMPACT"),
        _t("sqlite_browser_cli", "sqlite3 CLI", "sqlite3", "sqlite3", C.DATABASE_ASSESSMENT,
           "SQLite database inspection", ("database_inspection",), network=False, risk="LOW_IMPACT"),

        # --- Password Attacks ---
        _t("hydra", "Hydra", "hydra", "hydra", C.PASSWORD_ATTACKS,
           "Parallel network login cracker", ("password_spray", "brute_force"), risk="ACTIVE_SCAN", timeout=600),
        _t("john", "John the Ripper", "john", "john", C.PASSWORD_ATTACKS,
           "Offline password cracker", ("hash_cracking",), network=False, risk="LOW_IMPACT", target=False),
        _t("hashcat", "Hashcat", "hashcat", "hashcat", C.PASSWORD_ATTACKS,
           "GPU-accelerated offline hash cracking", ("hash_cracking",), network=False, risk="LOW_IMPACT", target=False),
        _t("medusa", "Medusa", "medusa", "medusa", C.PASSWORD_ATTACKS,
           "Parallel network login brute-forcer", ("brute_force",), risk="ACTIVE_SCAN"),
        _t("cewl", "CeWL", "cewl", "cewl", C.PASSWORD_ATTACKS,
           "Custom wordlist generator by spidering", ("wordlist_generation",), risk="LOW_IMPACT"),

        # --- Wireless ---
        _t("aircrack-ng", "Aircrack-ng suite", "aircrack-ng", "aircrack-ng", C.WIRELESS,
           "WiFi security assessment suite", ("wifi_scan", "wifi_capture", "handshake_capture"),
           privileges=("CAP_NET_ADMIN", "CAP_NET_RAW"), risk="PRIVILEGED", timeout=900, network=False),
        _t("kismet", "Kismet", "kismet", "kismet", C.WIRELESS,
           "Wireless network detector and IDS", ("wifi_scan", "wifi_monitor"),
           privileges=("CAP_NET_RAW",), risk="PRIVILEGED", network=False),
        _t("wifite", "Wifite", "wifite", "wifite", C.WIRELESS,
           "Automated wireless auditing", ("wifi_scan", "handshake_capture"),
           privileges=("CAP_NET_ADMIN",), risk="PRIVILEGED", network=False),
        _t("bully", "Bully", "bully", "bully", C.WIRELESS,
           "WPS brute-force attack tool", ("wps_attack", "brute_force"),
           privileges=("CAP_NET_RAW",), risk="PRIVILEGED", network=False),

        # --- Reverse Engineering ---
        _t("ghidra", "Ghidra", "ghidra", "ghidra", C.REVERSE_ENGINEERING,
           "Software reverse engineering suite", ("binary_analysis", "decompilation"), network=False, risk="READ_ONLY", target=False),
        _t("radare2", "Radare2", "r2", "radare2", C.REVERSE_ENGINEERING,
           "Unix-like reverse engineering framework", ("binary_analysis", "disassembly"), network=False, risk="READ_ONLY", target=False),
        _t("objdump", "Objdump", "objdump", "binutils", C.REVERSE_ENGINEERING,
           "Binary disassembly inspection", ("disassembly",), network=False, risk="READ_ONLY", target=False),
        _t("apktool", "Apktool", "apktool", "apktool", C.REVERSE_ENGINEERING,
           "Android APK reverse engineering", ("apk_analysis", "decompilation"), network=False, risk="READ_ONLY", target=False),
        _t("gdb_pwndbg", "GDB + Pwndbg", "gdb", "gdb", C.REVERSE_ENGINEERING,
           "Binary debugging with exploit dev extensions", ("binary_debugging", "exploit_dev"),
           privileges=("CAP_SYS_PTRACE",), network=False, risk="PRIVILEGED", target=False),

        # --- Exploitation Tools ---
        _t("metasploit", "Metasploit Framework", "msfconsole", "metasploit-framework", C.EXPLOITATION_TOOLS,
           "Exploitation and post-exploitation framework", ("exploitation", "payload_generation", "post_exploitation"),
           risk="EXPLOITATION_CAPABLE", timeout=900),
        _t("searchsploit_cli", "Searchsploit CLI", "searchsploit", "exploitdb", C.EXPLOITATION_TOOLS,
           "Exploit database search", ("exploit_search",), risk="READ_ONLY", network=False, target=False),
        _t("crackmapexec", "CrackMapExec (NetExec)", "nxc", "netexec", C.EXPLOITATION_TOOLS,
           "Networked pentesting swiss army knife", ("smb_enum", "authenticated_scan", "credential_reuse"),
           credential=True, risk="AUTHENTICATED_TEST"),
        _t("impacket_secretsdump", "Impacket secretsdump", "secretsdump.py", "impacket-scripts", C.EXPLOITATION_TOOLS,
           "Windows credential extraction via Impacket", ("credential_extraction",),
           credential=True, risk="EXPLOITATION_CAPABLE"),

        # --- Sniffing & Spoofing ---
        _t("wireshark_cli", "Wireshark CLI (tshark)", "tshark", "wireshark-common", C.SNIFFING_SPOOFING,
           "Packet capture and analysis", ("packet_capture", "protocol_analysis"),
           privileges=("CAP_NET_RAW",), risk="PRIVILEGED", network=False),
        _t("tcpdump", "Tcpdump", "tcpdump", "tcpdump", C.SNIFFING_SPOOFING,
           "Classic packet capture utility", ("packet_capture",),
           privileges=("CAP_NET_RAW",), risk="PRIVILEGED", network=False),
        _t("ettercap", "Ettercap", "ettercap", "ettercap-text-only", C.SNIFFING_SPOOFING,
           "Man-in-the-middle network attacks", ("mitm", "arp_spoofing"),
           privileges=("CAP_NET_RAW",), risk="DESTRUCTIVE", timeout=300),
        _t("responder", "Responder", "responder", "responder", C.SNIFFING_SPOOFING,
           "LLMNR/NBT-NS/MDNS poisoner", ("credential_capture", "mitm"),
           privileges=("CAP_NET_RAW",), risk="DESTRUCTIVE"),

        # --- Post Exploitation ---
        _t("mimikatz_like", "Mimikatz-style tooling (via Impacket)", "getst.py", "impacket-scripts", C.POST_EXPLOITATION,
           "Credential extraction post-exploitation", ("credential_extraction",),
           credential=True, risk="EXPLOITATION_CAPABLE"),
        _t("chisel", "Chisel", "chisel", "chisel", C.POST_EXPLOITATION,
           "TCP tunnel and pivot", ("tunneling", "pivoting"), risk="EXPLOITATION_CAPABLE"),
        _t("proxychains", "Proxychains", "proxychains", "proxychains", C.POST_EXPLOITATION,
           "Route traffic through proxies for pivoting", ("pivoting", "traffic_routing"), risk="LOW_IMPACT"),

        # --- Forensics ---
        _t("autopsy_cli", "Autopsy ( Sleuth Kit CLI )", "fls", "sleuthkit", C.FORENSICS,
           "Disk forensics via The Sleuth Kit", ("disk_forensics", "file_recovery"),
           network=False, privileges=("CAP_SYS_ADMIN",), risk="PRIVILEGED", target=False),
        _t("volatility3", "Volatility 3", "vol", "volatility3", C.FORENSICS,
           "Memory forensics and analysis", ("memory_forensics", "process_analysis"),
           network=False, risk="LOW_IMPACT", target=False),
        _t("binwalk", "Binwalk", "binwalk", "binwalk", C.FORENSICS,
           "Firmware analysis and embedded file extraction", ("firmware_analysis", "file_carving"),
           network=False, risk="READ_ONLY", target=False),
        _t("foremost", "Foremost", "foremost", "foremost", C.FORENSICS,
           "File carving from disk images", ("file_carving",), network=False, risk="READ_ONLY", target=False),
        _t("testdisk", "TestDisk", "testdisk", "testdisk", C.FORENSICS,
           "Partition repair and file recovery", ("partition_recovery",),
           network=False, privileges=("CAP_SYS_ADMIN",), risk="DESTRUCTIVE", target=False),

        # --- Reporting ---
        _t("cutycapt", "Cutycapt", "cutycapt", "cutycapt", C.REPORTING,
           "Website screenshot capture for reports", ("screenshot_capture",), risk="LOW_IMPACT"),
        _t("faraday_cli", "Faraday CLI", "faraday", "faraday", C.REPORTING,
           "Collaborative pentest report ingestion", ("report_generation",), network=False, risk="READ_ONLY", target=False),

        # --- OSINT / Social Engineering ---
        _t("maltego", "Maltego", "maltego", "maltego", C.OSINT,
           "OSINT link analysis", ("osint_recon", "link_analysis"), risk="READ_ONLY", target=False),
        _t("setoolkit", "Social Engineering Toolkit", "setoolkit", "set", C.SOCIAL_ENGINEERING,
           "Social-engineering attack toolkit", ("phishing_simulation",),
           risk="DESTRUCTIVE", timeout=600),
        _t("exiftool", "ExifTool", "exiftool", "exiftool", C.OSINT,
           "Read/write file metadata", ("metadata_extraction",), network=False, risk="READ_ONLY", target=False),

        # --- Hardware / RFID / SDR / VoIP ---
        _t("pcileech", "PCILeech", "pcileech", "pcileech", C.HARDWARE,
           "PCIe DMA attacks and memory acquisition", ("dma_attack", "memory_acquisition"),
           network=False, privileges=("CAP_SYS_ADMIN",), risk="DESTRUCTIVE", target=False),
        _t("proxmark3", "Proxmark3", "proxmark3", "proxmark3", C.RFID_NFC,
           "RFID/NFC research toolkit", ("rfid_read", "rfid_emulation"), network=False, risk="PRIVILEGED", target=False),
        _t("gnuradio", "GNU Radio Companion", "gnuradio-companion", "gnuradio", C.SDR,
           "Software-defined radio toolkit", ("sdr_capture", "signal_analysis"), network=False, risk="PRIVILEGED", target=False),
        _t("sipvicious", "SIPVicious", "svmap", "sipvicious", C.VOIP,
           "VoIP scanning and auditing", ("voip_scan", "sip_enum"), risk="ACTIVE_SCAN"),

        # --- Cryptography / Steganography ---
        _t("hashid", "Hash Identifier", "hashid", "hashid", C.CRYPTOGRAPHY,
           "Identify hash types", ("hash_identification",), network=False, risk="READ_ONLY", target=False),
        _t("steghide", "Steghide", "steghide", "steghide", C.STEGANOGRAPHY,
           "Steganography hide/extract in images and audio", ("stego_extraction", "stego_hiding"),
           network=False, risk="LOW_IMPACT", target=False),
        _t("stegseek", "Stegseek", "stegseek", "stegseek", C.STEGANOGRAPHY,
           "Fast steganography brute-force", ("stego_extraction", "brute_force"),
           network=False, risk="LOW_IMPACT", target=False),
        _t("zsteg", "Zsteg", "zsteg", "zsteg", C.STEGANOGRAPHY,
           "PNG/BMP steganography detection", ("stego_extraction",), network=False, risk="READ_ONLY", target=False),

        # --- Fuzzing ---
        _t("wfuzz", "Wfuzz", "wfuzz", "wfuzz", C.FUZZING,
           "Web application fuzzer", ("web_fuzz", "parameter_fuzz"), risk="FUZZING"),
        _t("bfuzz", "Binary Fuzzers (AFL entry)", "afl-fuzz", "aflplusplus", C.FUZZING,
           "Coverage-guided binary fuzzing", ("binary_fuzz", "crash_discovery"),
           network=False, risk="FUZZING", target=False),
        _t("SPIKE", "SPIKE", "generic_send_tcp", "spike", C.FUZZING,
           "Protocol fuzzing framework", ("protocol_fuzz",), risk="FUZZING"),

        # --- Malware Analysis ---
        _t("clamscan", "ClamAV scanner", "clamscan", "clamav", C.MALWARE_ANALYSIS,
           "Malware signature scanning", ("malware_scan",), network=False, risk="READ_ONLY", target=False),
        _t("yara", "YARA", "yara", "yara", C.MALWARE_ANALYSIS,
           "Pattern-based malware identification", ("malware_scan", "pattern_matching"), network=False, risk="READ_ONLY", target=False),
        _t("cuckoo_cli", "Cuckoo Sandbox (CLI bridge)", "cuckoo", "cuckoo", C.MALWARE_ANALYSIS,
           "Malware sandbox analysis", ("dynamic_malware_analysis",), network=False, risk="PRIVILEGED", target=False),

        # --- Cloud / Container ---
        _t("trivy", "Trivy", "trivy", "trivy", C.CLOUD_CONTAINER,
           "Container and dependency vulnerability scanner", ("container_scan", "dependency_scan"), risk="READ_ONLY"),
        _t("kube_hunter", "kube-hunter", "kube-hunter", "kube-hunter", C.CLOUD_CONTAINER,
           "Kubernetes security probing", ("kubernetes_scan",), risk="ACTIVE_SCAN"),
        _t("pacu", "Pacu", "pacu", "pacu", C.CLOUD_CONTAINER,
           "AWS exploitation framework", ("cloud_audit", "cloud_exploitation"), credential=True, risk="EXPLOITATION_CAPABLE"),

        # --- Windows Resources ---
        _t("impacket_smbexec", "Impacket smbexec", "smbexec.py", "impacket-scripts", C.WINDOWS_RESOURCES,
           "SMB command execution via Impacket", ("smb_execution",),
           credential=True, risk="EXPLOITATION_CAPABLE"),
        _t("evil-winrm_bridge", "Evil-WinRM (bridge entry)", "evil-winrm", "evil-winrm", C.WINDOWS_RESOURCES,
           "WinRM remote shell", ("remote_shell",),
           credential=True, risk="EXPLOITATION_CAPABLE"),

        # --- Defensive / detection ---
        _t("nmap_nse_vuln", "Nmap NSE vuln scripts", "nmap", "nmap", C.DEFENSIVE_DETECTION,
           "NSE-based exposure detection", ("network_scan", "exposure_detection"),
           privileges=("CAP_NET_RAW",), risk="ACTIVE_SCAN"),
        _t("testssl", "testssl.sh", "testssl.sh", "testssl.sh", C.DEFENSIVE_DETECTION,
           "TLS/SSL configuration auditing", ("tls_audit", "crypto_audit"), risk="LOW_IMPACT"),
        _t("lynis", "Lynis", "lynis", "lynis", C.DEFENSIVE_DETECTION,
           "Host security auditing and hardening", ("host_audit",),
           network=False, privileges=("CAP_SYS_ADMIN",), risk="READ_ONLY", target=False),
        _t("chkrootkit", "chkrootkit", "chkrootkit", "chkrootkit", C.DEFENSIVE_DETECTION,
           "Rootkit detection", ("rootkit_detection",), network=False, risk="READ_ONLY", target=False),
    )


def build_default_registry() -> KaliToolRegistry:
    """Build the seed Kali inventory registry.

    HONESTY NOTE: this is a curated SEED inventory of 77 representative tools
    across the 25 Kali categories, authored from the official Kali tool
    categories. It is NOT a complete mirror of the official Kali tool list and
    does NOT claim runtime availability for any tool. Availability is a
    runtime fact discovered by kali.discovery against the actual runtime.
    """
    return KaliToolRegistry(_seed_inventory())


__all__ = [
    "RISK_CLASSES",
    "KNOWN_PRIVILEGES",
    "KaliToolSpec",
    "KaliToolRegistry",
    "build_default_registry",
]
