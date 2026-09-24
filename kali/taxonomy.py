from __future__ import annotations

from enum import Enum


class KaliToolCategory(str, Enum):
    """Taxonomy mirroring the official Kali Linux tool category structure."""

    INFORMATION_GATHERING = "information-gathering"
    VULNERABILITY_ANALYSIS = "vulnerability-analysis"
    WEB_APPLICATIONS = "web-applications"
    DATABASE_ASSESSMENT = "database-assessment"
    PASSWORD_ATTACKS = "password-attacks"
    WIRELESS = "wireless"
    REVERSE_ENGINEERING = "reverse-engineering"
    EXPLOITATION_TOOLS = "exploitation-tools"
    SNIFFING_SPOOFING = "sniffing-spoofing"
    POST_EXPLOITATION = "post-exploitation"
    FORENSICS = "forensics"
    REPORTING = "reporting"
    OSINT = "osint"
    SOCIAL_ENGINEERING = "social-engineering"
    HARDWARE = "hardware"
    RFID_NFC = "rfid-nfc"
    SDR = "sdr"
    VOIP = "voip"
    CRYPTOGRAPHY = "cryptography"
    STEGANOGRAPHY = "steganography"
    FUZZING = "fuzzing"
    MALWARE_ANALYSIS = "malware-analysis"
    CLOUD_CONTAINER = "cloud-container"
    WINDOWS_RESOURCES = "windows-resources"
    DEFENSIVE_DETECTION = "defensive-detection"


KALI_CATEGORIES: tuple[str, ...] = tuple(item.value for item in KaliToolCategory)

__all__ = ["KaliToolCategory", "KALI_CATEGORIES"]
