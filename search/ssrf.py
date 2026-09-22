"""
SSRF Protection Module

Server-Side Request Forgery protection for all external search providers.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .exceptions import SSRFError


# =============================================================================
# SSRF Protection Configuration
# =============================================================================

class SSRFProtection:
    """SSRF protection configuration."""
    
    # Allowed URL schemes
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    
    # Blocked host patterns
    blocked_hosts: frozenset[str] = frozenset({
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "169.254.169.254",  # AWS metadata
        "169.254.170.2",    # AWS ECS metadata
        "metadata.google.internal",  # GCP metadata
        "100.100.100.200",  # Alibaba Cloud metadata
        "192.0.0.192",  # Oracle Cloud metadata
    })
    
    # Blocked IP ranges (CIDR)
    blocked_ranges: frozenset[str] = frozenset({
        "127.0.0.0/8",           # Loopback
        "::1/128",               # IPv6 loopback
        "10.0.0.0/8",            # Private
        "172.16.0.0/12",         # Private
        "192.168.0.0/16",        # Private
        "169.254.0.0/16",        # Link-local
        "fe80::/10",             # IPv6 link-local
        "::ffff:127.0.0.0/104",  # IPv4-mapped IPv6 loopback
        "::ffff:10.0.0.0/112",   # IPv4-mapped IPv6 private
        "::ffff:172.16.0.0/108", # IPv4-mapped IPv6 private
        "::ffff:192.168.0.0/112", # IPv4-mapped IPv6 private
        "169.254.169.254/32",    # AWS metadata
    })
    
    # Blocked host suffixes
    blocked_suffixes: frozenset[str] = frozenset({
        ".internal",
        ".local",
        ".localhost",
        ".onion",
        ".i2p",
    })
    
    # Maximum URL length
    max_url_length: int = 2048
    
    # Maximum redirect count
    max_redirects: int = 3
    
    # Allowed ports
    allowed_ports: frozenset[int] = frozenset({80, 443})
    
    def __init__(self):
        # Pre-compile blocked ranges for faster lookup
        self._blocked_networks = [
            ipaddress.ip_network(r) for r in self.blocked_ranges
        ]


# Global SSRF protection instance
ssrf_protection = SSRFProtection()


# =============================================================================
# URL Validation
# =============================================================================

def validate_url(url: str) -> tuple[bool, str]:
    """Validate a URL for SSRF safety.
    
    Returns:
        tuple of (is_valid, reason)
    """
    if not url or not isinstance(url, str):
        return False, "URL is empty or not a string"
    
    # Check length
    if len(url) > ssrf_protection.max_url_length:
        return False, f"URL exceeds maximum length of {ssrf_protection.max_url_length}"
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Failed to parse URL: {e}"
    
    # Check scheme
    if parsed.scheme not in ssrf_protection.allowed_schemes:
        return False, f"Scheme '{parsed.scheme}' is not allowed. Allowed: {ssrf_protection.allowed_schemes}"
    
    # Check empty host
    if not parsed.hostname:
        return False, "URL has no hostname"
    
    hostname = parsed.hostname.lower()
    
    # Check blocked hosts
    if hostname in ssrf_protection.blocked_hosts:
        return False, f"Host '{hostname}' is blocked"
    
    # Check blocked suffixes
    for suffix in ssrf_protection.blocked_suffixes:
        if hostname.endswith(suffix):
            return False, f"Host ends with blocked suffix '{suffix}'"
    
    # Check port
    if parsed.port and parsed.port not in ssrf_protection.allowed_ports:
        return False, f"Port {parsed.port} is not allowed. Allowed: {ssrf_protection.allowed_ports}"
    
    # Check IP address
    try:
        ip = ipaddress.ip_address(hostname)
        for network in ssrf_protection._blocked_networks:
            if ip in network:
                return False, f"IP address {hostname} is in blocked range {network}"
    except ValueError:
        # Not an IP address, it's a hostname
        pass
    
    # Check for IP literal in hostname (e.g., http://192.168.1.1)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        try:
            ip = ipaddress.ip_address(hostname)
            for network in ssrf_protection._blocked_networks:
                if ip in network:
                    return False, f"IP address {hostname} is in blocked range {network}"
        except ValueError:
            return False, f"Invalid IP address format: {hostname}"
    
    # Try to resolve hostname and check IP
    try:
        # Don't actually resolve in validation (could be slow)
        # Just check if it looks like an internal hostname
        if any(part in hostname for part in ["internal", "local", "localhost", "intranet"]):
            return False, f"Hostname '{hostname}' appears to be internal"
    except Exception:
        pass
    
    return True, "URL is valid"


def is_safe_url(url: str) -> bool:
    """Quick check if URL is safe (for use in hot paths)."""
    is_valid, _ = validate_url(url)
    return is_valid


# =============================================================================
# DNS/IP Validation
# =============================================================================

def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in ssrf_protection._blocked_networks:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def is_metadata_endpoint(url: str) -> bool:
    """Check if URL is a known cloud metadata endpoint."""
    metadata_endpoints = {
        "169.254.169.254",  # AWS
        "169.254.170.2",    # AWS ECS
        "metadata.google.internal",  # GCP
        "100.100.100.200",  # Alibaba
        "192.0.0.192",      # Oracle
    }
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return hostname in metadata_endpoints
    except Exception:
        return False


# =============================================================================
# Redirect Policy
# =============================================================================

@dataclass
class RedirectPolicy:
    """Redirect handling policy."""
    max_redirects: int = 3
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    disallow_redirect_to_private: bool = True
    
    def is_redirect_allowed(self, url: str, redirect_url: str, redirect_count: int) -> tuple[bool, str]:
        """Check if a redirect is allowed."""
        if redirect_count >= self.max_redirects:
            return False, f"Maximum redirects ({self.max_redirects}) exceeded"
        
        # Validate redirect URL
        is_valid, reason = validate_url(redirect_url)
        if not is_valid:
            return False, f"Redirect URL invalid: {reason}"
        
        # Check scheme change
        original_scheme = urlparse(url).scheme
        redirect_scheme = urlparse(redirect_url).scheme
        if redirect_scheme != original_scheme and redirect_scheme not in self.allowed_schemes:
            return False, f"Redirect to scheme '{redirect_scheme}' not allowed"
        
        # Check if redirecting to private IP
        if self.disallow_redirect_to_private:
            redirect_host = urlparse(redirect_url).hostname
            if redirect_host and is_private_ip(redirect_host):
                return False, "Redirect to private IP address not allowed"
        
        return True, "Redirect allowed"


# =============================================================================
# Response Validation
# =============================================================================

def validate_response_size(content: str | bytes, max_bytes: int) -> bool:
    """Validate response size."""
    size = len(content) if isinstance(content, bytes) else len(content.encode('utf-8'))
    return size <= max_bytes


def validate_content_type(content_type: str | None, allowed_types: frozenset[str]) -> bool:
    """Validate content type."""
    if content_type is None:
        return True  # Allow unknown content types
    
    content_type = content_type.lower().split(";")[0]
    return content_type in allowed_types


# =============================================================================
# Utility Functions
# =============================================================================

def get_domain_from_url(url: str) -> str | None:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def get_ip_addresses(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses (for additional validation)."""
    try:
        return [ip[4][0] for ip in socket.getaddrinfo(hostname, None)]
    except Exception:
        return []


def check_url_ssrf(url: str, raise_on_block: bool = False) -> bool:
    """Comprehensive SSRF check for a URL.
    
    Args:
        url: URL to check
        raise_on_block: If True, raise SSRFError on blocked URL
        
    Returns:
        True if URL is safe, False otherwise
        
    Raises:
        SSRFError: If URL is blocked and raise_on_block is True
    """
    is_valid, reason = validate_url(url)
    
    if not is_valid:
        if raise_on_block:
            raise SSRFError(f"SSRF protection blocked URL: {reason}", provider="ssrf")
        return False
    
    # Additional checks
    if is_metadata_endpoint(url):
        if raise_on_block:
            raise SSRFError("URL is a cloud metadata endpoint", provider="ssrf")
        return False

    # Validate DNS results at the network boundary as well as the URL text.
    # A public-looking hostname may resolve to a private address (or change
    # between validation and connection), so unresolved DNS must fail closed.
    hostname = urlparse(url).hostname or ""
    try:
        ipaddress.ip_address(hostname)
        resolved = [hostname]
    except ValueError:
        resolved = get_ip_addresses(hostname)
    if not resolved:
        if raise_on_block:
            raise SSRFError("hostname could not be resolved safely", provider="ssrf")
        return False
    for resolved_ip in resolved:
        if is_private_ip(resolved_ip):
            if raise_on_block:
                raise SSRFError("hostname resolves to a blocked private address", provider="ssrf")
            return False

    return True
