from __future__ import annotations
import json
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from .config import CISA_KEV_URL, RSS_FEEDS
from .db import add_intel, add_event, intel_recent

UA = "CyberSentinel-X/FINAL defensive-intelligence"
MAX_CISA_RESPONSE_BYTES = 16 * 1024 * 1024
CISA_FEED_URLS = frozenset((CISA_KEV_URL, RSS_FEEDS["CISA Advisories"]))


def _is_safe_cisa_redirect(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme.lower() == "https"
        and parsed.hostname is not None
        and parsed.hostname.lower() == "www.cisa.gov"
        and port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )


class _CISASafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        if req.get_method() != "GET" or not _is_safe_cisa_redirect(target):
            raise urllib.error.HTTPError(
                req.full_url, code, "CISA redirect rejected by policy", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, target)

def _get(url, timeout=25):
    if url not in CISA_FEED_URLS:
        raise ValueError("unsupported CISA feed URL")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    opener = urllib.request.build_opener(_CISASafeRedirectHandler())
    with opener.open(req, timeout=timeout) as response:
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid CISA Content-Length") from exc
            if declared_size < 0:
                raise ValueError("invalid CISA Content-Length")
            if declared_size > MAX_CISA_RESPONSE_BYTES:
                raise ValueError("CISA response exceeds byte limit")
        body = response.read(MAX_CISA_RESPONSE_BYTES + 1)
        if len(body) > MAX_CISA_RESPONSE_BYTES:
            raise ValueError("CISA response exceeds byte limit")
        return body

def severity_for_kev(v):
    if v.get("knownRansomwareUse") == "Known":
        return "critical"
    return "high"

def collect_cisa_kev():
    data = json.loads(_get(CISA_KEV_URL).decode("utf-8"))
    vulns = data.get("vulnerabilities", [])
    new = 0
    for v in vulns:
        cve = v.get("cveID", "").strip()
        if not cve:
            continue
        title = f"{cve} — {v.get('vendorProject','')} {v.get('product','')}".strip()
        body = v.get("shortDescription", "") or "Known exploited vulnerability."
        meta = {
            "dateAdded": v.get("dateAdded"),
            "dueDate": v.get("dueDate"),
            "knownRansomwareUse": v.get("knownRansomwareUse"),
            "requiredAction": v.get("requiredAction"),
            "vulnerabilityName": v.get("vulnerabilityName"),
        }
        if add_intel(cve, "CISA KEV", title, body, severity_for_kev(v), meta):
            new += 1
    result = {"source":"CISA KEV","total":len(vulns),"new":new}
    add_event("intel","CISA KEV collection completed",
              json.dumps(result,ensure_ascii=False),"CISA KEV","info",False,result)
    return result

def collect_cisa_advisories():
    raw = _get(RSS_FEEDS["CISA Advisories"])
    root = ET.fromstring(raw)
    new = 0
    for item in root.findall(".//item")[:100]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        desc = (item.findtext("description") or "").strip()
        guid = (item.findtext("guid") or link or title).strip()
        if title and add_intel(guid, "CISA Advisories", title, desc[:4000], "info",
                               {"url": link}):
            new += 1
    result = {"source":"CISA Advisories","new":new}
    add_event("intel","CISA advisory collection completed",
              json.dumps(result,ensure_ascii=False),"CISA Advisories","info",False,result)
    return result

def refresh_all():
    results=[]
    errors=[]
    for fn in (collect_cisa_kev, collect_cisa_advisories):
        try:
            results.append(fn())
        except Exception as exc:
            errors.append({"source":fn.__name__,"error":str(exc)})
            add_event("intel","Intel source failed",str(exc),fn.__name__,"warning",False)
    return {"ok":not errors,"results":results,"errors":errors}

def latest_intel(limit=50):
    return intel_recent(limit)
