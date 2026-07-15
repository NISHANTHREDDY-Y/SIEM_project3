import ipaddress
import re
from urllib.parse import urlparse


HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
IP_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HASH_SIZES = {32: "MD5", 40: "SHA1", 64: "SHA256"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "cam", "ru", "cn", "su", "biz", "tk", "work"}
RISKY_KEYWORDS = {
    "malware",
    "phish",
    "ransom",
    "botnet",
    "c2",
    "evil",
    "payload",
    "credential",
    "exploit",
    "dropper",
}


def _normalize_items(raw_value):
    items = []
    for chunk in re.split(r"[\n,;]+", raw_value or ""):
        item = chunk.strip()
        if item and item not in items:
            items.append(item)
    return items


def _score_to_verdict(score, has_known_bad=False):
    if has_known_bad or score >= 85:
        return "Malicious"
    if score >= 45:
        return "Suspicious"
    return "Safe"


def _scan_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return {
            "indicator_type": "IP address",
            "confidence": 15,
            "verdict": "Safe",
            "reason": "Private, local, or reserved address space.",
            "recommendation": "No immediate action required.",
        }

    return {
        "indicator_type": "IP address",
        "confidence": 62,
        "verdict": "Suspicious",
        "reason": "Public address not found in local trust data.",
        "recommendation": "Check firewall, proxy, and threat intelligence sources before trusting this IP.",
    }


def _scan_hash(value):
    clean = value.strip()
    length = len(clean)
    hash_type = HASH_SIZES.get(length)
    if not hash_type or not HEX_RE.match(clean):
        return None

    if len(set(clean.lower())) == 1:
        return {
            "indicator_type": f"{hash_type} hash",
            "confidence": 95,
            "verdict": "Malicious",
            "reason": "Low-quality hash pattern indicates a known test or filler value.",
            "recommendation": "Verify source integrity and treat this sample as unsafe.",
        }

    return {
        "indicator_type": f"{hash_type} hash",
        "confidence": 58,
        "verdict": "Suspicious",
        "reason": "Valid hash format with no local reputation feed available.",
        "recommendation": "Submit the hash to a reputation service or sandbox before allowing execution.",
    }


def _scan_url_or_domain(value):
    raw = value.strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="http")
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    joined = f"{host}{path}{query}".lower()

    if not host:
        return None

    reasons = []
    score = 25
    verdict = "Safe"

    if "://" not in raw:
        score += 10
        reasons.append("Domain observed without protocol context.")

    if not DOMAIN_RE.match(host):
        if IP_LIKE_RE.match(host):
            reasons.append("Host is an IP literal.")
            score += 35
        else:
            reasons.append("Domain format is unusual or malformed.")
            score += 50

    tld = host.rsplit(".", 1)[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"Suspicious TLD '.{tld}' is often abused.")

    if host.count(".") >= 4:
        score += 10
        reasons.append("Excessive subdomain depth detected.")

    if any(keyword in joined for keyword in RISKY_KEYWORDS):
        score = 95
        reasons.append("Contains a high-risk keyword.")
        verdict = "Malicious"

    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        score += 20
        reasons.append(f"Non-web scheme '{parsed.scheme}' needs manual review.")

    if parsed.scheme == "http" and IP_LIKE_RE.match(host):
        score += 20
        reasons.append("HTTP over IP literal is commonly used in phishing or staging.")

    if not reasons:
        reasons.append("Known to be reachable, but no reputation feed is configured.")
        score += 25

    return {
        "indicator_type": "URL" if "://" in raw else "Domain",
        "confidence": min(score, 100),
        "verdict": verdict if verdict == "Malicious" else _score_to_verdict(score),
        "reason": " ".join(reasons),
        "recommendation": "Validate the target with threat intelligence and user reports before allowing access.",
    }


def scan_indicator(value):
    item = value.strip()
    if not item:
        return None

    result = _scan_hash(item) or _scan_ip(item) or _scan_url_or_domain(item)
    if result is None:
        result = {
            "indicator_type": "Unknown",
            "confidence": 20,
            "verdict": "Suspicious",
            "reason": "Pattern does not match a supported IOC format.",
            "recommendation": "Review manually or convert the input to a supported IP, domain, URL, or hash.",
        }

    result["value"] = item
    return result


def scan_indicators(raw_value):
    results = [scan_indicator(item) for item in _normalize_items(raw_value)]
    return [result for result in results if result is not None]
