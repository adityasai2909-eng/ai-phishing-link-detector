import ipaddress
import math
import re
from urllib.parse import urlparse


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "at_count",
    "question_count",
    "equals_count",
    "ampersand_count",
    "percent_count",
    "https",
    "has_ip",
    "subdomain_count",
    "has_punycode",
    "has_sensitive_word",
    "is_shortener",
    "has_port",
    "hostname_entropy",
    "tld_length",
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

SENSITIVE_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "update",
    "confirm",
    "wallet",
    "banking",
    "authenticate",
    "credential",
    "reset",
}


def extract_url_features(raw_url):
    if not isinstance(raw_url, str):
        raw_url = ""

    raw_url = raw_url.strip()

    candidate = raw_url
    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        hostname = ""
        port = None
        parsed = urlparse("https://invalid.example")

    try:
        hostname.encode("idna")
    except UnicodeError:
        hostname = ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    labels = hostname.split(".") if hostname else []
    tld = labels[-1] if len(labels) > 1 else ""

    domain_entropy = 0.0

    if hostname:
        length = len(hostname)
        frequencies = {
            char: hostname.count(char)
            for char in set(hostname)
        }

        domain_entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in frequencies.values()
        )

    url_lower = candidate.lower()

    has_sensitive_word = int(
        any(
            re.search(
                rf"(?<![a-z]){re.escape(word)}(?![a-z])",
                url_lower,
            )
            for word in SENSITIVE_WORDS
        )
    )

    is_shortener = int(
        hostname in SHORTENERS
        or any(
            hostname.endswith("." + domain)
            for domain in SHORTENERS
        )
    )

    return {
        "url_length": len(raw_url),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "digit_count": sum(char.isdigit() for char in raw_url),
        "at_count": raw_url.count("@"),
        "question_count": raw_url.count("?"),
        "equals_count": raw_url.count("="),
        "ampersand_count": raw_url.count("&"),
        "percent_count": raw_url.count("%"),
        "https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "subdomain_count": max(0, len(labels) - 2) if not has_ip else 0,
        "has_punycode": int("xn--" in hostname),
        "has_sensitive_word": has_sensitive_word,
        "is_shortener": is_shortener,
        "has_port": int(port is not None),
        "hostname_entropy": domain_entropy,
        "tld_length": len(tld),
    }