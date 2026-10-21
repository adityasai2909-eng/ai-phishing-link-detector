import ipaddress
import re
from urllib.parse import urlparse

import streamlit as st


st.set_page_config(
    page_title="Phishing Link Detector",
    page_icon="🛡️",
    layout="centered",
)

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "secure",
    "account", "password", "update", "confirm", "wallet",
    "banking", "authenticate", "credential", "reset",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at",
}


def analyze_url(raw_url):
    """Analyze URL structure locally without visiting the website."""
    raw_url = raw_url.strip()
    findings = []
    score = 0

    if not raw_url:
        return None, ["Please enter a URL."], 0

    # Add a default scheme if the user enters only a domain.
    candidate = raw_url if "://" in raw_url else "https://" + raw_url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        _ = parsed.port  # Accessing this catches malformed ports.
    except ValueError:
        return None, ["The URL contains an invalid port or address."], 0

    if (
        parsed.scheme not in ("http", "https")
        or not hostname
        or any(char.isspace() for char in raw_url)
    ):
        return None, [
            "Enter a valid web address using HTTP or HTTPS."
        ], 0

    hostname = hostname.lower().rstrip(".")

    # Check for an IP address instead of a regular domain name.
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    def flag(points, message):
        nonlocal score
        score += points
        findings.append(message)

    if parsed.scheme == "http":
        flag(15, "The URL uses HTTP instead of encrypted HTTPS.")

    if parsed.username is not None or parsed.password is not None:
        flag(25, "The URL contains user-information fields before the host.")

    if is_ip:
        flag(20, "The hostname is an IP address rather than a domain name.")

    if "@" in parsed.netloc:
        flag(20, "An @ symbol appears in the address authority.")

    if "xn--" in hostname:
        flag(20, "The hostname contains an internationalized/punycode label.")

    labels = hostname.split(".")
    if len(labels) >= 5:
        flag(15, "The hostname has many dot-separated labels.")
    elif len(labels) == 4 and not is_ip:
        flag(5, "The hostname has several subdomain labels.")

    if hostname.count("-") >= 3:
        flag(10, "The hostname contains several hyphens.")

    if len(raw_url) > 100:
        flag(10, "The URL is unusually long.")

    if len(raw_url) > 200:
        flag(10, "The URL is extremely long.")

    if hostname in SHORTENERS:
        flag(15, "This hostname belongs to a known URL-shortening service.")

    words_found = sorted(
        word
        for word in SUSPICIOUS_WORDS
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])",
                     hostname + parsed.path.lower())
    )

    if words_found:
        flag(
            min(20, 10 + 5 * (len(words_found) - 1)),
            "Potentially sensitive words appear in the hostname or path: "
            + ", ".join(words_found) + ".",
        )

    if not findings:
        findings.append(
            "No suspicious structural patterns were detected by these checks."
        )

    score = min(score, 100)
    return score, findings, 0


st.title("🛡️ AI Phishing Link Detector")
st.caption("A local URL risk analyzer for cybersecurity awareness.")

st.info(
    "Privacy: URLs are analyzed locally by this app. "
    "The app does not open submitted websites or send URLs to an AI service."
)

st.warning(
    "This is a heuristic prototype, not a trained AI model or a definitive "
    "phishing detector. A low score does not prove a website is safe."
)

url_input = st.text_input(
    "Enter a URL to analyze",
    placeholder="https://example.com",
)

analyze_button = st.button(
    "Analyze URL",
    type="primary",
    use_container_width=True,
)

if analyze_button:
    score, findings, _ = analyze_url(url_input)

    if score is None:
        st.error(findings[0])
    else:
        st.subheader("Analysis result")
        st.metric("URL risk score", f"{score}/100")

        if score >= 50:
            st.error("High risk indicators detected")
        elif score >= 25:
            st.warning("Some suspicious indicators detected")
        else:
            st.success("Few structural risk indicators detected")

        st.progress(score / 100)

        st.markdown("**What we found**")
        for finding in findings:
            st.markdown(f"- {finding}")

        st.caption(
            "The score is a simple sum of heuristic warning points, capped "
            "at 100. It is not a calibrated probability of phishing."
        )

        st.markdown("**Safety advice**")
        st.write(
            "Do not enter passwords, payment details, or verification codes "
            "on a site you do not trust. Independently navigate to the "
            "official website if a message asks you to sign in."
        )

st.divider()
st.caption("Project 1 · Beginner Cybersecurity Lab · Version 1.0")