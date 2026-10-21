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
    """Validate and score a URL without opening it."""
    raw_url = raw_url.strip()
    findings = []
    score = 0

    def invalid(message):
        return None, [message], 0

    if not raw_url:
        return invalid("Please enter a URL.")

    if any(c.isspace() or ord(c) < 32 for c in raw_url):
        return invalid("The URL contains spaces or control characters.")

    # Add HTTPS when no scheme is supplied.
    if "://" not in raw_url:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw_url):
            if not re.match(r"^[^/:?#]+:\d+(?:[/?#]|$)", raw_url):
                return invalid("Unsupported or malformed URL scheme.")
        candidate = "https://" + raw_url
    else:
        candidate = raw_url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return invalid("The URL contains an invalid hostname or port.")

    if parsed.scheme.lower() not in ("http", "https"):
        return invalid("Only HTTP and HTTPS URLs are supported.")

    if not parsed.netloc or not hostname:
        return invalid("The URL must contain a hostname.")

    # An explicit colon at the end means an empty port.
    if parsed.netloc.endswith(":"):
        return invalid("The URL contains an empty port.")

    hostname = hostname.lower().rstrip(".")

    if not hostname:
        return invalid("The hostname is empty.")

    if port is not None and not 1 <= port <= 65535:
        return invalid("The port must be between 1 and 65535.")

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return invalid("The hostname contains invalid international characters.")

    try:
        ipaddress.ip_address(ascii_hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    # Reject malformed numeric IPv4-style addresses.
    if (
        not is_ip
        and re.fullmatch(r"[0-9.]+", ascii_hostname)
        and "." in ascii_hostname
    ):
        return invalid("The URL contains an invalid IP address.")

    if not is_ip:
        labels = ascii_hostname.split(".")

        if len(ascii_hostname) > 253:
            return invalid("The hostname is too long.")

        if ascii_hostname != "localhost" and len(labels) < 2:
            return invalid("Enter a hostname with a domain suffix.")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label,
                )
            ):
                return invalid("The hostname contains an invalid domain label.")

    def flag(points, message):
        nonlocal score
        score += points
        findings.append(message)

    if parsed.scheme.lower() == "http":
        flag(15, "The URL uses HTTP instead of encrypted HTTPS.")

    if parsed.username is not None or parsed.password is not None:
        flag(25, "The URL contains user-information fields before the host.")

    if is_ip:
        flag(20, "The hostname is an IP address rather than a domain name.")

    if "@" in parsed.netloc:
        flag(20, "An @ symbol appears in the address authority.")

    if "xn--" in ascii_hostname:
        flag(20, "The hostname contains a punycode label.")

    labels = ascii_hostname.split(".")
    if not is_ip and len(labels) >= 5:
        flag(15, "The hostname has many dot-separated labels.")
    elif not is_ip and len(labels) == 4:
        flag(5, "The hostname has several subdomain labels.")

    if ascii_hostname.count("-") >= 3:
        flag(10, "The hostname contains several hyphens.")

    if len(raw_url) > 100:
        flag(10, "The URL is unusually long.")
    if len(raw_url) > 200:
        flag(10, "The URL is extremely long.")

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd",
        "cutt.ly", "rb.gy", "shorturl.at",
    }
    if ascii_hostname in shorteners:
        flag(15, "This hostname belongs to a URL-shortening service.")

    sensitive_words = {
        "login", "signin", "verify", "verification", "secure",
        "account", "password", "update", "confirm", "wallet",
        "banking", "authenticate", "credential", "reset",
    }

    words_found = sorted(
        word for word in sensitive_words
        if re.search(
            rf"(?<![a-z]){re.escape(word)}(?![a-z])",
            ascii_hostname + parsed.path.lower(),
        )
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

    return min(score, 100), findings, 0


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