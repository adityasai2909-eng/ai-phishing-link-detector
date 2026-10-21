
import base64
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
import requests
import streamlit as st

from url_features import extract_url_features


st.set_page_config(
    page_title="AI Phishing Link Detector",
    page_icon="🛡️",
    layout="wide",
)


def analyze_url(raw_url):
    if not isinstance(raw_url, str):
        raw_url = ""

    raw_url = raw_url.strip()
    findings = []
    score = 0

    def invalid(message):
        return None, [message], 0

    if not raw_url:
        return invalid("Please enter a URL.")

    if any(c.isspace() or ord(c) < 32 for c in raw_url):
        return invalid("The URL contains spaces or control characters.")

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
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
    }

    if ascii_hostname in shorteners:
        flag(15, "This hostname belongs to a URL-shortening service.")

    sensitive_words = {
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

    words_found = sorted(
        word
        for word in sensitive_words
        if re.search(
            rf"(?<![a-z]){re.escape(word)}(?![a-z])",
            ascii_hostname + parsed.path.lower(),
        )
    )

    if words_found:
        points = min(20, 10 + 5 * (len(words_found) - 1))
        flag(
            points,
            "Potentially sensitive words appear in the hostname or path: "
            + ", ".join(words_found)
            + ".",
        )

    if not findings:
        findings.append(
            "No suspicious structural patterns were detected by these checks."
        )

    return min(score, 100), findings, 0


def get_virustotal_api_key():
    try:
        key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
        return key.strip() if isinstance(key, str) else ""
    except Exception:
        return ""


def check_virustotal(url, api_key):
    if not api_key:
        return {
            "status": "not_configured",
            "message": "VirusTotal API key is not configured.",
        }

    url = url.strip()

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return {
                "status": "error",
                "message": "Only HTTP and HTTPS URLs are supported.",
            }

        if not parsed.netloc or not parsed.hostname:
            return {
                "status": "error",
                "message": "The URL must contain a hostname.",
            }

        local_score, local_findings, _ = analyze_url(url)

        if local_score is None:
            return {
                "status": "error",
                "message": local_findings[0],
            }

    except (ValueError, TypeError):
        return {
            "status": "error",
            "message": "The URL could not be parsed.",
        }

    url_id = (
        base64.urlsafe_b64encode(url.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": (
                    "No existing report was found. This does not mean "
                    "the URL is safe. No URL was submitted for scanning."
                ),
            }

        if response.status_code == 401:
            return {
                "status": "error",
                "message": "VirusTotal rejected the API key. Check your key.",
            }

        if response.status_code == 403:
            return {
                "status": "error",
                "message": (
                    "VirusTotal denied access. Check your account and API "
                    "permissions."
                ),
            }

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "message": (
                    "VirusTotal's rate limit was reached. "
                    "Wait before trying again."
                ),
            }

        response.raise_for_status()
        payload = response.json()

        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats")

        if not isinstance(stats, dict):
            return {
                "status": "pending",
                "message": "The report does not contain analysis statistics.",
            }

        return {
            "status": "found",
            "malicious": stats.get("malicious") or 0,
            "suspicious": stats.get("suspicious") or 0,
            "harmless": stats.get("harmless") or 0,
            "undetected": stats.get("undetected") or 0,
            "reputation": attributes.get("reputation"),
        }

    except requests.Timeout:
        return {
            "status": "error",
            "message": "VirusTotal timed out. Try again later.",
        }

    except requests.RequestException:
        return {
            "status": "error",
            "message": (
                "Could not contact VirusTotal. Check your internet connection."
            ),
        }

    except (ValueError, TypeError):
        return {
            "status": "error",
            "message": "VirusTotal returned an unexpected response.",
        }


@st.cache_resource
def load_ml_model():
    model_path = Path(__file__).with_name("phishing_url_model.joblib")

    if not model_path.is_file():
        return None

    bundle = joblib.load(model_path)

    if not isinstance(bundle, dict):
        raise ValueError("The saved model has an unexpected format.")

    if "model" not in bundle or "feature_names" not in bundle:
        raise ValueError("The saved model is missing required fields.")

    return bundle


def predict_ml_phishing(raw_url):
    bundle = load_ml_model()

    if bundle is None:
        return None

    features = extract_url_features(raw_url)
    feature_names = bundle["feature_names"]

    X = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names,
    )

    model = bundle["model"]
    prediction = int(model.predict(X)[0])

    if prediction not in (0, 1):
        raise ValueError("The model returned an unexpected class.")

    classes = list(model.classes_)
    phishing_index = classes.index(1)

    probability = float(
        model.predict_proba(X)[0][phishing_index]
    )

    return {
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "phishing_probability": probability,
    }


st.markdown(
    """
    <style>
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }

        .hero {
            padding: 24px;
            border: 1px solid #374151;
            border-radius: 16px;
            margin-bottom: 20px;
        }

        .muted {
            color: #9ca3af;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "current_analysis" not in st.session_state:
    st.session_state.current_analysis = None

if "input_error" not in st.session_state:
    st.session_state.input_error = None

if "vt_result" not in st.session_state:
    st.session_state.vt_result = None

if "vt_url" not in st.session_state:
    st.session_state.vt_url = None


st.title("🛡️ AI Phishing Link Detector")
st.caption("Cybersecurity • Machine Learning • Threat Intelligence")

st.markdown(
    """
    <div class="hero">
        <h3>Check a link before you trust it</h3>
        <p class="muted">
            Combines local URL heuristics, a trained Random Forest model,
            and optional VirusTotal report lookups.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.subheader("🔎 Analyze a URL")

with st.form("url_analysis_form"):
    url_input = st.text_input(
        "Enter a URL",
        placeholder="https://example.com",
        help="Do not enter private links containing passwords, tokens, or personal data.",
    )

    analyze_button = st.form_submit_button(
        "Analyze URL",
        use_container_width=True,
    )

if analyze_button:
    score, findings, _ = analyze_url(url_input)

    st.session_state.vt_result = None
    st.session_state.vt_url = None

    if score is None:
        st.session_state.current_analysis = None
        st.session_state.input_error = findings[0]
    else:
        st.session_state.input_error = None

        try:
            ml_result = predict_ml_phishing(url_input)
            ml_error = None
        except Exception:
            ml_result = None
            ml_error = (
                "The ML prediction failed. Check the saved model and "
                "feature extraction files."
            )

        if score < 30:
            risk_label = "Low structural risk"
        elif score < 60:
            risk_label = "Medium structural risk"
        else:
            risk_label = "High structural risk"

        st.session_state.current_analysis = {
            "url": url_input.strip(),
            "score": score,
            "risk": risk_label,
            "findings": findings,
            "ml_result": ml_result,
            "ml_error": ml_error,
        }

        st.session_state.scan_history.insert(
            0,
            {
                "url": url_input.strip(),
                "score": score,
                "risk": risk_label,
                "findings": findings,
            },
        )

        st.session_state.scan_history = (
            st.session_state.scan_history[:10]
        )

if st.session_state.input_error:
    st.error(st.session_state.input_error)

analysis = st.session_state.current_analysis

if analysis is not None:
    st.markdown("---")
    st.subheader("📊 Local URL Analysis")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Heuristic Score", f"{analysis['score']}/100")
        st.progress(analysis["score"] / 100)

    with col2:
        st.metric("Structural Assessment", analysis["risk"])

    if analysis["score"] < 30:
        st.success(
            "Few suspicious structural indicators were detected. "
            "This does not prove the URL is safe."
        )
    elif analysis["score"] < 60:
        st.warning(
            "Some suspicious structural indicators were detected."
        )
    else:
        st.error(
            "Multiple suspicious structural indicators were detected."
        )

    st.subheader("🧾 Local Findings")

    for finding in analysis["findings"]:
        st.markdown(f"- {finding}")

    st.markdown("---")
    st.subheader("🤖 Machine Learning Prediction")

    ml_result = analysis["ml_result"]

    if analysis["ml_error"]:
        st.warning(analysis["ml_error"])
    elif ml_result is None:
        st.info(
            "The trained model file was not found. Run "
            "python train_ml_model.py to create it."
        )
    else:
        ml_col1, ml_col2 = st.columns(2)

        with ml_col1:
            st.metric(
                "ML Classification",
                ml_result["prediction"],
            )

        with ml_col2:
            st.metric(
                "Estimated Phishing Probability",
                f"{ml_result['phishing_probability'] * 100:.2f}%",
            )

        st.progress(ml_result["phishing_probability"])

        st.caption(
            "This probability is the model's estimate, not a guarantee "
            "that a URL is malicious or safe."
        )

    st.markdown("---")
    st.subheader("🌐 VirusTotal Threat Intelligence")

    st.warning(
        "The lookup sends the URL to VirusTotal. Only query public URLs "
        "you are comfortable sharing. Never query private links containing "
        "passwords, access tokens, or personal data."
    )

    if st.button("Check Existing VirusTotal Report"):
        api_key = get_virustotal_api_key()

        if not api_key:
            st.session_state.vt_result = {
                "status": "not_configured",
                "message": (
                    "API key not configured. Check "
                    ".streamlit/secrets.toml."
                ),
            }
        else:
            with st.spinner("Retrieving existing report..."):
                st.session_state.vt_result = check_virustotal(
                    analysis["url"],
                    api_key,
                )

        st.session_state.vt_url = analysis["url"]

    vt_result = st.session_state.vt_result

    if (
        vt_result is not None
        and st.session_state.vt_url == analysis["url"]
    ):
        if vt_result["status"] == "found":
            st.write("**Existing report statistics**")

            a, b, c, d = st.columns(4)

            a.metric("Malicious", vt_result["malicious"])
            b.metric("Suspicious", vt_result["suspicious"])
            c.metric("Harmless", vt_result["harmless"])
            d.metric("Undetected", vt_result["undetected"])

            if vt_result["malicious"] > 0:
                st.error(
                    "One or more engines flagged this URL as malicious."
                )
            elif vt_result["suspicious"] > 0:
                st.warning(
                    "One or more engines flagged this URL as suspicious."
                )
            else:
                st.info(
                    "This report contains no malicious or suspicious "
                    "detections. That does not guarantee safety."
                )

            if vt_result["reputation"] is not None:
                st.write(
                    "**VirusTotal community reputation:**",
                    vt_result["reputation"],
                )
        else:
            st.info(vt_result["message"])

    st.caption(
        "Local heuristic scores, ML predictions, and VirusTotal statistics "
        "are different signals. None guarantees that a URL is safe."
    )

st.markdown("---")
st.subheader("🕘 Recent Scans")

if st.session_state.scan_history:
    for index, item in enumerate(
        st.session_state.scan_history,
        start=1,
    ):
        with st.expander(
            f"{index}. {item['url']} — {item['score']}/100"
        ):
            st.write("**Assessment:**", item["risk"])

            for finding in item["findings"]:
                st.write(f"- {finding}")

    if st.button("Clear Scan History"):
        st.session_state.scan_history = []
        st.rerun()
else:
    st.info("Your scan history will appear here after your first analysis.")

st.markdown("---")
st.caption(
    "Educational cybersecurity prototype • A low score or zero detections "
    "does not prove a URL is safe."
)