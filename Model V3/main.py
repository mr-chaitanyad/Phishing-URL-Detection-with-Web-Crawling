import math
import pickle
import re
import scipy.sparse as sp
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request

try:
    from asgiref.wsgi import WsgiToAsgi
except Exception:
    WsgiToAsgi = None


app = Flask(__name__)


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "pw", "top", "club", "online",
    "site", "info", "biz", "cc", "ws", "cn", "ru", "co", "in", "io"
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "short.link",
    "buff.ly", "adf.ly", "is.gd", "cli.gs", "ift.tt", "dlvr.it", "mcaf.ee",
    "su.pr", "twit.ac", "snipurl.com", "short.to", "shorturl.at"
}
PHISHING_KEYWORDS = [
    "login", "logon", "signin", "sign-in", "sign_in", "verify", "validation",
    "validate", "secure", "security", "account", "update", "upgrade", "confirm",
    "password", "passwd", "credential", "webscr", "cmd=", "banking", "support",
    "auth", "authenticate", "authorization", "recover", "recovery", "reset",
    "unlock", "suspend", "suspended", "limited", "unusual", "click", "redirect",
    "response", "token"
]
BRAND_NAMES = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook", "instagram",
    "netflix", "twitter", "linkedin", "dropbox", "yahoo", "outlook", "office365",
    "office", "chase", "wellsfargo", "citibank", "bankofamerica", "ebay",
    "alibaba", "aliexpress", "walmart", "target", "fedex", "dhl", "ups", "usps",
    "royal", "post", "icloud", "onedrive", "sharepoint", "docusign", "steam",
    "discord", "whatsapp", "telegram"
]
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".js", ".jar", ".msi",
    ".dll", ".com", ".php", ".asp", ".aspx", ".cgi", ".pl"
}
STANDARD_PORTS = {80, 443, 8080, 8443}

# ── Detection threshold ───────────────────────────────────────
# Lower = catches more phishing (may have more false positives)
# Higher = fewer false positives (may miss some phishing)
PHISHING_THRESHOLD = 0.35


# ─────────────────────────────────────────────────────────────
# Feature helpers
# ─────────────────────────────────────────────────────────────

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequency = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequency.values())


def longest_run(value: str, char_type: str = "digit") -> int:
    if not value:
        return 0
    matcher = str.isdigit if char_type == "digit" else str.isalpha
    maximum = 0
    current = 0
    for char in value:
        if matcher(char):
            current += 1
            maximum = max(maximum, current)
        else:
            current = 0
    return maximum


def max_consecutive_repeat(value: str) -> int:
    if not value:
        return 0
    maximum = 1
    current = 1
    previous = value[0]
    for char in value[1:]:
        if char == previous:
            current += 1
        else:
            current = 1
        maximum = max(maximum, current)
        previous = char
    return maximum


def is_ip(domain: str) -> int:
    return int(bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", domain)))


def is_ipv6(url: str) -> int:
    return int(bool(re.search(r"\[([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\]", url)))


def normalize_user_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if not re.match(r"^https?://", raw, re.I):
        raw = f"https://{raw.lstrip('/')}"
    return raw


def safe_parse(url: str):
    normalized = normalize_user_url(url)
    try:
        return urlparse(normalized)
    except Exception:
        return urlparse("")


def extract_features(url: str) -> dict:
    raw_url  = str(url).strip()
    lowered  = raw_url.lower()
    parsed   = safe_parse(raw_url)
    scheme   = parsed.scheme
    netloc   = parsed.netloc.lower()
    path     = parsed.path
    query    = parsed.query
    fragment = parsed.fragment

    domain_port = netloc.split(":")
    domain_full = domain_port[0]
    port_text   = domain_port[1] if len(domain_port) > 1 else ""
    domain      = domain_full.lstrip("www.")
    parts       = domain.split(".") if domain else []
    tld         = parts[-1] if parts else ""
    sld         = parts[-2] if len(parts) >= 2 else ""
    subdomain   = ".".join(parts[:-2]) if len(parts) > 2 else ""

    feature = {}
    feature["url_length"]            = len(raw_url)
    feature["dot_count"]             = raw_url.count(".")
    feature["hyphen_count"]          = raw_url.count("-")
    feature["underscore_count"]      = raw_url.count("_")
    feature["slash_count"]           = raw_url.count("/")
    feature["digit_count"]           = sum(c.isdigit() for c in raw_url)
    feature["letter_count"]          = sum(c.isalpha() for c in raw_url)
    feature["special_char_count"]    = len(re.findall(r"[^a-z0-9.\-/:?=&%#@_~+]", lowered))
    feature["at_symbol"]             = int("@" in raw_url)
    feature["double_slash_redirect"] = int("//" in raw_url[7:])
    feature["url_entropy"]           = shannon_entropy(lowered)
    feature["digit_ratio"]           = feature["digit_count"] / max(len(raw_url), 1)
    feature["percent_encoded_count"] = len(re.findall(r"%[0-9a-fA-F]{2}", raw_url))

    feature["domain_length"]         = len(domain)
    feature["domain_entropy"]        = shannon_entropy(domain)
    feature["has_ipv4"]              = is_ip(domain_full)
    feature["has_ipv6"]              = is_ipv6(raw_url)
    feature["uses_https"]            = int(scheme == "https")
    feature["subdomain_count"]       = len([p for p in subdomain.split(".") if p])
    feature["domain_has_hyphen"]     = int("-" in sld)
    feature["domain_has_digit"]      = int(any(c.isdigit() for c in domain))
    feature["suspicious_tld"]        = int(tld in SUSPICIOUS_TLDS)
    feature["is_shortener"]          = int(any(s in domain_full for s in SHORTENERS))
    feature["tld_length"]            = len(tld)
    feature["longest_digit_run"]     = longest_run(domain, "digit")
    feature["max_char_repeat"]       = max_consecutive_repeat(domain)
    feature["is_punycode"]           = int("xn--" in domain_full)

    tld_sld = f"{sld}.{tld}" if sld or tld else ""
    feature["brand_in_subdomain"]    = int(
        any(b in subdomain for b in BRAND_NAMES) and
        not any(b in tld_sld for b in BRAND_NAMES)
    )
    feature["brand_in_path"]         = int(any(b in path.lower() for b in BRAND_NAMES))
    feature["brand_count_url"]       = sum(b in lowered for b in BRAND_NAMES)
    feature["phish_kw_url"]          = int(any(k in lowered for k in PHISHING_KEYWORDS))
    feature["phish_kw_path"]         = int(any(k in path.lower() for k in PHISHING_KEYWORDS))
    feature["phish_kw_domain"]       = int(any(k in domain_full for k in PHISHING_KEYWORDS))
    feature["phish_kw_query"]        = int(any(k in query.lower() for k in PHISHING_KEYWORDS))

    port_number = int(port_text) if port_text.isdigit() else (443 if scheme == "https" else 80)
    feature["has_port"]              = int(bool(port_text))
    feature["non_standard_port"]     = int(port_number not in STANDARD_PORTS)
    feature["path_length"]           = len(path)
    feature["query_length"]          = len(query)
    feature["query_param_count"]     = len(parse_qs(query))
    feature["path_depth"]            = len([s for s in path.split("/") if s])
    last_segment                     = path.split("/")[-1] if "/" in path else path
    feature["last_seg_length"]       = len(last_segment)
    feature["suspicious_extension"]  = int(any(last_segment.lower().endswith(e) for e in SUSPICIOUS_EXTENSIONS))
    feature["has_fragment"]          = int(bool(fragment))

    tokens = [t for t in re.split(r"[^a-z0-9]", sld.lower()) if t]
    feature["avg_token_length"]      = (sum(len(t) for t in tokens) / len(tokens)) if tokens else 0
    feature["longest_token_length"]  = max((len(t) for t in tokens), default=0)
    feature["tld_in_path"]           = int((f".{tld}" in path.lower()) if tld else False)
    feature["double_extension"]      = int(bool(re.search(
        r"\.(php|asp|aspx|html?|cgi)\.(php|asp|aspx|html?)$", last_segment.lower()
    )))
    feature["has_www"]               = int("www." in domain_full)
    vowels     = sum(c in "aeiou" for c in domain if c.isalpha())
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain)
    feature["consonant_vowel_ratio"] = consonants / max(vowels, 1)
    alpha_count = sum(c.isalpha() for c in domain)
    digit_count = sum(c.isdigit() for c in domain)
    feature["domain_digit_ratio"]    = digit_count / max(alpha_count + digit_count, 1)
    return feature


FEATURE_NAMES = list(extract_features("https://example.com").keys())


# ─────────────────────────────────────────────────────────────
# Model V3 loading
# ─────────────────────────────────────────────────────────────

MODEL_DIR = Path(".")


def load_artifact(filename):
    path = MODEL_DIR / filename
    with open(path, "rb") as f:
        return pickle.load(f)


try:
    model = load_artifact("xgb_tfidf_enhanced.pkl")
    tfidf  = load_artifact("tfidf_vectorizer.pkl")
    scaler = load_artifact("numeric_scaler.pkl")
    MODEL_READY = True
    print("[INFO] Model V3 loaded successfully.")
    print(f"[INFO] Model type  : {type(model).__name__}")
    print(f"[INFO] TF-IDF vocab: {len(tfidf.vocabulary_)} tokens")
    print(f"[INFO] Scaler cols : {scaler.n_features_in_}")
    print(f"[INFO] Numeric cols: {len(FEATURE_NAMES)}")
    try:
        print(f"[INFO] Model expects {model.n_features_in_} input features")
    except AttributeError:
        pass
except Exception as e:
    print(f"[WARN] Could not load Model V3: {e}")
    model = tfidf = scaler = None
    MODEL_READY = False


def _build_combined(numeric_scaled, tfidf_vec):
    """
    Auto-detect correct hstack order by matching model.n_features_in_.
    Order A : [numeric | tfidf]
    Order B : [tfidf   | numeric]
    """
    try:
        expected = model.n_features_in_
    except AttributeError:
        expected = None

    order_a = sp.hstack([sp.csr_matrix(numeric_scaled), tfidf_vec])
    order_b = sp.hstack([tfidf_vec, sp.csr_matrix(numeric_scaled)])

    if expected is None:
        return order_a, "numeric+tfidf (default)"
    if order_a.shape[1] == expected:
        return order_a, "numeric+tfidf"
    if order_b.shape[1] == expected:
        return order_b, "tfidf+numeric"
    # Neither matches — return A and let XGBoost raise a clear error
    return order_a, f"numeric+tfidf (MISMATCH: got {order_a.shape[1]}, expected {expected})"


def _heuristic_score(feature_dict: dict) -> float:
    """Rule-based fallback when ML model is unavailable or errors."""
    score = 0.05
    score += 0.20 * feature_dict["phish_kw_domain"]
    score += 0.15 * feature_dict["phish_kw_url"]
    score += 0.15 * feature_dict["suspicious_tld"]
    score += 0.12 * feature_dict["brand_in_subdomain"]
    score += 0.10 * feature_dict["is_shortener"]
    score += 0.08 * feature_dict["has_ipv4"]
    score += 0.05 * feature_dict["brand_count_url"]
    score += 0.05 * min(feature_dict["url_length"] / 200, 1.0)
    return min(score, 1.0)


def predict_url(url: str):
    feature_dict = extract_features(url)

    # ── Heuristic fallback when model not loaded ──────────────
    if not MODEL_READY:
        score = _heuristic_score(feature_dict)
        return (1 if score >= PHISHING_THRESHOLD else 0), score

    try:
        # 1. Numeric features → scale
        numeric_vec    = np.array([[feature_dict[name] for name in FEATURE_NAMES]])
        numeric_scaled = scaler.transform(numeric_vec)

        # 2. TF-IDF on raw URL string
        tfidf_vec = tfidf.transform([url])

        # 3. Combine in auto-detected correct order
        combined, order = _build_combined(numeric_scaled, tfidf_vec)
        print(f"[DEBUG] hstack={order}  shape={combined.shape}  url={url[:60]}")

        # 4. Predict — use custom threshold instead of default 0.5
        probability = (
            float(model.predict_proba(combined)[0][1])
            if hasattr(model, "predict_proba")
            else float(model.predict(combined)[0])
        )
        prediction = 1 if probability >= PHISHING_THRESHOLD else 0

        return prediction, probability

    except Exception as e:
        print(f"[ERROR] ML prediction failed: {e} — falling back to heuristic")
        score = _heuristic_score(feature_dict)
        return (1 if score >= PHISHING_THRESHOLD else 0), score


# ─────────────────────────────────────────────────────────────
# Web crawler
# ─────────────────────────────────────────────────────────────

def extract_links(url: str, max_nodes: int = 80):
    headers = {"User-Agent": "Mozilla/5.0"}
    nodes, edges = [], []
    seen_nodes, seen_edges = set(), set()

    root_label, root_score = predict_url(url)
    root_text = "spam" if root_label == 1 else "not spam"
    nodes.append({"id": url, "score": root_score, "label": root_text})
    seen_nodes.add(url)

    try:
        response = requests.get(url, headers=headers, timeout=8)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        for anchor in soup.find_all("a", href=True):
            if len(nodes) >= max_nodes:
                break
            link   = urljoin(url, anchor["href"]).strip()
            parsed = urlparse(link)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            edge_key = (url, link)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            if link not in seen_nodes:
                pred, prob = predict_url(link)
                label = "spam" if pred == 1 else "not spam"
                nodes.append({"id": link, "score": prob, "label": label})
                seen_nodes.add(link)
            edges.append({"source": url, "target": link})

    except requests.exceptions.ConnectionError:
        print(f"[WARN] Cannot reach {url} — returning root node only")
    except requests.exceptions.Timeout:
        print(f"[WARN] Timeout reaching {url}")
    except requests.exceptions.HTTPError as e:
        print(f"[WARN] HTTP error {e}")
    except Exception as e:
        print(f"[WARN] Crawl error: {e}")

    valid_ids      = {n["id"] for n in nodes}
    filtered_edges = [e for e in edges if e["source"] in valid_ids and e["target"] in valid_ids]
    return nodes, filtered_edges


# ─────────────────────────────────────────────────────────────
# Flask routes
# ─────────────────────────────────────────────────────────────

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return response


@app.route("/")
def home():
    return render_template("index.html") # index.html is advanced code


@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url  = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing URL"}), 400
    try:
        pred, prob = predict_url(url)
        return jsonify({
            "url":         url,
            "prediction":  "Phishing" if pred == 1 else "Benign",
            "probability": round(prob, 4)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/crawl", methods=["POST", "OPTIONS"])
def crawl():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.json
    url  = normalize_user_url((data or {}).get("url", ""))
    if not url:
        return jsonify({"error": "Missing URL"}), 400
    parsed = urlparse(url)
    print(f"[INFO] Crawl request for URL: {url}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return jsonify({"error": "Invalid URL"}), 400
    try:
        nodes, edges = extract_links(url)
    except Exception as error:
        return jsonify({"error": str(error)}), 500
    return jsonify({"nodes": nodes, "links": edges})


@app.route("/features", methods=["POST"])
def features():
    """
    Debug route — shows all extracted features + prediction details.
    Use in Postman or browser console:
        POST /features   { "url": "https://..." }
    """
    data = request.json
    url  = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    feat       = extract_features(url)
    pred, prob = predict_url(url)
    fired      = {k: v for k, v in feat.items() if v not in (0, 0.0)}

    return jsonify({
        "url":            url,
        "prediction":     "Phishing" if pred == 1 else "Benign",
        "probability":    round(prob, 4),
        "threshold_used": PHISHING_THRESHOLD,
        "model_ready":    MODEL_READY,
        "features_fired": fired,
        "all_features":   feat
    })


if WsgiToAsgi is not None:
    asgi_app = WsgiToAsgi(app)

# if __name__ == "__main__":
#     app.run(debug=True)

app = app