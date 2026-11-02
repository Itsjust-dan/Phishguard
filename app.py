"""
PhishGuard API v4.0
Hybrid phishing detection: calibrated Random Forest (URL-only or URL+page),
heuristic rules, and an optional VirusTotal lookup.
"""
import os, time, base64, threading, logging
from urllib.parse import urlparse

import joblib, numpy as np, requests
from flask import Flask, request, jsonify
from flask_cors import CORS

from feature_extractor import (url_features, page_features, features_to_list, registered_domain,
                               is_blocked_host, WebsiteFetchError, BlockedTargetError,
                               URL_FEATURE_NAMES, FULL_FEATURE_NAMES)

# ── configuration ────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()           # set in your environment, never in code
VT_URL     = "https://www.virustotal.com/api/v3/urls"
VT_TIMEOUT = 4
CACHE_TTL  = 6 * 3600
CACHE_MAX  = 2000
# Who may call this API. Default = browser extensions only. Add origins with ALLOWED_ORIGINS="a,b".
ALLOWED_ORIGINS = [r"chrome-extension://.*", r"moz-extension://.*"] + \
                  [o for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o]

logging.basicConfig(level=logging.INFO)
logger  = logging.getLogger("phishguard")
app     = Flask(__name__)
CORS(app, origins=ALLOWED_ORIGINS)
session = requests.Session()
lock    = threading.Lock()
VT_CACHE, VT_SUBMITTED = {}, {}

TOP_WHITELIST = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "wikipedia.org", "yahoo.com", "reddit.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "netflix.com", "github.com", "stackoverflow.com", "worldbank.org",
    "bbc.co.uk", "cloudflare.com", "techcrunch.com", "medium.com",
}
# Hosts on whitelisted domains where ANYONE can publish pages -> never auto-allow
USER_CONTENT_HOSTS = ("sites.google.com", "docs.google.com", "drive.google.com", "forms.gle",
                      "storage.googleapis.com", "googleusercontent.com", "firebaseapp.com", "web.app")

# ── model ────────────────────────────────────────────────────────────────────
url_model = full_model = None
try:
    art = joblib.load(MODEL_PATH)
    if not (isinstance(art, dict) and "url_model" in art and "full_model" in art):
        raise ValueError("phishing_model.pkl is an old format - retrain with train_model.py")
    if art["url_features"] != URL_FEATURE_NAMES or art["full_features"] != FULL_FEATURE_NAMES:
        raise ValueError("Model feature list differs from feature_extractor.py - retrain")
    if art.get("positive_class") != 1 or list(art["full_model"].classes_) != [0, 1]:
        raise ValueError("Unexpected class layout (1 must be phishing)")
    url_model, full_model = art["url_model"], art["full_model"]
    logger.info("Models loaded (v%s)", art.get("version"))
except FileNotFoundError:
    logger.warning("Model file not found: %s", MODEL_PATH)
except Exception:
    logger.exception("Could not load the models")


def cache_put(cache, key, value):
    with lock:
        if len(cache) >= CACHE_MAX:
            cache.pop(next(iter(cache)))
        cache[key] = value


# ── input validation ─────────────────────────────────────────────────────────
def normalize_url(raw):
    if not isinstance(raw, str):
        raise ValueError("URL must be a string.")
    url = raw.strip()
    if not url or len(url) > 4096:
        raise ValueError("URL is empty or too long.")
    if any(ord(c) < 32 for c in url):
        raise ValueError("URL contains invalid control characters.")
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not p.hostname:
        raise ValueError("URL must contain a valid hostname.")
    if p.username or p.password:
        raise ValueError("URLs containing embedded credentials are not supported.")
    return url, p

REAL_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "whatsapp.com",
    "facebook.com", "instagram.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "apple.com", "icloud.com",
    "amazon.com", "paypal.com", "linkedin.com", "github.com",
    "twitter.com", "x.com", "yahoo.com", "dropbox.com",
    "zoom.us", "netflix.com", "wikipedia.org",
}

# ── heuristics ───────────────────────────────────────────────────────────────
import re

LURE_WORDS = ("login", "logging", "signin", "secure", "verify", "account",
              "update", "voicemail", "webmail", "password")

def url_heuristics(url):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if registered_domain(url) in REAL_DOMAINS:
        return 0, []
    score, reasons = 0, []
    if any(w in host for w in LURE_WORDS):
        score += 25
        reasons.append("Lure word in domain name")
    if re.search(r"[a-z0-9-]+\.(com|net|org|co|ng|info)\b", p.path.lower()):
        score += 30
        reasons.append("Another domain name inside the URL path")
    if re.search(r"(email|user|login|pass)=", p.query.lower()):
        score += 20
        reasons.append("Credential or email parameter in URL")
    return score, reasons


def heuristic_check(feats, url):
    score, flags = 0, []
    u_score, u_flags = url_heuristics(url)
    score += u_score
    flags += u_flags
    if feats.get("IsDomainIP"):
        score += 75; flags.append("Website host is a raw IP address")
    if feats.get("BrandImpersonation"):
        score += 60; flags.append("Brand name used on a domain that doesn't belong to that brand")
    if feats.get("HasExternalFormSubmit") and feats.get("HasPasswordField"):
        score += 45; flags.append("Password form submits data to a different domain")
    if feats.get("OnFreePlatform") and feats.get("HasPasswordField"):
        score += 35; flags.append("Password form hosted on a free/shared platform")
    if feats.get("HasAtSymbol"):
        score += 25; flags.append("'@' in the address can hide the real destination")
    if feats.get("HasPunycode"):
        score += 25; flags.append("Punycode domain (possible look-alike characters)")
    return {"heuristic_score": min(score, 100), "flags": flags}


# ── VirusTotal (non-blocking: look up first, submit only if unknown) ─────────
def virustotal_check(url):
    unavailable = {"vt_available": False, "vt_malicious": 0, "vt_engines": 0, "vt_verdict": "unknown"}
    if not VT_API_KEY:
        return {**unavailable, "vt_verdict": "not_configured"}
    now = time.time()
    with lock:
        hit = VT_CACHE.get(url)
    if hit and now - hit["ts"] < CACHE_TTL:
        return dict(hit["result"])

    headers = {"x-apikey": VT_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = session.get(f"{VT_URL}/{url_id}", headers=headers, timeout=VT_TIMEOUT)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"].get("last_analysis_stats") or {}
            total = sum(int(v) for v in stats.values())
            if total:
                mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
                result = {"vt_available": True, "vt_malicious": mal, "vt_suspicious": sus, "vt_engines": total,
                          "vt_verdict": "phishing" if mal >= 3 else "suspicious" if mal + sus else "no_detections"}
                cache_put(VT_CACHE, url, {"result": result, "ts": now})
                return result
            return {**unavailable, "vt_verdict": "pending"}
        if r.status_code == 404:                      # never scanned: submit once, check again on a later request
            if now - VT_SUBMITTED.get(url, 0) > 300:
                s = session.post(VT_URL, headers=headers, data={"url": url}, timeout=VT_TIMEOUT)
                if s.status_code in (200, 201):
                    cache_put(VT_SUBMITTED, url, now)
            return {**unavailable, "vt_verdict": "pending"}
        logger.warning("VirusTotal returned HTTP %s", r.status_code)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        logger.warning("VirusTotal check failed", exc_info=True)
    return unavailable


# ── model ────────────────────────────────────────────────────────────────────
def _predict(model, names, feats):
    vec = np.asarray(features_to_list(feats, names), dtype=float).reshape(1, -1)
    return float(model.predict_proba(vec)[0][1])      # class 1 = phishing (checked at load time)


# The page model was trained on rich homepages only, so it calls ANY small/plain page phishing
# (real sites like claude.ai and netacad.com send scripts a thin page and scored ~100%).
# So page evidence may lower the risk a lot, but may raise it only a little.
PAGE_LOWER_WEIGHT = 0.5
PAGE_RAISE_WEIGHT = 0.15


def ml_scores(feats, page_ok):
    """Returns (final_probability, url_model_probability, page_model_probability_or_None)."""
    if url_model is None or full_model is None:
        raise RuntimeError("Model unavailable. Run train_model.py to create phishing_model.pkl.")
    p_url = _predict(url_model, URL_FEATURE_NAMES, feats)
    if not page_ok:
        return p_url, p_url, None
    p_page = _predict(full_model, FULL_FEATURE_NAMES, feats)
    if p_page < p_url:      # page looks richer/safer than the URL suggests
        final = (1 - PAGE_LOWER_WEIGHT) * p_url + PAGE_LOWER_WEIGHT * p_page
    else:                   # page looks worse: only a small nudge up
        final = p_url + PAGE_RAISE_WEIGHT * (p_page - p_url)
    return final, p_url, p_page


# ── scoring ──────────────────────────────────────────────────────────────────
WHITELIST_RISK = 0.02        # fixed policy value for trusted domains (not a model output)
BLOCK_AT, WARN_AT = 0.85, 0.50   # chosen from the held-out calibration table (URL-only: >=0.85 is ~97% precise)


def vt_evidence(vt):
    """Turn VirusTotal detections into a 0-1 risk. 1-2 hits are often false positives, so they count less."""
    mal = vt.get("vt_malicious", 0)
    return 0.95 if mal >= 3 else 0.25 if mal >= 1 else 0.0


def combine_risk(ml, heuristic_score, vt):
    """Noisy-OR: each source can only ADD evidence of phishing. A rule that doesn't fire (score 0)
    no longer drags a confident model result down, which is what produced the old 58%."""
    risk = 1 - (1 - ml) * (1 - heuristic_score / 100.0) * (1 - vt_evidence(vt))
    return min(max(risk, 0.01), 0.99)


# ── routes ───────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return jsonify({"service": "PhishGuard API", "status": "running",
                    "model_loaded": url_model is not None, "vt_enabled": bool(VT_API_KEY)})


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError("Send a JSON object like {\"url\": \"https://...\"}.")
        url, parsed = normalize_url(data.get("url"))
        host = (parsed.hostname or "").lower()

        if is_blocked_host(host):                     # IP literals, localhost, LAN, metadata, names resolving to private IPs
            return jsonify({"error": "Local or private network addresses cannot be scanned."}), 400

        feats = url_features(url)

        # Tier 1: whitelist exits BEFORE any network request
        if (registered_domain(url) in TOP_WHITELIST and not host.endswith(USER_CONTENT_HOSTS)
                and not feats["HasAtSymbol"] and not feats["OnFreePlatform"]):
            return jsonify({"url": url, "prediction": "legitimate", "action": "ALLOW",
                            "risk_score": WHITELIST_RISK, "confidence": round(1 - WHITELIST_RISK, 3),
                            "mode": "whitelist", "ml_proba": None, "ml_url": None, "ml_page": None, "heuristic_score": 0,
                            "heuristic_flags": ["Established domain (whitelist)"],
                            "virustotal": {"vt_available": False, "vt_verdict": "skipped", "vt_malicious": 0}})

        # Page inspection; if it fails we still answer, using the URL-only model
        page_ok, note = True, None
        try:
            feats.update(page_features(url))
        except BlockedTargetError:
            return jsonify({"error": "Local or private network addresses cannot be scanned."}), 400
        except WebsiteFetchError as exc:
            page_ok, note = False, str(exc)

        ml, ml_url, ml_page = ml_scores(feats, page_ok)
        h = heuristic_check(feats, url)
        vt = (virustotal_check(url) if ml >= 0.35 or h["heuristic_score"] >= 25
              else {"vt_available": False, "vt_verdict": "skipped", "vt_malicious": 0})

        risk = combine_risk(ml, h["heuristic_score"], vt)
        if vt.get("vt_malicious", 0) >= 3 or h["heuristic_score"] >= 75 or risk >= BLOCK_AT:
            verdict, action = "phishing", "BLOCK"
        elif risk >= WARN_AT:
            verdict, action = "suspicious", "ADVISORY_BADGE"
        else:
            verdict, action = "legitimate", "ALLOW"
        # "confidence" = how sure we are of the verdict shown: risk for a warning, (1 - risk) for a safe site
        confidence = risk if verdict != "legitimate" else 1 - risk

        return jsonify({"url": url, "prediction": verdict, "action": action,
                        "risk_score": round(risk, 3), "confidence": round(confidence, 3),
                        "mode": "url+page" if page_ok else "url_only", "note": note,
                        "ml_proba": round(ml, 4), "ml_url": round(ml_url, 4),
                        "ml_page": None if ml_page is None else round(ml_page, 4),
                        "heuristic_score": h["heuristic_score"],
                        "heuristic_flags": h["flags"], "virustotal": vt})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Prediction failed")
        return jsonify({"error": "Could not analyse this URL. Check the server logs."}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
