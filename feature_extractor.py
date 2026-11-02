"""
feature_extractor.py  v4.0

Two groups of features:

  URL_FEATURE_NAMES   (19)  computed from the URL string only. Used for BOTH training and
                            serving, from this one function, so they can never drift apart.
                            Scheme, a leading "www." and the path are ignored on purpose:
                            in PhiUSIIL every legit URL is "https://www.<site>" with no path,
                            so those would only teach dataset artifacts.
  PAGE_FEATURE_NAMES  (25)  read from the downloaded HTML. Training uses the values that ship
                            in PhiUSIIL; serving computes them here.

Dropped on purpose (cannot be recomputed from a URL/HTML, they are scores made by the dataset
authors): URLSimilarityIndex, CharContinuationRate, TLDLegitimateProb, URLCharProb,
DomainTitleMatchScore, URLTitleMatchScore (0-100 fuzzy scores in the data, not 0/1),
NoOfSelfRedirect, and the letter / special-character counts whose definition doesn't match
the data (e.g. DomainLength in the data = length of the whole host incl. "www.").
"""
# pyright: reportAttributeAccessIssue=false, reportOptionalMemberAccess=false, reportCallIssue=false, reportArgumentType=false
import ipaddress, math, re, socket, time
from urllib.parse import urlparse, urljoin

import requests
import tldextract
from bs4 import BeautifulSoup

# ── configuration ────────────────────────────────────────────────────────────
HEADERS = {"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
           "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"}
CONNECT_TIMEOUT, READ_TIMEOUT = 3, 4
TOTAL_DEADLINE = 8.0                 # seconds for the whole download, redirects included
MAX_RESPONSE_BYTES = 2_000_000
MAX_REDIRECTS = 5

SUSPICIOUS_KW = ["login", "verify", "secure", "account", "update", "bank", "password",
                 "confirm", "signin", "credential", "billing", "suspend", "unlock",
                 "recover", "validate", "authorize", "authenticate", "webscr", "wallet"]
BRAND_NAMES = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
               "netflix", "chase", "wellsfargo", "barclays", "hsbc", "dhl", "whatsapp",
               "office365", "outlook", "binance", "coinbase", "linkedin", "twitter"]
BRAND_AFFIXES = {"id", "support", "secure", "security", "login", "signin", "verify", "account",
                 "accounts", "pay", "payment", "mail", "service", "services", "online", "update",
                 "help", "web", "app", "auth", "billing", "wallet", "team", "care"}
REAL_BRAND_DOMAINS = {
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "instagram.com", "netflix.com", "chase.com", "wellsfargo.com", "barclays.co.uk", "hsbc.com",
    "dhl.com", "whatsapp.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com",
    "amazon.co.uk", "binance.com", "coinbase.com", "linkedin.com", "twitter.com", "x.com",
}
FREE_HOSTS = ["github.io", "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
              "glitch.me", "repl.co", "000webhostapp.com", "wixsite.com", "weebly.com",
              "blogspot.com", "sites.google.com", "onrender.com", "pages.dev", "surge.sh",
              "herokuapp.com", "pythonanywhere.com", "ipfs.io"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "support",
              "zip", "mov", "icu", "buzz", "rest", "cyou", "live"}

URL_FEATURE_NAMES = [
    "HostLength", "NumDots", "NumHyphens", "NumDigitsInHost", "DigitRatioInHost",
    "NoOfSubDomain", "DomainLabelMaxLen", "HostEntropy", "IsDomainIP", "TLDLength",
    "RiskyTLD", "HasAtSymbol", "HasPunycode", "IsShortener", "HasPort",
    "SuspiciousKeywords", "BrandImpersonation", "BrandInSubdomain", "OnFreePlatform",
]
PAGE_FEATURE_NAMES = [
    "LineOfCode", "LargestLineLength", "HasTitle", "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "HasDescription", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSocialNet", "HasSubmitButton", "HasHiddenFields", "HasPasswordField", "Bank", "Pay",
    "Crypto", "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
    "NoOfEmptyRef", "NoOfExternalRef",
]
FULL_FEATURE_NAMES = URL_FEATURE_NAMES + PAGE_FEATURE_NAMES


class WebsiteFetchError(Exception):
    """The page could not be downloaded/inspected. Callers fall back to the URL-only model."""


class BlockedTargetError(ValueError):
    """The URL points at a local / private / otherwise forbidden network target."""


# offline-safe public suffix list (no network call at import or first use)
_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ── URL features ─────────────────────────────────────────────────────────────
def _entropy(s):
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def _parse(url):
    url = str(url).strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    try:
        netloc = urlparse(url).netloc.lower()
    except ValueError:
        netloc = ""
    has_at = "@" in netloc
    hostport = netloc.split("@")[-1]
    host = hostport.rsplit(":", 1)[0] if re.search(r":\d*$", hostport) and not hostport.endswith("]") else hostport
    has_port = int(host != hostport)
    host = host.strip("[]").rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return url, host, has_port, has_at, _tld(host)


def _brand_hit(text):
    """Token-based, so 'pineapple-farm.com' does not match 'apple'."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", text) if t]
    for t in tokens:
        for b in BRAND_NAMES:
            if t == b or (t.startswith(b) and t[len(b):] in BRAND_AFFIXES) \
                      or (t.endswith(b) and t[: -len(b)] in BRAND_AFFIXES):
                return True
    return False


def registered_domain(url: str) -> str:
    _, host, _, _, ext = _parse(url)
    return f"{ext.domain}.{ext.suffix}".strip(".").lower() or host


def url_features(url: str) -> dict:
    full, host, has_port, has_at, ext = _parse(url)
    registered = f"{ext.domain}.{ext.suffix}".strip(".")
    is_ip = int(bool(_ip_re.match(host)))
    labels = [l for l in host.split(".") if l]
    digits = sum(c.isdigit() for c in host)
    sub = ext.subdomain[4:] if ext.subdomain.startswith("www.") else ("" if ext.subdomain == "www" else ext.subdomain)
    host_no_tld = host[: len(host) - len(ext.suffix)] if ext.suffix else host
    brand = _brand_hit(host_no_tld) and registered not in REAL_BRAND_DOMAINS and not is_ip
    sub_brand = _brand_hit(sub) if sub else False
    return {
        "HostLength": len(host),
        "NumDots": host.count("."),
        "NumHyphens": host.count("-"),
        "NumDigitsInHost": digits,
        "DigitRatioInHost": round(digits / len(host), 4) if host else 0,
        "NoOfSubDomain": 0 if is_ip else len([l for l in sub.split(".") if l]),
        "DomainLabelMaxLen": max((len(l) for l in labels), default=0),
        "HostEntropy": round(_entropy(host), 4),
        "IsDomainIP": is_ip,
        "TLDLength": len(labels[-1]) if labels and not is_ip else 0,
        "RiskyTLD": int(ext.suffix.split(".")[-1] in RISKY_TLDS),
        "HasAtSymbol": int(has_at),
        "HasPunycode": int("xn--" in host),
        "IsShortener": int(registered in SHORTENERS),
        "HasPort": has_port,
        "SuspiciousKeywords": sum(kw in host for kw in SUSPICIOUS_KW),
        "BrandImpersonation": int(brand),
        "BrandInSubdomain": int(bool(sub_brand) and registered not in REAL_BRAND_DOMAINS),
        "OnFreePlatform": int(any(host == h or host.endswith("." + h) for h in FREE_HOSTS)),
    }


def features_to_list(features: dict, names) -> list:
    missing = [n for n in names if n not in features]
    if missing:
        raise ValueError(f"Missing features: {missing}")
    return [features[n] for n in names]


# ── network safety ───────────────────────────────────────────────────────────
def is_blocked_host(host: str, resolve: bool = True) -> bool:
    """True for localhost / LAN / loopback / link-local / cloud-metadata targets.
    resolve=True also resolves DNS and checks EVERY returned address."""
    host = (host or "").strip("[]").lower().rstrip(".")
    if not host or host == "localhost" or host.endswith((".local", ".localhost", ".internal", ".lan")):
        return True
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        if not resolve:
            return False
        try:
            ips = [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)]
        except OSError:
            return False          # doesn't resolve: nothing to fetch, handled as fetch failure later
    return any(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
               or ip.is_multicast or ip.is_unspecified for ip in ips)


def _fetch_html(url: str):
    """Download with manual redirect handling so EVERY hop is checked. Returns (html, n_redirects)."""
    deadline = time.monotonic() + TOTAL_DEADLINE
    hops = 0
    while True:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise WebsiteFetchError("Redirected to an unsupported URL.")
        if is_blocked_host(p.hostname):
            raise BlockedTargetError("Target resolves to a local or private network address.")
        try:
            with requests.get(url, headers=HEADERS, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                              allow_redirects=False, verify=True, stream=True) as r:
                if r.is_redirect and r.headers.get("Location"):
                    hops += 1
                    if hops > MAX_REDIRECTS:
                        raise WebsiteFetchError("Too many redirects.")
                    url = urljoin(url, r.headers["Location"])
                    continue
                if r.status_code >= 400:
                    raise WebsiteFetchError(f"Server answered HTTP {r.status_code}.")
                ctype = r.headers.get("Content-Type", "").lower()
                if ctype and "html" not in ctype:
                    raise WebsiteFetchError("Not an HTML page.")
                chunks, total = [], 0
                for chunk in r.iter_content(16384):
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES or time.monotonic() > deadline:
                        raise WebsiteFetchError("Page too large or too slow to inspect.")
                    chunks.append(chunk)
                return b"".join(chunks).decode(r.encoding or "utf-8", errors="replace"), hops, url
        except requests.RequestException as exc:
            raise WebsiteFetchError(f"Could not fetch page ({type(exc).__name__}).") from exc


# ── page features ────────────────────────────────────────────────────────────
def page_features(url: str) -> dict:
    """Downloads the page and returns PAGE_FEATURE_NAMES. Raises WebsiteFetchError / BlockedTargetError."""
    html, hops, final_url = _fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    host = (urlparse(final_url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    def same_site(h):
        h = (h or "").lower()
        h = h[4:] if h.startswith("www.") else h
        return h == host or h.endswith("." + host)

    links = [a.get("href", "").strip() for a in soup.find_all("a", href=True)]
    abs_hosts = [(urlparse(urljoin(final_url, l)).hostname or "") for l in links]
    lines = html.splitlines()
    title = soup.find("title")
    text = soup.get_text(" ", strip=True).lower()
    ext_form = 0
    for f in soup.find_all("form"):
        act = (f.get("action") or "").strip()
        if act:
            ah = urlparse(urljoin(final_url, act)).hostname
            if ah and not same_site(ah):
                ext_form = 1
                break
    meta = lambda n: int(bool(soup.find("meta", attrs={"name": re.compile(n, re.I)})))
    inp = lambda t: int(bool(soup.find("input", attrs={"type": re.compile(t, re.I)})))
    return {
        "LineOfCode": len(lines),
        "LargestLineLength": max((len(l) for l in lines), default=0),
        "HasTitle": int(bool(title and title.get_text(strip=True))),
        "HasFavicon": int(bool(soup.find("link", rel=lambda r: r and "icon" in str(r).lower()))),
        "Robots": meta("robots"),
        "IsResponsive": meta("viewport"),
        "NoOfURLRedirect": min(hops, 1),                    # data is 0/1
        "HasDescription": meta("description"),
        "NoOfPopup": len(re.findall(r"\bwindow\s*\.\s*open\s*\(", html, re.I)),
        "NoOfiFrame": len(soup.find_all("iframe")),
        "HasExternalFormSubmit": ext_form,
        "HasSocialNet": int(any(s in l.lower() for l in links for s in ("facebook", "twitter", "x.com", "linkedin", "instagram", "youtube"))),
        "HasSubmitButton": int(bool(inp("submit") or soup.find("button", attrs={"type": re.compile("submit", re.I)}))),
        "HasHiddenFields": inp("hidden"),
        "HasPasswordField": inp("password"),
        "Bank": int("bank" in text),
        "Pay": int(any(w in text for w in ("pay", "payment", "paypal"))),
        "Crypto": int(any(w in text for w in ("crypto", "bitcoin", "wallet"))),
        "HasCopyrightInfo": int("©" in text or "copyright" in text),
        "NoOfImage": len(soup.find_all("img")),
        "NoOfCSS": len(soup.find_all("link", rel=lambda r: r and "stylesheet" in str(r).lower())),
        "NoOfJS": len(soup.find_all("script", src=True)),
        "NoOfSelfRef": sum(1 for l, h in zip(links, abs_hosts) if l.startswith("/") or same_site(h)),
        "NoOfEmptyRef": sum(1 for l in links if l in ("", "#", "javascript:void(0)")),
        "NoOfExternalRef": sum(1 for h in abs_hosts if h and not same_site(h)),
    }