/**
 * PhishGuard background service worker
 * Checks each page you visit with the PhishGuard API and updates the badge.
 * Pages flagged as phishing are replaced with a warning page.
 */

const API_ENDPOINT = "https://phishguard-api-a1xe.onrender.com/predict";
const cache = new Map();
const allowed = new Set();
const CACHE_TTL_MS = 10 * 60 * 1000;

// Remove the #fragment so tokens in it are never sent to the server
function cleanUrl(url) {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.href;
  } catch {
    return url;
  }
}

async function checkUrl(url) {
  const now = Date.now();
  const cached = cache.get(url);
  if (cached && now - cached.ts < CACHE_TTL_MS) return cached;

  try {
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) {
      console.error("[PhishGuard] API returned HTTP", response.status);
      return null;
    }

    const data = await response.json();
    if (!data.prediction || !data.action) {
      console.error("[PhishGuard] Unexpected API response:", data);
      return null;
    }

    const entry = {
      prediction: data.prediction,
      action: data.action,
      riskScore: Number(data.risk_score ?? data.confidence ?? 0),
      flags: Array.isArray(data.heuristic_flags) ? data.heuristic_flags : [],
      ts: now,
    };
    cache.set(url, entry);
    return entry;
  } catch (error) {
    console.error("[PhishGuard] Cannot connect to API:", error);
    return null;
  }
}

// The warning page asks us to let one URL through after "Proceed anyway"
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "allow" && typeof msg.url === "string") {
    allowed.add(msg.url);
    sendResponse({ ok: true });
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;

  const url = cleanUrl(tab.url || "");
  if (!/^https?:\/\//i.test(url)) return;

  void (async () => {
    chrome.action.setBadgeText({ tabId, text: "…" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6B7280" });

    const result = await checkUrl(url);

    if (!result) {
      chrome.action.setBadgeText({ tabId, text: "?" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#6B7280" });
      return;
    }

    if (result.action === "BLOCK") {
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#DC2626" });

      if (!allowed.has(url)) {
        const warningPage =
          chrome.runtime.getURL("warning.html") +
          "?url=" + encodeURIComponent(url) +
          "&reasons=" + encodeURIComponent(result.flags.join(" • "));
        chrome.tabs.update(tabId, { url: warningPage });
      }
    } else if (result.action === "ADVISORY_BADGE") {
      chrome.action.setBadgeText({ tabId, text: "?" });
      chrome.action.setBadgeBackgroundColor({tabId,color: "#D97706" });
    } else {
      chrome.action.setBadgeText({ tabId, text: "✓" });
      chrome.action.setBadgeBackgroundColor({tabId,color: "#16A34A" });
    }
  })();
});
