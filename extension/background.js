
/**
 * PhishGuard background service worker
 * Connects to the local Flask API and updates the extension badge.
 */

const API_ENDPOINT = "http://127.0.0.1:5000/predict";
const cache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;

async function checkUrl(url) {
  const now = Date.now();
  const cached = cache.get(url);

  if (cached && now - cached.ts < CACHE_TTL_MS) {
    return cached;
  }

  try {
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      console.error(
        "[PhishGuard] API returned HTTP",
        response.status,
        await response.text()
      );
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

      // app.py returns risk_score, not confidence.
      riskScore: Number(data.risk_score ?? data.confidence ?? 0),

      flags: Array.isArray(data.heuristic_flags)
        ? data.heuristic_flags
        : [],

      ts: now,
    };

    cache.set(url, entry);
    return entry;

  } catch (error) {
    console.error("[PhishGuard] Cannot connect to API:", error);
    return null;
  }
}

async function injectWarning(tabId, flags) {
  const details = flags.length
    ? flags.join(" • ")
    : "One or more detection signals raised an alert.";

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (detailText) => {
        if (!document.body ||
            document.getElementById("phishguard-overlay")) {
          return;
        }

        const overlay = document.createElement("div");
        overlay.id = "phishguard-overlay";
        overlay.style.cssText = [
          "position:fixed",
          "inset:0",
          "width:100%",
          "height:100%",
          "background:rgba(150,0,0,0.97)",
          "z-index:2147483647",
          "display:flex",
          "flex-direction:column",
          "align-items:center",
          "justify-content:center",
          "font-family:Arial,sans-serif",
          "color:white",
          "padding:24px",
          "box-sizing:border-box",
          "text-align:center"
        ].join(";");

        const heading = document.createElement("h1");
        heading.textContent = "PHISHGUARD WARNING";
        heading.style.cssText = "font-size:2rem;margin-bottom:12px";

        const message = document.createElement("p");
        message.textContent =
          "This website has been flagged as potentially dangerous.";
        message.style.cssText =
          "max-width:560px;line-height:1.6";

        const details = document.createElement("p");
        // Use textContent so returned text cannot inject HTML.
        details.textContent = detailText;
        details.style.cssText =
          "max-width:560px;padding:12px;background:#500;border-radius:8px";

        const backButton = document.createElement("button");
        backButton.textContent = "Go Back";
        backButton.style.cssText =
          "padding:12px 20px;margin-top:16px;cursor:pointer";
        backButton.addEventListener("click", () => history.back());

        overlay.append(heading, message, details, backButton);
        document.body.appendChild(overlay);
      },
      args: [details],
    });
  } catch (error) {
    console.warn(
      "[PhishGuard] Could not display warning on this tab:",
      error
    );
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;

  const url = tab.url || "";
  if (!/^https?:\/\//i.test(url)) return;

  void (async () => {
    const result = await checkUrl(url);

    if (!result) {
      chrome.action.setBadgeText({ tabId, text: "?" });
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: "#6B7280",
      });
      return;
    }

    if (result.action === "BLOCK") {
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: "#DC2626",
      });
      await injectWarning(tabId, result.flags);

    } else if (result.action === "ADVISORY_BADGE") {
      chrome.action.setBadgeText({ tabId, text: "?" });
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: "#D97706",
      });

    } else {
      chrome.action.setBadgeText({ tabId, text: "✓" });
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: "#16A34A",
      });
    }
  })();
});
