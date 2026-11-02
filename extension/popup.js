
/**
 * PhishGuard popup
 * Matches the response schema returned by app.py.
 */

const API_ENDPOINT = "http://127.0.0.1:5000/predict";

const elUrl = document.getElementById("current-url");
const elResultCard = document.getElementById("result-card");
const elLoading = document.getElementById("loading");
const elError = document.getElementById("error-section");
const elErrorMsg = document.getElementById("error-message");
const elIconEmoji = document.getElementById("icon-emoji");
const elStatusTitle = document.getElementById("status-title");
const elStatusMsg = document.getElementById("status-message");
const elConfidence = document.getElementById("confidence-value");
const elRiskBar = document.getElementById("risk-bar");
const elScanBtn = document.getElementById("scan-btn");
const elDetails = document.getElementById("details-section");

function show(el) {
  if (el) el.classList.remove("hidden");
}

function hide(el) {
  if (el) el.classList.add("hidden");
}

function truncate(value, max = 52) {
  const text = String(value || "");
  return text.length > max ? text.slice(0, max) + "…" : text;
}

function addDetailRow(container, label, value) {
  const row = document.createElement("div");
  row.className = "detail-row";

  const labelElement = document.createElement("span");
  labelElement.className = "detail-label";
  labelElement.textContent = label;

  const valueElement = document.createElement("span");
  valueElement.className = "detail-val";
  valueElement.textContent = value;

  row.append(labelElement, valueElement);
  container.appendChild(row);
}

function renderDetails(data) {
  if (!elDetails) return;

  const grid = document.createElement("div");
  grid.className = "detail-grid";

  // These fields match the current Flask API response.
  const isWhitelist = data.mode === "whitelist";
  const mlProbability = Number(data.ml_proba ?? 0);
  const heuristicScore = Number(data.heuristic_score ?? 0);
  const heuristicFlags = isWhitelist
    ? []   // "Established domain (whitelist)" is good news, not a risk signal
    : (Array.isArray(data.heuristic_flags) ? data.heuristic_flags : []);

  if (isWhitelist) {
    addDetailRow(grid, "Trust check", "Established domain (trusted list)");
  } else {
    addDetailRow(
      grid,
      "ML Model",
      `${Math.round(mlProbability * 100)}% phishing probability`
    );

    addDetailRow(grid, "Heuristics", `${heuristicScore}/100`);

    if (data.mode === "url+page") {
      addDetailRow(grid, "Scan type", "URL + page content");
    } else if (data.mode === "url_only") {
      addDetailRow(grid, "Scan type", "URL only (page could not be loaded)");
    }
  }

  const vt = data.virustotal || {};
  const vtAvailable = Boolean(vt.vt_available ?? vt.available);

  if (vtAvailable) {
    const malicious = Number(vt.vt_malicious ?? vt.malicious ?? 0);
    const engines = Number(vt.vt_engines ?? vt.engines ?? 0);

    addDetailRow(
      grid,
      "VirusTotal",
      `${malicious} detections / ${engines} engines`
    );
  } else {
    let vtMessage = "Not checked";

    if (vt.vt_verdict === "pending") {
      vtMessage = "Scan pending";
    } else if (vt.vt_verdict === "not_configured") {
      vtMessage = "Not configured";
    } else if (vt.vt_verdict === "unknown") {
      vtMessage = "Unavailable";
    }

    addDetailRow(grid, "VirusTotal", vtMessage);
  }

  if (heuristicFlags.length > 0) {
    const section = document.createElement("div");
    section.className = "flags-section";

    const heading = document.createElement("p");
    heading.className = "flags-title";
    heading.textContent = "⚠️ Risk signals detected:";

    const list = document.createElement("ul");

    for (const flag of heuristicFlags) {
      const item = document.createElement("li");
      item.textContent = String(flag);
      list.appendChild(item);
    }

    section.append(heading, list);
    grid.appendChild(section);
  }

  elDetails.replaceChildren(grid);
  show(elDetails);
}

function renderResult(data) {
  hide(elLoading);
  hide(elError);
  show(elResultCard);

  // risk_score = overall phishing risk (0-1). confidence = how sure we are of the verdict shown:
  // risk for a warning, (1 - risk) for a safe site.
  const rawRisk = Number(data.risk_score ?? 0);
  const risk = Number.isFinite(rawRisk)
    ? Math.max(0, Math.min(1, rawRisk))
    : 0;

  const prediction = String(data.prediction || "").toLowerCase();
  const action = String(data.action || "").toUpperCase();

  const isPhishing = action === "BLOCK" || prediction === "phishing";
  const isSuspicious =
    !isPhishing &&
    (action === "ADVISORY_BADGE" || prediction === "suspicious");
  const isSafe = !isPhishing && !isSuspicious;
  const limited = isSafe && data.mode === "url_only";

  const rawConf = Number(data.confidence);
  const conf = Number.isFinite(rawConf)
    ? Math.max(0, Math.min(1, rawConf))
    : (isSafe ? 1 - risk : risk);
  const percentage = Math.round(conf * 100);

  elConfidence.textContent = isSafe ? `${percentage}% safe` : `${percentage}% risk`;
  if (limited) elConfidence.textContent = "Limited scan";
  elConfidence.title = isSafe
    ? "How confident the scan is that this site is safe. Not a guarantee."
    : "Estimated phishing risk. Not a guarantee.";

  elRiskBar.style.width = `${percentage}%`;

  elRiskBar.style.background = "";

  if (isPhishing) {
    elResultCard.className = "result-card danger";
    elIconEmoji.textContent = "🚨";
    elStatusTitle.textContent = "PHISHING DETECTED";
    elStatusMsg.textContent =
      "This website was flagged as potentially dangerous. Avoid entering passwords or sensitive information.";
    elRiskBar.className = "risk-bar bar-danger";
  } else if (isSuspicious) {
    elResultCard.className = "result-card neutral";
    elIconEmoji.textContent = "⚠️";
    elStatusTitle.textContent = "SUSPICIOUS WEBSITE";
    elStatusMsg.textContent =
      "PhishGuard detected warning signals. Proceed carefully and avoid entering sensitive information until you can verify the site.";
    elRiskBar.className = "risk-bar";
    elRiskBar.style.background = "#D97706";   // amber, so the bar is visible for warnings
  } else if (limited) {
    elResultCard.className = "result-card neutral";
    elIconEmoji.textContent = "❔";
    elStatusTitle.textContent = "Inconclusive: page not loaded";
    elStatusMsg.textContent =
      "The page couldn't be loaded, so only the web address was checked. No red flags were found in the address, but don't enter passwords unless you're sure of the site.";
    elRiskBar.className = "risk-bar";
    elRiskBar.style.background = "#6B7280";
  } else {
    elResultCard.className = "result-card safe";
    elIconEmoji.textContent = "✅";
    elStatusTitle.textContent = "Site Appears Safe";
    elStatusMsg.textContent =
      "No strong phishing indicators were identified by this scan. This is not a guarantee that the site is safe.";
    elRiskBar.className = "risk-bar bar-safe";
  }

  renderDetails(data);
}

function renderError(message) {
  hide(elLoading);
  hide(elResultCard);
  hide(elDetails);
  show(elError);

  if (elErrorMsg) {
    elErrorMsg.textContent = `⚠️ ${message}`;
  }
}

async function scanCurrentTab() {
  hide(elResultCard);
  hide(elError);
  hide(elDetails);
  show(elLoading);

  let tabUrl = "";

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    tabUrl = tab?.url || "";
  } catch (error) {
    console.error("[PhishGuard] Could not retrieve current tab:", error);
    renderError("Could not retrieve the current tab URL.");
    return;
  }

  if (elUrl) {
    elUrl.textContent = truncate(tabUrl);
    elUrl.title = tabUrl;
  }

  if (!/^https?:\/\//i.test(tabUrl)) {
    hide(elLoading);
    show(elResultCard);

    elResultCard.className = "result-card neutral";
    elIconEmoji.textContent = "ℹ️";
    elStatusTitle.textContent = "Not a web page";
    elStatusMsg.textContent =
      "Phishing detection only works on HTTP or HTTPS pages.";
    elConfidence.textContent = "—";
    elRiskBar.style.width = "0%";

    return;
  }

  try {
    console.log("[PhishGuard] Starting scan:", tabUrl);
console.log("[PhishGuard] API endpoint:", API_ENDPOINT);
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: tabUrl }),
      signal: AbortSignal.timeout(15000)
    });

    const data = await response.json().catch(() => ({}));
    console.log("[PhishGuard] HTTP status:", response.status);
console.log("[PhishGuard] API response:", data);

    if (!response.ok) {
      console.error("[PhishGuard] API error:", response.status, data);
      renderError(data.error || `Detection API returned HTTP ${response.status}.`);
      return;
    }

    if (!data.prediction) {
      console.error("[PhishGuard] Unexpected API response:", data);
      renderError("The detection API returned an unexpected response.");
      return;
    }

    renderResult(data);

  } catch (error) {
    console.error("[PhishGuard] Detection request failed:", error);

    renderError(
      "Cannot connect to the detection API. Check that Flask is running at 127.0.0.1:5000, then reload the extension."
    );
  }
}

if (elScanBtn) {
  elScanBtn.addEventListener("click", scanCurrentTab);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", scanCurrentTab, { once: true });
} else {
  scanCurrentTab();
}
