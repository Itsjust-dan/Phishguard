const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const reasons = params.get("reasons") || "";

document.getElementById("site").textContent = target;
document.getElementById("reasons").textContent =
  reasons || "One or more detection signals raised an alert.";

document.getElementById("close").addEventListener("click", () => {
  chrome.tabs.getCurrent((tab) => {
    if (tab) chrome.tabs.remove(tab.id);
  });
});

document.getElementById("proceed").addEventListener("click", (e) => {
  e.preventDefault();
  if (!/^https?:\/\//i.test(target)) return;
  chrome.runtime.sendMessage({ type: "allow", url: target }, () => {
    location.href = target;
  });
});