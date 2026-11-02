"""
download_datasets.py v4.0
Builds urls_extra.csv (columns: url,label,source) with label 1 = PHISHING, 0 = LEGITIMATE.
These extra URLs are used ONLY for the URL-only model (they have no page data).
PhiUSIIL (dataset.csv) is read directly by train_model.py - it is NOT merged here, because
its label is reversed (1 = legit) and its page features can't be rebuilt for scraped URLs.

Run:  python download_datasets.py   then   python train_model.py dataset.csv urls_extra.csv
"""
import io, sys, zipfile
import pandas as pd, requests

UA = {"User-Agent": "phishguard-research/1.0"}
frames = []

def add(urls, label, source):
    df = pd.DataFrame({"url": list(urls), "label": label, "source": source})
    frames.append(df); print(f"  -> {len(df)} rows from {source}")

print("[1] OpenPhish (phishing)")
try:
    r = requests.get("https://openphish.com/feed.txt", headers=UA, timeout=30); r.raise_for_status()
    add([u.strip() for u in r.text.splitlines() if u.startswith("http")][:3000], 1, "openphish")
except Exception as e:
    print(f"  [WARN] skipped: {e}")

print("[2] PhishTank (phishing)")
try:
    r = requests.get("http://data.phishtank.com/data/online-valid.csv", headers=UA, timeout=60); r.raise_for_status()
    pt = pd.read_csv(io.StringIO(r.text), usecols=["url"], on_bad_lines="skip").dropna()
    add(pt["url"].head(5000), 1, "phishtank")
except Exception as e:
    print(f"  [WARN] skipped: {e}")

print("[3] Tranco top sites (legitimate)")
try:
    r = requests.get("https://tranco-list.eu/top-1m.csv.zip", headers=UA, timeout=120); r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        t = pd.read_csv(z.open(z.namelist()[0]), header=None, names=["rank", "domain"], nrows=20000)
    add("https://" + t["domain"], 0, "tranco")
except Exception as e:
    print(f"  [WARN] skipped: {e}")

if not frames:
    sys.exit("[ERROR] nothing downloaded")
out = pd.concat(frames, ignore_index=True).drop_duplicates("url")
out.to_csv("urls_extra.csv", index=False)
print(f"[INFO] Saved urls_extra.csv: {len(out)} URLs (phishing={int((out.label==1).sum())}, legit={int((out.label==0).sum())})")
