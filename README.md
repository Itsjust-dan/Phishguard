# PhishGuard

PhishGuard is a browser extension that checks the websites you visit for signs of phishing and warns you before you enter your details. It combines a machine learning model, a set of warning-sign rules, and a VirusTotal lookup, served by a small Flask API.

It was built as a final-year Computer Science project at Bells University of Technology.

## How it works

1. When a page finishes loading, the extension sends the page's address (without the `#fragment`) to the PhishGuard API.
2. The API scores the address in three ways:
   - **Machine learning:** a calibrated Random Forest model. When the page can be fetched, a second model looks at the page itself (forms, links, scripts) and adjusts the score.
   - **Rules:** checks for things like lure words in the domain, a raw IP address as the host, `@` in the address, look-alike (punycode) domains, brand names on the wrong domain, and password forms that send data to another domain.
   - **VirusTotal:** looked up only for sites that already look suspicious.
3. The scores are combined into one risk value, and the extension shows the result:

| Badge | Meaning |
|-------|---------|
| ✓ | Looks safe |
| ? | Suspicious, or the server could not be reached |
| ! | Phishing. The page is replaced with a warning page |

Well-known sites (for example Google, GitHub and Wikipedia) are allowed straight away without being scanned. Sites that let anyone publish pages, such as `sites.google.com`, are never auto-allowed.

On the warning page you can close the tab or choose to proceed anyway.

## Install

**Chrome Web Store:** [Install PhishGuard](https://chromewebstore.google.com/detail/phishguard-phishing-detec/nckdcimpkdgnakbdgmpcabhgamgiodee)

**Manual install (Chrome, Brave, Edge):**
1. Go to the [latest release](https://github.com/Itsjust-dan/Phishguard/releases/latest) and download `phishguard-extension.zip`.
2. Unzip it.
3. Open `chrome://extensions` and turn on **Developer mode**.
4. Click **Load unpacked** and choose the unzipped folder.

The hosted API runs on a free server, so the first check after a long quiet spell can take up to a minute.

If PhishGuard helps you, you can [support it here](https://github.com/sponsors/Itsjust-dan).

## Privacy

The extension sends the address of each page you visit to the PhishGuard server and, for suspicious sites, to VirusTotal. It does not read page contents, form entries, passwords or cookies. See [PRIVACY.md](PRIVACY.md) for the full policy.

The extension asks for one permission, `tabs`, which it uses to read the address of the page being loaded and to update the toolbar badge.

## Project layout

```
PhishGuard/
├── app.py                # Flask API (POST /predict, GET / health check)
├── feature_extractor.py  # URL and page feature extraction
├── train_model.py        # trains and saves the models
├── download_datasets.py  # fetches the extra training URLs
├── phishing_model.pkl    # trained models used by the API
├── requirements.txt
├── PRIVACY.md
└── extension/            # the browser extension
    ├── manifest.json
    ├── background.js     # checks each page and sets the badge
    ├── popup.html / popup.js / styles.css
    ├── warning.html / warning.js
    └── icons/
```

## Run it yourself

You need Python 3.13 or similar.

```bash
git clone https://github.com/Itsjust-dan/Phishguard.git
cd Phishguard
python -m venv .venv
.venv\Scripts\activate          # on macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Optional: set a VirusTotal API key so suspicious sites are also checked there. Without it, the API still works using the model and rules.

```bash
set VT_API_KEY=your_key_here    # on macOS/Linux: export VT_API_KEY=your_key_here
python app.py
```

The API listens on `http://127.0.0.1:5000`. Test it:

```bash
curl -X POST http://127.0.0.1:5000/predict -H "Content-Type: application/json" -d "{\"url\": \"https://example.com\"}"
```

The response includes `prediction` (`legitimate`, `suspicious` or `phishing`), `action` (`ALLOW`, `ADVISORY_BADGE` or `BLOCK`), `risk_score`, the individual model scores, the rule flags that fired, and the VirusTotal result.

### Use your local API with the extension

The published extension points at the hosted server. To use your own, change the address in three places:
- `API_ENDPOINT` in `extension/background.js`
- `API_ENDPOINT` in `extension/popup.js`
- `host_permissions` in `extension/manifest.json`

Then load the `extension` folder with **Load unpacked** as described above.

### Retrain the model

1. Download the [PhiUSIIL Phishing URL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) and save the CSV in the project folder as `dataset.csv`.
2. Fetch the extra URLs (PhishTank, OpenPhish and Tranco), which creates `urls_extra.csv`:

```bash
python download_datasets.py
```

3. Train:

```bash
python train_model.py dataset.csv urls_extra.csv
```

This prints the held-out results shown below and **overwrites** `phishing_model.pkl`. The API checks the model's feature list when it starts, so if you change `feature_extractor.py` you must retrain.

## Deployment

The API is deployed on Render with:

```
gunicorn app:app --workers 1 --threads 4 --timeout 60
```

and the environment variable `VT_API_KEY`. By default it only accepts browser requests from extensions. To allow other origins, set `ALLOWED_ORIGINS` to a comma-separated list.

The `/predict` endpoint is rate limited to 120 requests a minute and 5,000 a day for each visitor. Behind Render and Cloudflare, the visitor is identified from the `True-Client-IP` header.

## Model evaluation

PhishGuard uses two calibrated Random Forest models: a **URL-only** model (used whenever the page cannot be fetched) and a **URL + page** model. Both were trained on the PhiUSIIL dataset (235,370 unique URLs after removing duplicates: 100,520 phishing and 134,850 legitimate). The URL-only model was also trained on 24,261 extra URLs (4,930 phishing) from PhishTank and OpenPhish, plus legitimate sites from the Tranco list. Some legitimate training rows were given extra subdomains (for example `auth.` or `mail.`), because almost every legitimate URL in the dataset starts with `www.`.

**How it was tested:** 20% of sites were held out, split by registered domain, so no site appears in both the training and test data. Precision, recall and the "at 0.5" false alarm rate use a 0.5 threshold.

| Model | AUC | Precision | Recall | False alarms at 0.5 | False alarms at 0.85 |
|-------|-----|-----------|--------|---------------------|----------------------|
| URL only | 0.853 | 95.6% | 63.6% | 2.2% | 0.08% |
| URL + page | 1.000 | 99.9% | 99.5% | 0.08% | 0.03% |

"False alarms" is the share of legitimate sites wrongly flagged as phishing. A stress test took 4,000 held-out legitimate sites and added a subdomain: the URL-only model flagged 4.1% of them at 0.5 and 0.4% at 0.85.

**How to read these results**
- The URL-only model misses about a third of phishing URLs at a 0.5 threshold. That is why the API also applies warning-sign rules and a VirusTotal lookup, and why pages are only blocked at high risk.
- The near-perfect page-model score reflects the dataset, not real-world performance. In PhiUSIIL, legitimate pages are full homepages, so the model learns that small, plain pages look suspicious. The API therefore lets page evidence lower the risk a lot but raise it only a little.
- The final verdict combines the models, the rules and VirusTotal, so no single row above is the accuracy of the whole system.
- These figures come from re-running the training script on current data. The PhishTank, OpenPhish and Tranco lists change daily, so they will not exactly match the model file in this repository.

## Limitations

- PhishGuard reduces risk but cannot guarantee that a site is safe. Always check links carefully, especially in emails and messages.
- It judges addresses and page structure. It cannot catch every new or targeted phishing page, and it can occasionally flag a legitimate site.
- Page analysis depends on the server being able to fetch the page. If it cannot, the API falls back to the address-only model.
- Local, private-network and IP-literal addresses are deliberately not scanned.

## Data and credits

- Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website)* [Dataset]. UCI Machine Learning Repository. https://doi.org/10.1016/j.cose.2023.103545 (CC BY 4.0).
- Phishing URL feeds from [PhishTank](https://phishtank.com) and [OpenPhish](https://openphish.com).
- Legitimate site list from [Tranco](https://tranco-list.eu).

## Author

Adejinmi Dan Toluwase

## Licence

See [LICENSE](LICENSE).