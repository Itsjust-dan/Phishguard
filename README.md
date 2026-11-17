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

**Chrome Web Store:** submitted and currently in review. The link will be added here once it is approved.

**Manual install (Chrome, Brave, Edge):**
1. Go to the [latest release](https://github.com/Itsjust-dan/Phishguard/releases/latest) and download `phishguard-extension.zip`.
2. Unzip it.
3. Open `chrome://extensions` and turn on **Developer mode**.
4. Click **Load unpacked** and choose the unzipped folder.

The hosted API runs on a free server, so the first check after a long quiet spell can take up to a minute.

## Privacy

The extension sends the address of each page you visit to the PhishGuard server and, for suspicious sites, to VirusTotal. It does not read page contents, form entries, passwords or cookies. See [PRIVACY.md](PRIVACY.md) for the full policy.

The extension asks for one permission, `tabs`, which it uses to read the address of the page being loaded and to update the toolbar badge.

## Project layout

```
PhishGuard/
├── app.py                # Flask API (POST /predict, GET / health check)
├── feature_extractor.py  # URL and page feature extraction
├── train_model.py        # trains and saves the models
├── download_datasets.py  # fetches the training data
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

```bash
python download_datasets.py
python train_model.py
```

This rebuilds `phishing_model.pkl`. The API checks the model's feature list when it starts, so if you change `feature_extractor.py` you must retrain.

## Deployment

The API is deployed on Render with:

```
gunicorn app:app --workers 1 --threads 4 --timeout 60
```

and the environment variable `VT_API_KEY`. By default it only accepts browser requests from extensions. To allow other origins, set `ALLOWED_ORIGINS` to a comma-separated list.

<!-- Add your model results here, for example accuracy, precision, recall and the dataset sizes from your thesis. -->

## Limitations

- PhishGuard reduces risk but cannot guarantee that a site is safe. Always check links carefully, especially in emails and messages.
- It judges addresses and page structure. It cannot catch every new or targeted phishing page, and it can occasionally flag a legitimate site.
- Page analysis depends on the server being able to fetch the page. If it cannot, the API falls back to the address-only model.
- Local, private-network and IP-literal addresses are deliberately not scanned.

## Author

Adejinmi Dan Toluwase

## Licence

See [LICENSE](LICENSE).
