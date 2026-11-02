# PhishGuard

PhishGuard is a browser extension that checks the website you're on and tells you if it looks like phishing. It was built as a final-year Computer Science project.

When you click the extension, it sends the page's URL to a small local Flask API. The API combines three signals into one verdict:

1. **Machine learning:** a calibrated Random Forest. It uses URL features alone, or URL plus page content when the page can be loaded.
2. **Heuristic rules:** checks for things like raw IP addresses, `@` in the address, look-alike (punycode) domains, brand impersonation, password forms that submit to another domain, and suspicious URL patterns.
3. **VirusTotal (optional):** a lookup that only runs when the first two signals look suspicious.

The popup then shows one of three results: **Safe**, **Suspicious**, or **Phishing detected**, along with the reasons. If the page can't be loaded, it says the scan was inconclusive instead of claiming the site is safe.

## Project layout

```
PhishGuard/
├── app.py                  # Flask API (the /predict endpoint)
├── feature_extractor.py    # URL and page feature extraction
├── train_model.py          # Trains and saves the models
├── download_datasets.py    # Downloads the training data
├── phishing_model.pkl      # Trained models (compressed)
├── requirements.txt
└── extension/              # The browser extension
    ├── manifest.json
    ├── popup.html / popup.js / styles.css
    ├── background.js
    └── icons/
```

## Setup

### 1. Start the backend

```bash
git clone https://github.com/<your-username>/phishguard.git
cd phishguard

python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

The API runs at `http://127.0.0.1:5000`. Opening that address in a browser should show a short status message.

### 2. Load the extension

1. Open `chrome://extensions` (or `brave://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select the `extension` folder.
4. Open any website and click the PhishGuard icon.

The backend must be running while you use the extension.

### 3. VirusTotal (optional)

PhishGuard works without VirusTotal. To turn it on, get a free API key from virustotal.com and set it before starting the backend:

```powershell
# Windows (PowerShell)
$env:VT_API_KEY="your_key_here"
python app.py
```

```bash
# macOS / Linux
export VT_API_KEY="your_key_here"
python app.py
```

The key is read from the environment and is never stored in the code.

## Retraining the model

The repository includes a trained model, so this is only needed if you want to train your own:

```bash
python download_datasets.py
python train_model.py
```

The training data combines the PhiUSIIL dataset with OpenPhish URLs (about 236,000 URLs in total). The dataset file is not included in this repository because of its size.

## Known limitations

- **It's a research project, not a security product.** Don't rely on it as your only protection.
- **New or unusual phishing URLs can be missed.** The training data is very easy to separate, which is why test scores look almost perfect. Real-world accuracy on unseen phishing sites will be lower.
- **Pages that can't be loaded** (for example, takedowns or dead domains) are judged on the URL alone. Those scans are marked "Inconclusive" rather than "Safe".
- **Popular sites** on a built-in trusted list skip the page scan.
- **The backend only listens on your own computer** (`127.0.0.1`) and refuses to scan local or private network addresses.

## Tech stack

Python, Flask, scikit-learn (Random Forest), BeautifulSoup, and a Manifest V3 browser extension in plain JavaScript.

## License

MIT (add a `LICENSE` file before publishing).
