"""
train_model.py v5.0

Trains TWO calibrated Random Forests and saves them in one file:
  url_model   - URL features only (used when the page can't be downloaded)
  full_model  - URL features + page features (used when the page was inspected)

Usage:
    python train_model.py                              # dataset.csv (PhiUSIIL) only
    python train_model.py dataset.csv urls_extra.csv   # + extra URLs (url_model only)

Label fact: in PhiUSIIL, label 1 = LEGITIMATE and 0 = PHISHING. Everything below converts
to 1 = PHISHING, which is what app.py expects.

Two dataset artifacts are handled here (both caused false alarms on real sites):
  1. Every legit URL in PhiUSIIL is "www.<site>", so ANY other subdomain (auth., mail.,
     portal., accounts.) looked like phishing. Fix: part of the legit training rows get a
     realistic subdomain added (their page features stay the same).
  2. Every legit page in PhiUSIIL is a rich homepage, so small plain pages (login pages,
     single-page apps) looked like phishing. Fix: app.py blends the page model with the URL
     model (PAGE_WEIGHT below) instead of trusting the page model alone.
"""
import re, sys, random
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import roc_auc_score, confusion_matrix, precision_score, recall_score
from feature_extractor import (url_features, registered_domain, URL_FEATURE_NAMES,
                               PAGE_FEATURE_NAMES, FULL_FEATURE_NAMES)

PAGE_WEIGHT = 0.35          # share of the page model in the final probability (rest = URL model)
AUG_FRACTION = 0.40         # share of legit training rows that get an extra subdomain
SUB_NEUTRAL = ["mail", "portal", "app", "blog", "docs", "support", "shop", "my", "online", "student",
                "learn", "news", "help", "dev", "api", "members", "careers", "store", "m", "events"]
SUB_LOGIN = ["auth", "accounts", "login", "secure", "sso", "id", "account", "signin", "myaccount"]


def add_subdomain(url, rng):
    sub = rng.choice(SUB_LOGIN) if rng.random() < 0.25 else rng.choice(SUB_NEUTRAL)
    if rng.random() < 0.15:
        sub = rng.choice(SUB_NEUTRAL) + "." + sub
    return re.sub(r"^(https?://)(www\.)?", rf"\g<1>{sub}.", url, count=1)


def build_url_matrix(urls):
    return pd.DataFrame([[url_features(u)[n] for n in URL_FEATURE_NAMES] for u in urls],
                        columns=URL_FEATURE_NAMES)


def make_model():
    rf = RandomForestClassifier(n_estimators=150, max_depth=16, min_samples_leaf=3,
                                class_weight="balanced", random_state=42, n_jobs=-1)
    return CalibratedClassifierCV(rf, method="sigmoid", cv=3)


def report(name, p, y_te):
    pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
    p85 = (p >= 0.85)
    fp85 = (p85 & (y_te == 0)).sum() / (y_te == 0).sum()
    print(f"[{name}]  AUC {roc_auc_score(y_te, p):.4f} | precision {precision_score(y_te, pred):.4f} | "
          f"recall {recall_score(y_te, pred):.4f} | false alarms @0.5 {fp/(fp+tn):.4f}, @0.85 {fp85:.4f}")


def main(main_csv="dataset.csv", extra_csv=None, out="phishing_model.pkl"):
    df = pd.read_csv(main_csv)
    missing = [c for c in PAGE_FEATURE_NAMES + ["URL", "label"] if c not in df.columns]
    if missing:
        sys.exit(f"{main_csv} is missing columns: {missing}  (expected the PhiUSIIL file)")
    df = df.drop_duplicates("URL").reset_index(drop=True)
    df["y"] = 1 - df["label"].astype(int)                 # flip: 1 = phishing
    print(f"[INFO] PhiUSIIL: {len(df)} rows | phishing={int(df.y.sum())} legit={int((1-df.y).sum())}")

    print("[INFO] Computing URL features with the same code the API uses ...")
    X_url = build_url_matrix(df.URL)
    X_page = df[PAGE_FEATURE_NAMES].reset_index(drop=True)
    y = df["y"].to_numpy()
    groups = df.URL.map(registered_domain)                # same site never in train and test
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(X_url, y, groups))

    # --- subdomain augmentation (training rows only) ---
    rng = random.Random(7)
    legit_tr = [i for i in tr if y[i] == 0]
    aug_idx = rng.sample(legit_tr, int(AUG_FRACTION * len(legit_tr)))
    aug_urls = [add_subdomain(df.URL[i], rng) for i in aug_idx]
    X_url_aug = build_url_matrix(aug_urls)
    print(f"[INFO] Added {len(aug_idx)} legit training rows with a subdomain, e.g. {aug_urls[0]}")

    Xu_train = pd.concat([X_url.iloc[tr], X_url_aug], ignore_index=True)
    Xp_train = pd.concat([X_page.iloc[tr], X_page.iloc[aug_idx]], ignore_index=True)
    y_train = np.concatenate([y[tr], np.zeros(len(aug_idx), dtype=int)])
    Xf_train = pd.concat([Xu_train, Xp_train], axis=1)[FULL_FEATURE_NAMES]
    Xf_test = pd.concat([X_url.iloc[te].reset_index(drop=True), X_page.iloc[te].reset_index(drop=True)],
                        axis=1)[FULL_FEATURE_NAMES]

    full = make_model().fit(Xf_train, y_train)
    p_full = full.predict_proba(Xf_test)[:, 1]

    # url_model: + optional extra URLs (never from test domains)
    Xu_fit, y_fit = Xu_train, y_train
    if extra_csv:
        ex = pd.read_csv(extra_csv).dropna(subset=["url"]).drop_duplicates("url")
        ex = ex[~ex.url.map(registered_domain).isin(set(groups.iloc[te]))]
        print(f"[INFO] Extra URLs for url_model: {len(ex)} (phishing={int(ex.label.sum())})")
        Xu_fit = pd.concat([Xu_train, build_url_matrix(ex.url)], ignore_index=True)
        y_fit = np.concatenate([y_train, ex.label.astype(int).values])
    url_m = make_model().fit(Xu_fit, y_fit)
    p_url = url_m.predict_proba(X_url.iloc[te])[:, 1]

    print("\n=== held-out sites (never seen in training) ===")
    report("url model only    ", p_url, y[te])
    report("page model only   ", p_full, y[te])
    report(f"blend ({PAGE_WEIGHT:.2f} page)  ", (1 - PAGE_WEIGHT) * p_url + PAGE_WEIGHT * p_full, y[te])

    # stress test: the same held-out LEGIT sites, but with a subdomain (auth./mail./portal./...)
    leg = [i for i in te if y[i] == 0]
    srng = random.Random(99)
    sub_urls = [re.sub(r"^(https?://)(www\.)?", rf"\g<1>{srng.choice(['auth','mail','portal','accounts','app','my'])}.", df.URL[i], count=1)
                for i in leg[:4000]]
    ps = url_m.predict_proba(build_url_matrix(sub_urls))[:, 1]
    print(f"\nStress test, {len(sub_urls)} real legit sites with a subdomain added: "
          f"flagged >=0.5: {(ps >= 0.5).mean():.1%} | >=0.85: {(ps >= 0.85).mean():.1%}")

    joblib.dump({"url_model": url_m, "full_model": full, "url_features": URL_FEATURE_NAMES,
                 "full_features": FULL_FEATURE_NAMES, "positive_class": 1, "version": 5,
                 "page_weight": PAGE_WEIGHT}, out, compress=("xz", 3))
    print(f"\n[INFO] Saved -> {out}")


if __name__ == "__main__":
    main(*(sys.argv[1:3]))
