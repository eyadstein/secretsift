"""Train and compare three model families. Run: python -m secretsift.train"""
from __future__ import annotations
import argparse, json, time, warnings
from pathlib import Path
import joblib, numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from . import data
from .features import featurize, preprocessor

warnings.filterwarnings("ignore")
ART = Path(__file__).resolve().parents[1] / "artifacts"


def frame(rows):
    df = featurize([r["cand"] for r in rows], [r["path"] for r in rows])
    return df, np.array([r["label"] for r in rows])


def make(name):
    if name == "logreg":
        clf = LogisticRegression(C=2.0, max_iter=3000, class_weight="balanced")
    elif name == "hist_gbm":
        clf = HistGradientBoostingClassifier(max_depth=6, learning_rate=0.08, max_iter=200, random_state=7)
    else:
        clf = MLPClassifier(hidden_layer_sizes=(64, 32), alpha=1e-3, early_stopping=True, max_iter=120, random_state=7)
    return Pipeline([("prep", preprocessor()), ("clf", clf)])


def metrics(y, p, thr):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": float(precision_score(y, pred, zero_division=0)), "recall": float(recall_score(y, pred)),
            "f1": float(f1_score(y, pred)), "roc_auc": float(roc_auc_score(y, p)), "pr_auc": float(average_precision_score(y, p)),
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def best_threshold(y, p):
    best = (-1, 0.5)
    for t in np.linspace(0.05, 0.95, 91):
        f = f1_score(y, (p >= t).astype(int))
        if f > best[0]:
            best = (f, float(t))
    return best[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-files", type=int, default=260)
    ap.add_argument("--eval-files", type=int, default=90)
    a = ap.parse_args()
    ART.mkdir(exist_ok=True)
    t0 = time.time()
    tr_rows, _ = data.build_rows("train", a.train_files, 11, data.SEEN, n_cfg=120)
    va_rows, _ = data.build_rows("val", a.eval_files, 12, data.SEEN, n_cfg=40)
    te_rows, _ = data.build_rows("test", a.eval_files, 13, data.SEEN, n_cfg=40)
    un_rows, _ = data.build_rows("test", a.eval_files, 14, data.UNSEEN, n_cfg=40)
    (Xtr, ytr), (Xva, yva), (Xte, yte), (Xun, yun) = map(frame, (tr_rows, va_rows, te_rows, un_rows))
    rng = np.random.default_rng(7)
    drop = rng.random(len(Xtr)) < 0.3          # provider-dropout: stop the model leaning on the prefix match alone
    Xtr.loc[drop, "is_provider"] = 0
    print(f"[data] train={len(ytr)} (pos {ytr.sum()}) val={len(yva)} test={len(yte)} unseen-test={len(yun)}  files are hash-partitioned (no overlap)")
    results, fitted = {}, {}
    for name in ("logreg", "hist_gbm", "mlp"):
        t1 = time.time()
        m = make(name).fit(Xtr, ytr)
        thr = best_threshold(yva, m.predict_proba(Xva)[:, 1])
        r = {"threshold": thr, "val_pr_auc": float(average_precision_score(yva, m.predict_proba(Xva)[:, 1])),
             "test_seen": metrics(yte, m.predict_proba(Xte)[:, 1], thr), "test_unseen_formats": metrics(yun, m.predict_proba(Xun)[:, 1], thr),
             "fit_seconds": round(time.time() - t1, 1)}
        results[name], fitted[name] = r, m
        print(f"[{name}] val PR-AUC={r['val_pr_auc']:.3f} | test F1={r['test_seen']['f1']:.3f} P={r['test_seen']['precision']:.3f} R={r['test_seen']['recall']:.3f} | unseen-format F1={r['test_unseen_formats']['f1']:.3f} thr={thr:.2f}")
    sel = max(results, key=lambda k: results[k]["val_pr_auc"])
    joblib.dump(fitted[sel], ART / "model.joblib")
    (ART / "threshold.json").write_text(json.dumps({"threshold": results[sel]["threshold"]}))
    (ART / "metrics.json").write_text(json.dumps({"selected": sel, "models": results, "n_train": int(len(ytr)),
        "note": "Secrets are synthetic; negatives are real code from site-packages."}, indent=2))
    with open(ART / "experiments.jsonl", "a") as f:
        f.write(json.dumps({"ts": time.time(), "selected": sel, "results": results}) + "\n")
    print(f"[done] selected={sel} in {time.time() - t0:.0f}s -> {ART}")


if __name__ == "__main__":
    main()
