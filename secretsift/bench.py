"""Reproducible benchmark. Real code = clean (false-positive pressure); secrets are synthetic and planted.
Half the planted formats are NEVER seen in training. Scanners are scored per (file, line)."""
from __future__ import annotations
import json, random, shutil, time
from pathlib import Path
from . import data
from .scanner import scan_path

ALL = {**data.SEEN, **data.UNSEEN}


def build(out: str = "bench_corpus", n_files: int = 120, n_cfg: int = 60, seed: int = 2026) -> dict:
    out_p = Path(out)
    if out_p.exists():
        shutil.rmtree(out_p)
    out_p.mkdir(parents=True)
    _, docs = data.build_rows("bench", n_files, seed, ALL, n_cfg=n_cfg)
    truth, loc = {}, 0
    for rel, text, planted in docs:
        dest = out_p / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
        except OSError:
            continue          # e.g. Windows path too long: skip the file (and its truth entry)
        loc += text.count("\n")
        truth[rel.replace("\\", "/")] = [{"line": q["line"], "label": q["label"], "kind": q["kind"], "unseen": q["kind"] in data.UNSEEN} for q in planted]
    (out_p / "truth.json").write_text(json.dumps({"loc": loc, "files": truth}))
    return {"files": len(docs), "loc": loc}


def _detect_secrets(root: Path):
    from detect_secrets import SecretsCollection
    from detect_secrets.settings import default_settings
    hits = set()
    with default_settings():
        sc = SecretsCollection()
        for p in root.rglob("*"):
            if p.is_file() and p.name != "truth.json":
                sc.scan_file(str(p))
        for fname, secrets in sc.data.items():
            for s in secrets:
                hits.add((Path(fname).resolve().relative_to(root.resolve()).as_posix(), s.line_number))
    return hits


def _ours(root: Path, mode: str):
    return {(f.file.replace("\\", "/"), f.line) for f in scan_path(str(root), mode)}


def score(hits: set, truth: dict) -> dict:
    pos = {(f, q["line"]) for f, qs in truth["files"].items() for q in qs if q["label"] == 1}
    unseen = {(f, q["line"]) for f, qs in truth["files"].items() for q in qs if q["label"] == 1 and q["unseen"]}
    neg_planted = {(f, q["line"]) for f, qs in truth["files"].items() for q in qs if q["label"] == 0}
    hits = {h for h in hits if h[0] != "truth.json"}
    tp = len(hits & pos); fp = len(hits - pos); fn = len(pos - hits)
    fp_planted = len(hits & neg_planted); fp_real = fp - fp_planted
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / len(pos) if pos else 0.0
    return {"precision": prec, "recall": rec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "recall_unseen_formats": len(hits & unseen) / len(unseen) if unseen else 0.0,
            "false_alerts_on_real_code_per_100k_loc": round(fp_real / max(truth["loc"], 1) * 100_000, 1),
            "false_alerts_on_planted_decoys": fp_planted, "tp": tp, "fp": fp, "fn": fn}


def run(out: str = "bench_corpus") -> dict:
    root = Path(out)
    truth = json.loads((root / "truth.json").read_text())
    res = {}
    for name, fn in (("pattern-rules-only", lambda: _ours(root, "rules")), ("rules+entropy (no ML)", lambda: _ours(root, "entropy")),
                     ("SecretSift (ML filter)", lambda: _ours(root, "ml")), ("detect-secrets (default)", lambda: _detect_secrets(root))):
        t = time.time()
        try:
            hits = fn()
        except Exception as e:
            res[name] = {"error": f"{type(e).__name__}: {e}"}
            continue
        res[name] = score(hits, truth)
        res[name]["seconds"] = round(time.time() - t, 1)
    res["_meta"] = {"loc": truth["loc"], "planted_positives": sum(1 for qs in truth["files"].values() for q in qs if q["label"] == 1)}
    (root.parent / "artifacts").mkdir(exist_ok=True)
    Path("artifacts/bench.json").write_text(json.dumps(res, indent=2))
    return res


def to_markdown(res: dict) -> str:
    rows = ["| Scanner | Precision | Recall | F1 | Recall on unseen formats | False alerts / 100k LOC (real code) | Decoys flagged |", "|---|---|---|---|---|---|---|"]
    for k, v in res.items():
        if k.startswith("_"):
            continue
        if "error" in v:
            rows.append(f"| {k} | error: {v['error']} | | | | | |")
            continue
        rows.append(f"| {k} | {v['precision']:.3f} | {v['recall']:.3f} | {v['f1']:.3f} | {v['recall_unseen_formats']:.3f} | {v['false_alerts_on_real_code_per_100k_loc']} | {v['false_alerts_on_planted_decoys']} |")
    return "\n".join(rows)
