from __future__ import annotations
import hashlib, json, os
from dataclasses import dataclass, asdict
from pathlib import Path
from . import model as M
from .features import featurize, reasons
from .rules import PRIVATE_KEY, extract

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".idea", ".vscode", "artifacts", "bench_corpus"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".whl", ".pyc", ".so", ".dll", ".exe", ".woff", ".woff2", ".ico", ".joblib", ".lock"}
MODES = ("ml", "entropy", "rules")


@dataclass
class Finding:
    file: str
    line: int
    kind: str
    rule: str
    score: float
    preview: str
    why: list
    fingerprint: str

    def to_dict(self):
        return asdict(self)


def redact(v: str) -> str:
    return (v[:4] + "…" + f"[{len(v)} chars]") if len(v) > 8 else "****"


def _fp(path, rule, value):
    return hashlib.sha256(f"{path}|{rule}|{value}".encode()).hexdigest()[:16]


def scan_text(path: str, text: str, mode: str = "ml", threshold: float | None = None) -> list:
    out = []
    if PRIVATE_KEY.search(text):
        for i, line in enumerate(text.splitlines(), 1):
            if PRIVATE_KEY.search(line):
                out.append(Finding(path, i, "provider", "private-key", 1.0, "-----BEGIN…", ["private key header"], _fp(path, "private-key", str(i))))
    cands = extract(text)
    if not cands:
        return out
    if mode == "rules":
        keep = [(c, 1.0, ["matches a known provider key format"]) for c in cands if c.kind == "provider"]
    elif mode == "entropy" or not M.available():
        keep = [(c, 1.0, ["pattern/entropy match (no ML filter)"]) for c in cands]
    else:
        model, thr = M.load()
        thr = thr if threshold is None else threshold
        df = featurize(cands, [path] * len(cands))
        probs = model.predict_proba(df)[:, 1]
        keep = [(c, float(p), reasons(df.iloc[i].to_dict())) for i, (c, p) in enumerate(zip(cands, probs)) if p >= thr]
    for c, p, why in keep:
        rule = c.provider or ("generic-assignment" if c.kind == "assign" else "high-entropy-string")
        out.append(Finding(path, c.line_no, c.kind, rule, round(p, 3), redact(c.value), why, _fp(path, rule, c.value)))
    return out


def iter_files(root: str):
    rp = Path(root)
    if rp.is_file():
        yield rp, rp.name
        return
    for dp, dns, fns in os.walk(rp):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = Path(dp) / fn
            if p.suffix.lower() in SKIP_EXT:
                continue
            try:
                if p.stat().st_size > 1_000_000:
                    continue
            except OSError:
                continue
            yield p, str(p.relative_to(rp))


def scan_path(root: str, mode: str = "ml", baseline: set | None = None, threshold: float | None = None) -> list:
    res = []
    for p, rel in iter_files(root):
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        res += scan_text(rel, text, mode, threshold)
    if baseline:
        res = [f for f in res if f.fingerprint not in baseline]
    return res


def load_baseline(path: str) -> set:
    return set(json.loads(Path(path).read_text())) if path and Path(path).exists() else set()
