from __future__ import annotations
import json
from pathlib import Path
import joblib

ART = Path(__file__).resolve().parents[1] / "artifacts"
_cache: dict = {}


def load():
    if "m" not in _cache:
        mp, tp = ART / "model.joblib", ART / "threshold.json"
        if mp.exists():
            _cache["m"] = (joblib.load(mp), float(json.loads(tp.read_text())["threshold"]) if tp.exists() else 0.5)
        else:
            _cache["m"] = (None, 0.5)
    return _cache["m"]


def available() -> bool:
    return load()[0] is not None
