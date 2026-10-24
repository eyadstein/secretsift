"""Value + context features. The secret value is masked out of the context text."""
from __future__ import annotations
import re
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from .rules import entropy, SECRETISH

HASHISH = re.compile(r"(hash|digest|checksum|sha\d*|md5|commit|uuid|guid|etag|nonce|salt|crc|fingerprint|_id$|^id$)", re.I)
PLACEHOLDER = re.compile(r"(example|sample|dummy|placeholder|your[_\-]?|xxxx|changeme|fake|redacted|test|foo|bar|<.*>|\$\{|\{\{|todo|insert|replace|secret_here|1234)", re.I)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_B64 = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")
_PREFIX = re.compile(r"^[A-Za-z]{2,8}[_.\-](?:[a-z0-9]{1,4}[_.\-])?[A-Za-z0-9_\-.]{16,}$")
_NAME_FROM_LINE = re.compile(r"([A-Za-z_][\w.\-]{1,60})[\"']?\s*(?:=>|=|:|\()")
NUM_COLS = ["length", "entropy", "has_digit", "has_upper", "has_lower", "has_symbol", "digit_ratio", "upper_ratio",
            "unique_ratio", "is_hex", "hex_hash_len", "is_uuid", "is_b64", "is_provider", "placeholder", "repeat_ratio",
            "sequential", "name_secretish", "name_hashish", "in_test_path", "in_docs_path", "kind_assign", "kind_entropy",
            "line_is_comment", "bcrypt_like", "prefix_token"]


def _repeat_ratio(v):
    return max(v.count(c) for c in set(v)) / len(v) if v else 0.0


def _sequential(v):
    low = v.lower()
    return int(any(s in low for s in ("123456", "abcdef", "qwerty", "000000", "111111")))


def _name(c):
    if c.name:
        return c.name
    m = _NAME_FROM_LINE.search(c.line.replace(c.value, " "))
    return m.group(1) if m else ""


def featurize(cands: list, paths: list) -> pd.DataFrame:
    rows = []
    for c, p in zip(cands, paths):
        v, name, pl = c.value, _name(c), p.replace("\\", "/").lower()
        n = max(len(v), 1)
        rows.append({
            "length": len(v), "entropy": entropy(v),
            "has_digit": int(any(ch.isdigit() for ch in v)), "has_upper": int(any(ch.isupper() for ch in v)),
            "has_lower": int(any(ch.islower() for ch in v)), "has_symbol": int(any(not ch.isalnum() for ch in v)),
            "digit_ratio": sum(ch.isdigit() for ch in v) / n, "upper_ratio": sum(ch.isupper() for ch in v) / n,
            "unique_ratio": len(set(v)) / n, "is_hex": int(bool(_HEX.match(v))),
            "hex_hash_len": int(bool(_HEX.match(v)) and len(v) in (32, 40, 64)), "is_uuid": int(bool(_UUID.match(v))),
            "is_b64": int(bool(_B64.match(v))), "is_provider": int(c.kind == "provider"),
            "placeholder": int(bool(PLACEHOLDER.search(v))), "repeat_ratio": _repeat_ratio(v), "sequential": _sequential(v),
            "name_secretish": int(bool(SECRETISH.search(name)) or c.provider == "db-url-password"), "name_hashish": int(bool(HASHISH.search(name))),
            "in_test_path": int("test" in pl or "fixture" in pl), "in_docs_path": int("doc" in pl or "example" in pl or "sample" in pl),
            "kind_assign": int(c.kind == "assign"), "kind_entropy": int(c.kind == "entropy"),
            "line_is_comment": int(c.line.lstrip().startswith(("#", "//", "*", "/*"))),
            "bcrypt_like": int(v.startswith(("$2a$", "$2b$", "$2y$", "$argon2", "$pbkdf2"))),
            "prefix_token": int(bool(_PREFIX.match(v))),
            "ctx": (name + " " + c.line.replace(v, " VAL ")[:200]),
        })
    return pd.DataFrame(rows)


def preprocessor():
    return ColumnTransformer([
        ("num", StandardScaler(), NUM_COLS),
        ("ctx", TfidfVectorizer(token_pattern=r"[A-Za-z_]{2,}", ngram_range=(1, 2), min_df=2, max_features=2500, lowercase=True), "ctx"),
    ], sparse_threshold=0.0)


def reasons(row: dict) -> list:
    """Positive reasons only (this is shown for findings that were kept)."""
    r = []
    if row["is_provider"]: r.append("matches a known provider key format")
    if row["name_secretish"]: r.append("secret-like variable name or connection string")
    if row["entropy"] >= 4.0 and row["length"] >= 20: r.append(f"high-entropy value ({row['entropy']:.1f} bits/char)")
    if row["prefix_token"]: r.append("prefix + random token structure")
    if not (row["placeholder"] or row["is_uuid"] or row["bcrypt_like"] or row["hex_hash_len"] and not row["name_secretish"]):
        r.append("no placeholder, hash or UUID signals")
    return r or ["statistical context score"]
