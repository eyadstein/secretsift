"""Corpus builder: real code from your own site-packages + planted secrets and hard negatives.

Real code supplies realistic FALSE-POSITIVE pressure (all real lines are treated as clean).
Secrets are SYNTHETIC (random values in real provider formats) planted into real files.
Files are partitioned by hash so train / val / test / bench never share a file.
Some provider formats are held out of training ("unseen") to measure generalisation.
"""
from __future__ import annotations
import os, random, string, sysconfig, uuid, zlib, hashlib, base64
from pathlib import Path
from .rules import extract

A62 = string.ascii_letters + string.digits
SECRET_NAMES = ["API_KEY", "api_key", "secret", "SECRET_KEY", "auth_token", "access_token", "password", "DB_PASSWORD",
                "client_secret", "private_token", "AWS_SECRET_ACCESS_KEY", "stripe_key", "bearer_token", "passwd", "credentials"]
NEUTRAL_NAMES = ["data", "value", "x", "payload", "config_value", "s", "item", "blob", "token_value", "header"]
HASH_NAMES = ["sha256", "checksum", "commit_hash", "digest", "file_hash", "etag", "request_id", "session_uuid", "fingerprint", "md5sum", "password_hash", "api_key_hash", "token_digest", "secret_sha256"]
CTX = ['{n} = "{v}"', '{n}: "{v}"', "{n} = '{v}'", 'headers = {{"Authorization": "Bearer {v}", "x": 1}}',
       'client = Client({n}="{v}")', 'os.environ.setdefault("{n}", "{v}")', "# {n}: {v}", 'cfg["{n}"] = "{v}"',
       "export {n}={v}", '{n} = os.getenv("{n}", "{v}")']


def _r(r, alphabet, k): return "".join(r.choices(alphabet, k=k))


SEEN = {
    "aws": lambda r: r.choice(["AKIA", "ASIA"]) + _r(r, string.ascii_uppercase + "234567", 16),
    "aws_secret": lambda r: _r(r, A62 + "+/", 40),
    "github": lambda r: "ghp_" + _r(r, A62, 36),
    "gitlab": lambda r: "glpat-" + _r(r, A62 + "_-", 20),
    "slack": lambda r: "xoxb-" + _r(r, string.digits, 12) + "-" + _r(r, string.digits, 13) + "-" + _r(r, A62, 24),
    "stripe": lambda r: r.choice(["sk_live_", "sk_test_", "rk_live_"]) + _r(r, A62, r.choice([24, 32])),
    "google": lambda r: "AIza" + _r(r, A62 + "_-", 35),
    "openai": lambda r: r.choice(["sk-", "sk-proj-"]) + _r(r, A62 + "_-", r.choice([48, 64])),
    "jwt": lambda r: "eyJ" + _r(r, A62 + "_-", r.randint(15, 30)) + ".eyJ" + _r(r, A62 + "_-", r.randint(30, 80)) + "." + _r(r, A62 + "_-", 43),
    "password": lambda r: _r(r, A62 + "!@#$%^&*_-", r.randint(10, 24)),
    "human_pw": lambda r: r.choice(["Summer", "Dragon", "Welcome", "Admin", "Monkey", "Winter"]) + str(r.randint(10, 9999)) + r.choice("!@#$"),
    "hex_key": lambda r: _r(r, "0123456789abcdef", r.choice([32, 40, 64])),
    "dburl": lambda r: "postgres://" + r.choice(["admin", "app", "root"]) + ":" + _r(r, A62, 14) + "@db" + str(r.randint(1, 9)) + ".internal:5432/prod",
}
UNSEEN = {
    "sendgrid": lambda r: "SG." + _r(r, A62 + "_-", 22) + "." + _r(r, A62 + "_-", 43),
    "npm": lambda r: "npm_" + _r(r, A62, 36),
    "shopify": lambda r: "shpat_" + _r(r, "0123456789abcdef", 32),
    "twilio": lambda r: "SK" + _r(r, "0123456789abcdef", 32),
    "digitalocean": lambda r: "dop_v1_" + _r(r, "0123456789abcdef", 64),
}
NEEDS_SECRET_NAME = {"password", "human_pw", "dburl", "aws_secret", "hex_key"}


def _neg_value(r):
    k = r.randrange(11)
    if k == 0: return hashlib.sha256(os.urandom(8)).hexdigest(), "hash"
    if k == 1: return hashlib.md5(os.urandom(8)).hexdigest(), "hash"
    if k == 2: return hashlib.sha1(os.urandom(8)).hexdigest(), "hash"
    if k == 3: return str(uuid.UUID(int=r.getrandbits(128))), "hash"
    if k == 4: return base64.b64encode(bytes(r.getrandbits(8) for _ in range(r.randint(30, 80)))).decode(), "blob"
    if k == 5: return r.choice(["your_api_key_here", "AKIA" + "IOSFODNN7EXAMPLE", "changeme", "<YOUR_TOKEN>", "${API_KEY}", "REPLACE_ME_WITH_SECRET", "xxxxxxxxxxxxxxxxxxxx"]), "placeholder"
    if k == 6: return "ghp_" + "x" * 36, "placeholder"
    if k == 7: return "sk-" + "a" * 48, "placeholder"
    if k == 8: return "test-token-" + str(r.randint(1000, 9999)), "placeholder"
    if k == 9: return "$2b$12$" + _r(r, A62 + "./", 53), "pwhash"
    return "UA-" + str(r.randint(10**7, 10**8)) + "-1", "id"


def partition(path: str) -> str:
    h = zlib.crc32(path.encode()) % 100
    return "train" if h < 60 else "val" if h < 75 else "test" if h < 85 else "bench"


def real_files(limit: int, seed: int, part: str) -> list:
    root = Path(sysconfig.get_paths()["purelib"])
    files = []
    for p in root.rglob("*.py"):
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if 1500 < sz < 120_000 and partition(str(p.relative_to(root))) == part:
            files.append(p)
    files.sort(); random.Random(seed).shuffle(files)
    return files[:limit]


def plant(lines: list, r: random.Random, n_pos: int, n_neg: int, providers: dict):
    """Insert planted lines; returns (new_lines, planted[{line, value, label, kind}])."""
    items = []
    for _ in range(n_pos):
        kind = r.choice(list(providers))
        v = providers[kind](r)
        name = r.choice(SECRET_NAMES) if (kind in NEEDS_SECRET_NAME or r.random() < 0.7) else r.choice(NEUTRAL_NAMES)
        items.append((v, 1, kind, name))
    for _ in range(n_neg):
        v, kind = _neg_value(r)
        name = r.choice(SECRET_NAMES) if (kind == "placeholder" or (kind in ("blob", "id", "pwhash") and r.random() < 0.3)) else r.choice(HASH_NAMES + NEUTRAL_NAMES)
        items.append((v, 0, kind, name))
    r.shuffle(items)
    out, planted = list(lines), []
    for v, label, kind, name in items:
        tpl = r.choice(CTX)
        text = tpl.format(n=name, v=v)
        pos = r.randint(0, len(out))
        out.insert(pos, text)
        planted.append({"value": v, "label": label, "kind": kind, "text": text})
    # recompute final line numbers (insertions shift earlier ones)
    for p in planted:
        p["line"] = out.index(p["text"]) + 1
    return out, planted


def synth_config_files(n: int, r: random.Random, providers: dict) -> list:
    """Synthetic .env/.yml/.json style files: list of (relpath, text, planted)."""
    res = []
    for i in range(n):
        ext = r.choice([".env", ".yml", ".json", ".properties"])
        base = {".env": ["APP_ENV=production", "PORT=8080", "DEBUG=false"], ".yml": ["version: 3", "services:", "  web:", "    image: app:latest"],
                ".json": ['{"name": "app", "version": "1.0.0"}'], ".properties": ["server.port=8080", "app.name=demo"]}[ext]
        lines, planted = plant(base, r, r.randint(1, 3), r.randint(1, 3), providers)
        if ext == ".json":
            lines = ["{"] + [f'  "{p["text"].split("=")[0].split(":")[0].strip("# ")}": "{p["value"]}",' for p in planted] + ['  "k": 1', "}"]
            planted = [dict(p, line=idx + 2, text=lines[idx + 1]) for idx, p in enumerate(planted)]
        res.append((f"config/service{i}{ext}", "\n".join(lines) + "\n", planted))
    return res


def build_rows(part: str, n_files: int, seed: int, providers: dict, n_cfg: int = 0):
    """Return list of dict rows: candidate, path, label, group, kind."""
    r = random.Random(seed)
    root = Path(sysconfig.get_paths()["purelib"])
    rows, docs = [], []
    for p in real_files(n_files, seed, part):
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        new, planted = plant(lines, r, 3, 3, providers)
        docs.append((str(p.relative_to(root)), "\n".join(new) + "\n", planted))
    docs += synth_config_files(n_cfg, r, providers)
    for path, text, planted in docs:
        by_line = {q["line"]: q for q in planted}
        for c in extract(text):
            q = by_line.get(c.line_no)
            if q is not None and c.value not in q["value"]:
                q = None          # candidate is part of the planted line only if it is a piece of the planted value
            rows.append({"cand": c, "path": path, "label": int(q["label"]) if q else 0, "group": path,
                         "kind": q["kind"] if q else "real-code"})
    return rows, docs
