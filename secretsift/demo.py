"""Writes a demo project with RUNTIME-generated fake secrets (nothing secret-like is ever committed)."""
from __future__ import annotations
import random
from pathlib import Path
from . import data


def make(dest: str) -> str:
    r, S = random.Random(42), data.SEEN
    d = Path(dest); d.mkdir(parents=True, exist_ok=True)
    (d / "settings.py").write_text(f'''import os
GITHUB_TOKEN = "{S["github"](r)}"
DATABASE_URL = "postgres://admin:{S["human_pw"](r).replace("!", "x")}ab@db.internal:5432/prod"
STRIPE_KEY = "{S["stripe"](r)}"
API_KEY = "your_api_key_here"
FILE_SHA256 = "{"".join(r.choices("0123456789abcdef", k=64))}"
REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"
''')
    (d / ".env").write_text(f"DEBUG=false\nAWS_SECRET_ACCESS_KEY={S['aws_secret'](r)}\nAWS_ACCESS_KEY_ID={S['aws'](r)}\n")
    return str(d)
