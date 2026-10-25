"""Pattern rules, entropy and candidate extraction."""
from __future__ import annotations
import math, re
from dataclasses import dataclass

PROVIDERS = [
    ("aws-access-key-id", r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    ("gitlab-pat", r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
    ("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,72}\b"),
    ("stripe-key", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,99}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("openai-style-key", r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_\-]{32,}\b"),
    ("ethereum-private-key", r"\b(?:0x)?[0-9a-fA-F]{64}\b"),
    ("solana-private-key", r"\b[1-9A-HJ-NP-Za-km-z]{87,88}\b"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("db-url-password", r"\b[a-z][a-z0-9+.\-]*://[^\s:/@\"']+:([^\s@\"']{4,})@[^\s/\"']+"),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")
_PROV = [(n, re.compile(r)) for n, r in PROVIDERS]
_ASSIGN = re.compile(r"""["']?(?P<name>[A-Za-z_][\w.\-]{1,60})["']?\s*(?:=>|:=|=|:)\s*["']?(?P<val>[^\s"',;)\]}]{8,200})["']?""")
_QUOTED = re.compile(r"""["'](?P<val>[A-Za-z0-9+/=_\-.]{20,200})["']""")
SECRETISH = re.compile(r"(key|secret|token|passw|pwd|auth|cred|api|private|bearer|signature)", re.I)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


@dataclass
class Candidate:
    value: str
    line_no: int
    line: str
    kind: str          # provider | assign | entropy
    provider: str = ""
    name: str = ""


def extract(text: str) -> list:
    out, seen = [], set()
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 600 or "secretsift: ignore" in line:
            continue
        for pname, rx in _PROV:
            for m in rx.finditer(line):
                val = m.group(1) if m.groups() else m.group(0)
                if (i, val) not in seen:
                    seen.add((i, val)); out.append(Candidate(val, i, line, "provider", pname))
        for m in _ASSIGN.finditer(line):
            name, val = m.group("name"), m.group("val")
            if SECRETISH.search(name) and (i, val) not in seen and not val.startswith(("http://", "https://")):
                seen.add((i, val)); out.append(Candidate(val, i, line, "assign", "", name))
        for m in _QUOTED.finditer(line):
            val = m.group("val")
            if (i, val) not in seen and entropy(val) >= 3.4 and not val.startswith(("http", "/", ".")):
                seen.add((i, val)); out.append(Candidate(val, i, line, "entropy"))
    return out
