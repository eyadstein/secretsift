from __future__ import annotations
from fastapi import FastAPI
from pydantic import BaseModel, Field
from . import __version__, model as M
from .scanner import scan_text

app = FastAPI(title="SecretSift API", version=__version__)


class ScanIn(BaseModel):
    filename: str = Field("snippet.py", max_length=200)
    content: str = Field(..., max_length=500_000)
    mode: str = Field("ml", pattern="^(ml|entropy|rules)$")


class FindingOut(BaseModel):
    file: str; line: int; kind: str; rule: str; score: float; preview: str; why: list[str]; fingerprint: str


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__, "ml_model_loaded": M.available()}


@app.post("/scan", response_model=list[FindingOut])
def scan(body: ScanIn):
    return [f.to_dict() for f in scan_text(body.filename, body.content, body.mode)]
