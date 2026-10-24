import random, subprocess, shutil
import pytest
from fastapi.testclient import TestClient
from secretsift import data, model as M
from secretsift.api import app
from secretsift.rules import entropy, extract
from secretsift.scanner import scan_path, scan_text

R = random.Random(5)
GH = data.SEEN["github"](R)          # secrets are generated at runtime so no secret-like strings are committed
AWS = data.SEEN["aws"](R)
c = TestClient(app)


def test_entropy_ordering():
    assert entropy("aaaaaaaa") < entropy("a1B2c3D4e5F6")


def test_provider_candidate_found():
    kinds = {x.provider for x in extract(f'TOKEN = "{GH}"\n')}
    assert "github-token" in kinds


def test_rules_mode_finds_provider_key():
    fs = scan_text("a.py", f'x = "{AWS}"\n', "rules")
    assert fs and fs[0].rule == "aws-access-key-id"


def test_ignore_comment():
    assert not scan_text("a.py", f'x = "{GH}"  # secretsift: ignore\n', "rules")


def test_preview_is_redacted():
    f = scan_text("a.py", f'x = "{GH}"\n', "rules")[0]
    assert GH not in f.preview and f.preview.startswith("ghp_")


def test_private_key_header():
    assert scan_text("k.pem", "-----BEGIN RSA " + "PRIVATE KEY-----\nabc\n", "rules")


@pytest.mark.skipif(not M.available(), reason="model not trained yet")
def test_ml_vetoes_placeholder_and_hash():
    txt = 'api_key = "your_api_key_here"\nchecksum = "' + "ab12" * 16 + '"\nid = "' + "0123456789abcdef" * 2 + '"\n'
    assert not scan_text("a.py", txt, "ml")


@pytest.mark.skipif(not M.available(), reason="model not trained yet")
def test_ml_keeps_real_looking_secret():
    assert scan_text("settings.py", f'API_KEY = "{GH}"\n', "ml")


def test_baseline_suppresses(tmp_path):
    (tmp_path / "a.py").write_text(f'x = "{GH}"\n')
    fs = scan_path(str(tmp_path), "rules")
    assert fs and not scan_path(str(tmp_path), "rules", {f.fingerprint for f in fs})


@pytest.mark.skipif(shutil.which("git") is None, reason="git missing")
def test_history_finds_deleted_secret(tmp_path):
    from secretsift.history import scan_history
    run = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)
    run("init"); run("config", "user.email", "t@t"); run("config", "user.name", "t")
    (tmp_path / "a.py").write_text(f'x = "{GH}"\n'); run("add", "."); run("commit", "-m", "add")
    (tmp_path / "a.py").write_text("x = 1\n"); run("commit", "-am", "remove")
    assert scan_history(str(tmp_path), "rules")


def test_api_health_and_scan():
    assert c.get("/health").json()["status"] == "ok"
    r = c.post("/scan", json={"filename": "a.py", "content": f'k = "{GH}"', "mode": "rules"})
    assert r.status_code == 200 and r.json()[0]["rule"] == "github-token"
    assert c.post("/scan", json={"content": "x", "mode": "bad"}).status_code == 422
