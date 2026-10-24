"""One runner for everything: python manage.py [setup|train|bench|test|report|demo|serve|all|push URL]"""
import argparse, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
PY = sys.executable


def run(*cmd, check=True):
    cmd = [str(c) for c in cmd]
    print(">", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=ROOT, check=check)


def setup(no_venv):
    global PY
    if not no_venv:
        if not VENV.exists():
            run(sys.executable, "-m", "venv", VENV)
        PY = str(VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    run(PY, "-m", "pip", "install", "-q", "-U", "pip")
    run(PY, "-m", "pip", "install", "-q", "-r", "requirements.txt")
    run(PY, "-m", "pip", "install", "-q", "-e", ".")


def cmd_push(url):
    if not (ROOT / ".git").exists():
        run("git", "init")
    run("git", "add", "-A")
    run("git", "commit", "-m", "SecretSift: context-aware secret scanner with reproducible benchmark", check=False)
    run("git", "branch", "-M", "main")
    if subprocess.run(["git", "remote"], cwd=ROOT, capture_output=True, text=True).stdout.split().count("origin"):
        run("git", "remote", "set-url", "origin", url)
    else:
        run("git", "remote", "add", "origin", url)
    run("git", "push", "-u", "origin", "main")


def main():
    global PY
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["setup", "train", "bench", "test", "report", "demo", "serve", "all", "push"])
    ap.add_argument("url", nargs="?")
    ap.add_argument("--no-venv", action="store_true", help="use the current Python instead of creating .venv")
    a = ap.parse_args()
    if a.cmd in ("setup", "all"):
        setup(a.no_venv)
    elif not a.no_venv and (VENV / ("Scripts" if os.name == "nt" else "bin")).exists():
        PY = str(VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    if a.cmd in ("train", "all"):
        run(PY, "-m", "secretsift.train")
    if a.cmd in ("bench", "all"):
        run(PY, "-m", "secretsift", "bench", "build"); run(PY, "-m", "secretsift", "bench", "run")
    if a.cmd in ("test", "all"):
        run(PY, "-m", "pytest", "-q")
    if a.cmd in ("report", "all"):
        run(PY, "-m", "secretsift.docgen")
    if a.cmd in ("demo", "all"):
        d = Path(tempfile.mkdtemp(prefix="secretsift_demo_"))
        run(PY, "-c", f"from secretsift.demo import make; make(r'{d}')")
        run(PY, "-m", "secretsift", "scan", d, "--exit-zero")
    if a.cmd == "serve":
        run(PY, "-m", "uvicorn", "secretsift.api:app", "--port", "8000")
    if a.cmd == "push":
        if not a.url:
            sys.exit("usage: python manage.py push https://github.com/<you>/secretsift.git")
        cmd_push(a.url)


if __name__ == "__main__":
    main()
