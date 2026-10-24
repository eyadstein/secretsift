from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import __version__, report
from .scanner import MODES, load_baseline, scan_path


def _scan(a) -> int:
    base = load_baseline(a.baseline)
    fs = []
    if a.history:
        from .history import scan_history
        for p in a.paths:
            fs += [f for f in scan_history(p, a.mode) if f.fingerprint not in base]
    else:
        for p in a.paths:
            fs += scan_path(p, a.mode, base, a.threshold)
    if a.write_baseline:
        Path(a.write_baseline).write_text(json.dumps(sorted({f.fingerprint for f in fs} | base)))
        print(f"baseline with {len(fs)} new finding(s) written to {a.write_baseline}")
        return 0
    body = {"text": report.to_text, "json": report.to_json, "sarif": report.to_sarif}[a.format](fs)
    if a.out:
        Path(a.out).write_text(body, encoding="utf-8"); print(f"wrote {a.out} ({len(fs)} finding(s))")
    else:
        sys.stdout.buffer.write((body + "\n").encode("utf-8"))
    return 0 if (a.exit_zero or not fs) else 1


def _bench(a) -> int:
    from . import bench
    if a.action == "build":
        print(bench.build(a.dir, a.files))
    else:
        print(bench.to_markdown(bench.run(a.dir)))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secretsift", description="Context-aware secret scanner")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan files, folders or git history")
    s.add_argument("paths", nargs="*", default=["."])
    s.add_argument("--mode", choices=MODES, default="ml")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--out"); s.add_argument("--history", action="store_true", help="scan secrets added anywhere in git history")
    s.add_argument("--baseline"); s.add_argument("--write-baseline"); s.add_argument("--threshold", type=float)
    s.add_argument("--exit-zero", action="store_true")
    s.set_defaults(fn=_scan)
    b = sub.add_parser("bench", help="build / run the reproducible benchmark")
    b.add_argument("action", choices=["build", "run"]); b.add_argument("--dir", default="bench_corpus"); b.add_argument("--files", type=int, default=120)
    b.set_defaults(fn=_bench)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
