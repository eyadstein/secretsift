from __future__ import annotations
import json


def to_text(fs: list) -> str:
    if not fs:
        return "No secrets found."
    lines = [f"{len(fs)} potential secret(s):"]
    for f in fs:
        lines.append(f"  {f.file}:{f.line}  [{f.rule}] score={f.score}  {f.preview}\n      why: {'; '.join(f.why)}")
    return "\n".join(lines)


def to_json(fs: list) -> str:
    return json.dumps([f.to_dict() for f in fs], indent=2)


def to_sarif(fs: list) -> str:
    rules = {f.rule: {"id": f.rule, "shortDescription": {"text": f"Possible hard-coded secret ({f.rule})"}} for f in fs}
    results = [{"ruleId": f.rule, "level": "error", "message": {"text": f"Possible secret {f.preview}. {'; '.join(f.why)}"},
                "partialFingerprints": {"secretsift/v1": f.fingerprint},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": max(f.line, 1)}}}]} for f in fs]
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "SecretSift", "rules": list(rules.values())}}, "results": results}]}, indent=2)
