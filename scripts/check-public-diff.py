#!/usr/bin/env python3
"""Conservative static credential-shape guard; never print matched values."""
import json
import re
import subprocess

diff = subprocess.check_output(["git", "diff", "--cached", "--no-ext-diff", "--unified=0"], text=True)
patterns = [
    re.compile(r"(?:sk-(?:proj-|ant-api\d+-)?|gh[pousr]_|github_pat_|glpat-|npm_|pypi-|cf(?:ut|at|k)_|vercel_)[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"xox[baprse]-[A-Za-z0-9-]{20,}"),
    re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
]
findings = []
path = ""
added = 0
for line in diff.splitlines():
    if line.startswith("+++ b/"):
        path = line[6:]
    if not line.startswith("+") or line.startswith("+++"):
        continue
    added += 1
    for pattern in patterns:
        for match in pattern.finditer(line):
            # These are explicit test sentinels, not an allowlist of fixture paths.
            if "SYNTH" not in match.group() and "[REDACTED]" not in match.group():
                findings.append({"path": path, "kind": "credential_shape"})
print(json.dumps({"added_lines_scanned": added, "unexplained_credential_shapes": len(findings), "findings": findings}))
raise SystemExit(bool(findings))
