#!/usr/bin/env python3
"""Collect fixed real benign sources privately; never print their contents.

The source-level dev/held-out split is fixed before downloading/inspection.
Public-domain literature tests prose; Git manuals test authentic technical text.
These do not substitute for labelled production-session precision evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import urllib.request

root = Path.home() / "scrubber-eval"
root.mkdir(mode=0o700, exist_ok=True)
root.chmod(0o700)
revision = "c44beea485f0f2feaf460e2ac87fdd5608d63cf0"
sources = [
    ("dev", "technical", f"https://raw.githubusercontent.com/git/git/{revision}/Documentation/git-log.adoc"),
    ("dev", "technical", f"https://raw.githubusercontent.com/git/git/{revision}/Documentation/git-commit.adoc"),
    ("dev", "prose", "https://www.gutenberg.org/ebooks/1342.txt.utf-8"),
    ("heldout", "technical", f"https://raw.githubusercontent.com/git/git/{revision}/Documentation/git-show.adoc"),
    ("heldout", "technical", f"https://raw.githubusercontent.com/git/git/{revision}/Documentation/git-grep.adoc"),
    ("heldout", "prose", "https://www.gutenberg.org/ebooks/161.txt.utf-8"),
]
manifest = {"created": "2026-11-10", "deleteBy": "2026-11-17", "sources": []}
for i, (split, kind, url) in enumerate(sources):
    data = urllib.request.urlopen(url, timeout=30).read()
    path = root / f"public-{split}-{i}.txt"
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
    path.chmod(0o600)
    manifest["sources"].append({"split": split, "class": kind, "path": str(path), "url": url,
                                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
path = root / "public-split.json"
with os.fdopen(os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600), "w") as file:
    json.dump(manifest, file)
print(json.dumps({"sources": len(sources), "bytes": sum(s["bytes"] for s in manifest["sources"])}))
