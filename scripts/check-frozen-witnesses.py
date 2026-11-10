#!/usr/bin/env python3
"""Compare archived synthetic witnesses with a pinned-base native executable.

The old v8 exact oracle has superseded semantics (including entropy/PII rules).
This gate checks no new loss of secret removal and current output stability;
all annotated secret values must be removed; exact historical formatting is not canonical.
"""
import json
import pathlib
import random
import re
import string
import subprocess
import sys

corpus = json.loads(pathlib.Path('vendor/corpus/scrub-secret-corpus.json').read_text())
rng = random.Random(24301)
charsets = {
    'alnum': string.ascii_letters + string.digits,
    'upper_alnum': string.ascii_uppercase + string.digits,
    'letters': string.ascii_letters, 'digits': string.digits,
    'hex': '0123456789abcdef', 'urlsafe': string.ascii_letters + string.digits + '_-',
    'b64': string.ascii_letters + string.digits + '+/',
}
values = {}
for name, generator in corpus['generators'].items():
    value = generator.get('prefix', '')
    for kind, count in generator['parts']:
        if kind == 'lit':
            value += count
        elif kind == 'uuid':
            value += '12345678-1234-4234-8234-123456789abc'
        else:
            value += ''.join(rng.choice(charsets[kind]) for _ in range(count))
    values[name] = value

def fill(text):
    return re.sub(r'\{\{([^}]+)\}\}', lambda m: values[m[1]], text)

def scrub(binary, texts):
    result = subprocess.run([binary], input=json.dumps(texts), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)

inputs = [fill(case['input']) for case in corpus['cases']]
base = scrub(sys.argv[1], inputs)
head = scrub(sys.argv[2], inputs)
base_misses, head_misses, regressions = set(), set(), set()
for case, old, new in zip(corpus['cases'], base, head):
    expected = fill(case['expected'])
    wanted = {name for name in re.findall(r'\{\{([^}]+)\}\}', case['input'])
              if name in corpus['secrets'] and values[name] not in expected}
    for name in wanted:
        if values[name] in old:
            base_misses.add(case['id'])
        if values[name] in new:
            head_misses.add(case['id'])
        if values[name] not in old and values[name] in new:
            regressions.add(case['id'])
twice = scrub(sys.argv[2], head)
result = {
    'cases': len(inputs),
    'baseExactArchivedOracle': sum(out == fill(case['expected']) for case, out in zip(corpus['cases'], base)),
    'headExactArchivedOracle': sum(out == fill(case['expected']) for case, out in zip(corpus['cases'], head)),
    'baseMissedSecretCases': len(base_misses), 'headMissedSecretCases': len(head_misses),
    'newMissedSecretCases': len(regressions),
    'inheritedArchivedDifferences': sorted(head_misses),
    'secondPassChangedCases': sum(a != b for a, b in zip(head, twice)),
    'scope': 'Historical v8 oracle has superseded semantics; this checks no new loss of secret removal and current idempotence.',
}
if len(sys.argv) > 3:
    vector_path = pathlib.Path(sys.argv[3])
    vectors = json.loads(vector_path.read_text())
    vectors['frozen'] = [{'input': text, 'output': output} for text, output in zip(inputs, head)]
    vector_path.write_text(json.dumps(vectors))
print(json.dumps(result, sort_keys=True))
sys.exit(bool(head_misses or regressions or result['secondPassChangedCases']))
