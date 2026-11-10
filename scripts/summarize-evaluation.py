#!/usr/bin/env python3
"""Write public aggregate receipts only; never copy a private sample or path."""
import json
import platform
import shutil
from pathlib import Path

result_dir = Path('docs/results')
old = json.loads((result_dir / 'precision.json').read_text())
metrics = json.loads(Path('target/dev-metrics.json').read_text())
alternate = json.loads(Path('target/alternate-seed.json').read_text())
artifact = json.loads(Path('js/generated/artifact.json').read_text())
assert metrics['manifest'] == alternate['manifest'] == artifact['manifest']
public = {s: json.loads(Path(f'target/public-{s}.json').read_text()) for s in ['dev', 'heldout']}
split = json.loads((Path.home() / 'scrubber-eval/fresh-split.json').read_text())
if 'retired_evaluation' in old:
    retired = old['retired_evaluation']
else:
    retired = {'frozen_source_sha256': old['frozen_source_sha256'],
               'public_heldout': old['public_benign']['heldout'],
               'private_unlabelled_candidates': old['private_unlabelled_candidates'],
               'reason': 'Independent historical-shape audit expanded Google token spans and multilingual boundaries; these observations are not current unseen-data evidence.'}
additional=old.get('additional_retired_evaluations',[])
if old['frozen_source_sha256']!=artifact['manifest']['rulesetSourceSha256'] and not any(r['frozen_source_sha256']==old['frozen_source_sha256'] for r in additional):
    additional.append({'frozen_source_sha256':old['frozen_source_sha256'],'public_heldout':old['public_benign']['heldout'],'reason':'Independent grammar/quote-boundary audit changed the engine; retire its prior held-out set.'})
precision = {'frozen_source_sha256': artifact['manifest']['rulesetSourceSha256'],
             'public_benign': public,
             'public_sources': [{k: v for k, v in source.items() if k != 'path'} for source in split['sources']],
             'retired_evaluation': retired,
             'additional_retired_evaluations': additional,
             'host': platform.system() + ' ' + platform.machine(),
             'runtime_versions': {'rust': '1.88.0', 'node': '26.13.0', 'bun': '1.3.14', 'wrangler': '4.77.0'}}
for source, dest in [('target/dev-metrics.json', 'dev.json'), ('target/alternate-seed.json', 'alternate-seed.json'), ('js/generated/artifact.json', 'artifact.json')]:
    shutil.copyfile(source, result_dir / dest)
(result_dir / 'precision.json').write_text(json.dumps(precision, indent=2) + '\n')
complete = sum(v['complete'] for v in metrics['recall'].values())
cases = sum(v['cases'] for v in metrics['recall'].values())
lines = ['# Candidate evaluation results', '',
         f"Frozen rules source: `{artifact['manifest']['rulesetSourceSha256']}`.",
         f"Mac development WASM: `{artifact['files']['relayscrubber_bg.wasm']}` ({Path('js/generated/relayscrubber_bg.wasm').stat().st_size:,} bytes).", '',
         'Candidate 10 is not approved for adoption. Ruleset reservation and independent',
         'relayscrubber-lead exact-commit PASS are pending. Veto host-assisted review passed',
         'with warnings about production precision evidence and Workers build verification;',
         'it does not replace that independent review. No registry publish or deployment occurred.', '',
         '## Recall and synthetic precision', '',
         f"Seed 24301: **{complete:,}/{cases:,} complete secret-span coverage**, {len(metrics['recall'])} classes.",
         f"Alternate seed 987654321: {sum(v['complete'] for v in alternate['recall'].values()):,}/{sum(v['cases'] for v in alternate['recall'].values()):,}.",
         'Four-seed tests also pass full coverage/idempotence. Alternate seeds vary bodies;',
         'they are not held-out provider families. Historical-input audit added extended',
         'Google bodies and multilingual boundaries independently of held-out observations.', '',
         '| Secret class | Complete / cases | Recall | Excess removed bytes |',
         '| --- | ---: | ---: | ---: |']
for name, value in metrics['recall'].items():
    lines.append(f"| {name} | {value['complete']} / {value['cases']} | {value['recall']:.0%} | {value['excess_removed_bytes']} |")
lines += ['', f"Excess removed: {metrics['excess_removed_bytes']:,} bytes, from intentional whole headers and YAML block syntax.",
          'This measures removed syntax separately from annotated secret bytes. Malformed',
          'quoted credentials can require additional removal through the enclosing end.', '',
          '| Synthetic benign class | Cases | Bytes | Changed cases / MB |', '| --- | ---: | ---: | ---: |']
for name, value in metrics['benign'].items():
    lines.append(f"| {name} | {value['cases']} | {value['bytes']:,} | {value['false_positive_cases_per_mb']:.2f} |")
lines += ['', '## Current real benign text: dev and fresh held-out', '',
          '| Split / class | Bytes | Changed spans | False-positive spans / MB | Removed bytes |',
          '| --- | ---: | ---: | ---: | ---: |']
for name, obj in public.items():
    for kind, value in obj['classes'].items():
        lines.append(f"| {name} / {kind} | {value['bytes']:,} | {value['changed_spans']} | {value['spans_per_mb']:.2f} | {value['removed_bytes']} |")
lines += ['', 'The fresh held-out set was selected/downloaded before reading, then evaluated',
          'once on the frozen digest above. It contains Git show/grep manuals and',
          'public-domain Sense and Sensibility prose. Previously evaluated source sets are retired',
          'with their old source digests after independent grammar/provider audits changed',
          'the engine. Their once-only observations remain in',
          '`results/precision.json`; it is not reused as unseen evidence for this candidate.',
          'Dev sources were reacquired with byte-identical hashes. No engine changes',
          'followed this final held-out evaluation. All source URLs/checksums are recorded.',
          'Zero observed changes in a finite sample does not prove universal zero false',
          'positives or represent every production code/log distribution.', '',
          '## Retired private workspace sample: unlabelled diagnostic only', '',
          f"These observations belong to source `{retired['frozen_source_sha256']}`;",
          'they are not current production precision evidence. The two-dev/two-held-out',
          'split was fixed before reading. No transcript content or session ID is retained.', '',
          '| Split | Sessions | Complete-event bytes | Candidate spans | Changed events | Removed bytes |',
          '| --- | ---: | ---: | ---: | ---: | ---: |']
for name, value in retired['private_unlabelled_candidates'].items():
    lines.append(f"| {name} | {value['sessions']} | {value['bytes']:,} | {value['redaction_spans']} | {value['changed_events']} | {value['removed_bytes']} |")
lines += ['', 'Each split requested 100 bounded events; 10 dev and 4 held-out truncated events',
          'were excluded. Counts are candidate rate, **not false-positive rate**. No raw',
          'sample was inspected or copied into tests. Production-session precision remains',
          'unqualified pending independently labelled evaluation. All owned raw inputs and',
          'generated parity vectors were deleted locally ahead of the 2026-11-17 deadline.', '',
          '## Timing and runtime checks', '',
          f"Host: {platform.system()} {platform.machine()}, Rust 1.88.0 release, five warm samples per family.",
          f"Recall corpus: {metrics['recall_corpus_bytes']:,} bytes, {metrics['recall_throughput_mb_s']:.2f} MB/s including many short calls.",
          'Observed worst times and mean throughput are not a service guarantee.', '',
          '| Family | 64 KiB worst ms | 256 KiB worst ms | 256 KiB mean MB/s |', '| --- | ---: | ---: | ---: |']
small = {value['class']: value for value in metrics['timing'] if value['bytes'] == 65536}
for value in metrics['timing']:
    if value['bytes'] == 262144:
        lines.append(f"| {value['class']} | {small[value['class']]['worst_ms']:.3f} | {value['worst_ms']:.3f} | {value['mb_per_s']:.2f} |")
lines += ['', 'Native tests, clippy, packaging, Node 26.13.0, Bun 1.3.14 and local Cloudflare',
          'workerd (Wrangler 4.77.0) pass. Node/Bun compare 4,928 native-generated vectors,',
          'exercise all APIs, error/pin mismatch paths and adversarial inputs. Native',
          'preserve_order feature-unification tests pass. Independent target-directory',
          'builds reproduce WASM, glue, types and adapter digests. Hosted Linux/Windows CI',
          'and exact-commit owner approval remain required.', '',
          '[Algorithmic bound](PERFORMANCE.md) and [evaluation protocol](EVALUATION.md).']
Path('docs/RESULTS.md').write_text('\n'.join(lines) + '\n')
print(json.dumps({'complete': complete, 'cases': cases, 'classes': len(metrics['recall']),
                  'source': precision['frozen_source_sha256'], 'public_benign': public}))
