# Recognition families and primary format references

The exact executable pattern list is in `src/engine.rs`. Bounds below are
recognition thresholds, not proof of token validity or a provider's guaranteed
maximum length. We do not contact issuers, verify checksums, or whitelist test
keys. All corpus keys are generated from seeds; no live credentials are used.

| Family | Recognition and precision decision | Format evidence |
| --- | --- | --- |
| GitHub | Classic `ghp/gho/ghu/ghs/ghr_`, fine-grained `github_pat_` | [GitHub token formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats) |
| AWS | `AKIA` / `ASIA` plus at least 16 uppercase alphanumeric bytes; labelled secret/session keys | [AWS credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html), [identifier prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html) |
| Stripe | `sk_` / `rk_` live/test and `whsec_`; preserve publishable `pk_` | [Stripe key types](https://docs.stripe.com/keys) |
| Slack | `xox[baprse]-`, `xapp-`, incoming services/workflow/trigger hooks | [Slack token types](https://docs.slack.dev/authentication/tokens/) |
| Cloudflare | `cfut_`, `cfat_`, `cfk_`; older unprefixed values require a credential label | [Cloudflare scannable formats](https://developers.cloudflare.com/fundamentals/api/get-started/token-formats/) |
| DigitalOcean | Personal/OAuth `dop_v1_`, `doo_v1_` plus 64 hex bytes | [DigitalOcean authentication](https://docs.digitalocean.com/products/kubernetes/reference/api/) |
| Vercel | `vercel_` and labelled `VERCEL_TOKEN` | [Vercel token setup](https://vercel.com/academy/production-monorepos/remote-caching) |
| OpenAI / Anthropic | `sk-`, including project/service-account/Anthropic families | Distinctive historical provider prefixes; minimum body is a detector policy, not a stable issuer length contract |
| GitLab, npm, PyPI, Google, SendGrid, Hugging Face | Distinctive `glpat-`, `npm_`, `pypi-`, `AIza`, `ya29.`, `SG.`, `hf_` families | [GitHub's supported provider inventory](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns); bounded pattern definitions in the engine |
| Agent Relay / Relayhistory / Capy / Cursor | `relay_ag/pa/ws/id_`, `rth_at/rt/st_`, `capy_`, `crsr_` | Existing repository contract, retained from frozen v8 as local format evidence |
| JWT / JWE | Base64url JSON header containing string `alg`; three or five segments; unsigned JWT accepted | [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) |
| PEM | PRIVATE KEY families and PGP PRIVATE KEY BLOCK, including unclosed input | [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) |

Credential names, headers, cookies, userinfo and signed-URL parameters cover
unprefixed values without an entropy heuristic. Bare arbitrary hashes and base64
are preserved. This inventory is finite; adding a provider requires independent
seeded positives, realistic wrappers and corresponding benign boundary tests.

`op://` references are preserved only as complete three/four-segment references
with nonempty trimmed components containing alphanumeric characters, single
spaces, `_`, `-` or `.`. No controls, quotes, escapes, percent encodings or appended
assignments are allowed. Provider-token recognition still applies within them.
