//! Best-in-class redaction evals: accuracy, zero false positives, robustness.
//!
//! Every secret below is synthetic (runtime-built filler), never a live
//! credential. Each text case pins whether the canonical engine already
//! fully satisfies it (`base_catches`); the suite proves the enhanced
//! pipeline catches every leak class plus every documented engine gap, while
//! the must-preserve cases prove the enhanced layer adds no false positives.

#![allow(missing_docs)]

use relayscrubber::{
    scrub_enhanced, scrub_enhanced_with_policy, scrub_json_enhanced, scrub_json_text_enhanced,
    scrub_long, Policy,
};
use serde_json::json;

struct Case {
    name: &'static str,
    input: String,
    gone: Vec<String>,
    kept: Vec<String>,
    base_catches: bool,
}

fn jwt_b64url(raw: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn text_cases() -> Vec<Case> {
    let a16 = "Ab1".repeat(16);
    let a12 = "Ab1".repeat(12);
    let hex64: String = "0123456789abcdef".repeat(4);
    // Runtime-built provider bodies: no secret-shaped literal may appear in
    // the blob (push protection), so every token below is assembled here.
    let synthetic = |prefix: &str, n: usize| format!("{prefix}{}", "A".repeat(n));
    let mut cases = Vec::new();
    let mut add = |name: &'static str,
                   input: String,
                   gone: Vec<String>,
                   kept: Vec<String>,
                   base_catches: bool| {
        cases.push(Case {
            name,
            input,
            gone,
            kept,
            base_catches,
        });
    };

    // ---- Relay history replays (synthetic stand-ins for real shapes) ----
    add(
        "relay/neon-url",
        format!(
            "{{\"neonOwnerUrl\":\"postgresql://neondb_owner:SYNpw9!xQ2vLm4nK8w@{a16}.us-east-2.aws.neon.tech/neondb\"}}"
        ),
        vec!["SYNpw9!xQ2vLm4nK8w".into()],
        vec!["postgresql://neondb_owner:".into(), "@".into(), "/neondb".into()],
        true,
    );
    add(
        "relay/bearer",
        format!("Authorization: Bearer CfTemp0{a16}0123"),
        vec![format!("CfTemp0{a16}0123")],
        vec!["Authorization: ".into()],
        true,
    );
    add(
        "relay/basic",
        format!(
            "Authorization: Basic {} happened",
            ["dXNlcjpw", "YXNzd29yZA=="].concat()
        ),
        vec![["dXNlcjpw", "YXNzd29yZA=="].concat()],
        vec!["Authorization: ".into()],
        true,
    );
    add(
        "relay/pem-block",
        format!(
            "here it is -----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY----- done",
            ["QUJD", &"A".repeat(24)].concat()
        ),
        vec![["QUJD", &"A".repeat(24)].concat()],
        vec!["here it is ".into(), " done".into()],
        true,
    );
    add(
        "relay/query-tail",
        "https://example.test/cb?api_key=AK7qW9zmP2xL5vN8sK4dF6hJ3bD0cA2eF9gH7&mode=1 end".into(),
        vec!["AK7qW9zmP2xL5vN8sK4dF6hJ3bD0cA2eF9gH7".into()],
        vec!["?api_key=[REDACTED]".into()],
        true,
    );
    add(
        "relay/fragment",
        "https://example.test/cb#access_token=AC7qW9zmP2xL5vN8sK4dF6hJ3bD0cA2eF9gH7xY1 end".into(),
        vec!["AC7qW9zmP2xL5vN8sK4dF6hJ3bD0cA2eF9gH7xY1".into()],
        vec!["#access_token=[REDACTED]".into()],
        true,
    );
    add(
        "relay/env-key",
        format!(
            "RELAYAUTH_SIGNING_KEY_PEM=-----BEGIN PRIVATE KEY----- {} -----END PRIVATE KEY----- done",
            ["SYNTHBODY", &"A".repeat(9)].concat()
        ),
        vec![["SYNTHBODY", &"A".repeat(9)].concat()],
        vec!["RELAYAUTH_SIGNING_KEY_PEM=".into()],
        true,
    );

    // ---- Canonical providers (ruleset 8 territory) ----
    add(
        "prov/sk-proj",
        format!("found sk-proj-{a16} in output"),
        vec![format!("sk-proj-{a16}")],
        vec!["found ".into(), " in output".into()],
        true,
    );
    add(
        "prov/openai-sk",
        format!("key sk-{a12}ab done"),
        vec![format!("sk-{a12}ab")],
        vec!["key ".into()],
        true,
    );
    add(
        "prov/stripe",
        format!("pay sk_live_{a12}ab ok"),
        vec![format!("sk_live_{a12}ab")],
        vec!["pay ".into()],
        true,
    );
    add(
        "prov/github",
        format!("pat ghp_{a12} ok"),
        vec![format!("ghp_{a12}")],
        vec!["pat ".into()],
        true,
    );
    add(
        "prov/github-fine",
        format!("pat github_pat_{a12}AAAAAA ok"),
        vec![format!("github_pat_{a12}AAAAAA")],
        vec!["pat ".into()],
        true,
    );
    add(
        "prov/aws",
        format!("key {} here", synthetic("AKIA", 16)),
        vec![synthetic("AKIA", 16)],
        vec!["key ".into()],
        true,
    );
    add(
        "prov/gitlab",
        format!("tok glpat-{a12}abcd ok"),
        vec![format!("glpat-{a12}abcd")],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/npm",
        format!("tok npm_{a12} ok"),
        vec![format!("npm_{a12}")],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/hf",
        format!("tok {} ok", synthetic("hf_", 34)),
        vec![synthetic("hf_", 34)],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/cf",
        format!("tok cfut_{a12}abcd ok"),
        vec![format!("cfut_{a12}abcd")],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/slack",
        format!("tok xoxb-{}-{} ok", "1234567890", "A".repeat(22)),
        vec![format!("xoxb-{}-{}", "1234567890", "A".repeat(22))],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/capy",
        format!("tok capy_{a12}abcd ok"),
        vec![format!("capy_{a12}abcd")],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/relay",
        format!("tok relay_ag_{a12}abcd ok"),
        vec![format!("relay_ag_{a12}abcd")],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/rth",
        format!("tok rth_at_{a12} ok"),
        vec![format!("rth_at_{a12}")],
        vec!["tok ".into()],
        true,
    );
    add(
        "prov/google",
        format!("key AIza{a12}abcd ok"),
        vec![format!("AIza{a12}abcd")],
        vec!["key ".into()],
        true,
    );
    add(
        "prov/sendgrid",
        format!(
            "key SG.{}AA.{}BBBBBBBBBBBBBBBBBBBBB ok",
            "C".repeat(20),
            "D".repeat(22)
        ),
        vec![format!(
            "SG.{}AA.{}BBBBBBBBBBBBBBBBBBBBB",
            "C".repeat(20),
            "D".repeat(22)
        )],
        vec!["key ".into()],
        true,
    );
    add(
        "prov/slack-hook",
        format!(
            "see https://hooks.slack.com/services/T00000000/B00000000/{} ok",
            "X".repeat(24)
        ),
        vec!["X".repeat(24)],
        vec!["see ".into(), " ok".into()],
        true,
    );
    add(
        "prov/automation-hook",
        "see /webhooks/automations/AbC12345xYz done".into(),
        vec!["AbC12345xYz".into()],
        vec!["see ".into(), " done".into()],
        true,
    );

    add(
        "prov/oauth",
        "https://example.test/cb?code_verifier=VER7qW9zmP2xL5vN8sK4dF6hJ3bD0cA2eF9gH7&state=abc ok"
            .into(),
        vec!["VER7qW9zmP2xL5vN8sK4dF6hJ3bD0cA2eF9gH7".into()],
        vec!["code_verifier=[REDACTED]".into()],
        true,
    );
    add(
        "prov/glued",
        format!("see build-sk-proj-{a16} ok"),
        vec![format!("build-sk-proj-{a16}")],
        vec!["see ".into(), " ok".into()],
        true,
    );
    add(
        "prov/anthropic",
        format!("found sk-ant-api03-{} end", "Aa0_-".repeat(19)),
        vec![format!("sk-ant-api03-{}", "Aa0_-".repeat(19))],
        vec!["found ".into()],
        true,
    );
    add(
        "prov/sk-or-v1",
        format!("key sk-or-v1-{} end", "B".repeat(64)),
        vec![format!("sk-or-v1-{}", "B".repeat(64))],
        vec!["key ".into()],
        true,
    );

    // Well-formed compact JWT: {"alg":"HS256"} header is a public constant;
    // body/signature are runtime-built so no token literal lives in the blob.
    let jwt = format!(
        "eyJhbGciOiJIUzI1NiJ9.{}.{}",
        jwt_b64url(r#"{"sub":"SYNTH_SUBJECT"}"#),
        jwt_b64url("SYNTH_SIGNATURE_BODY")
    );
    add(
        "prov/jwt",
        format!("tok {jwt} ok"),
        vec![jwt.clone()],
        vec!["tok ".into(), " ok".into()],
        true,
    );
    add(
        "prov/bearer-short",
        format!("Authorization: Bearer {t} ok", t = "abc"),
        vec!["abc".into()],
        vec!["Authorization: ".into()],
        true,
    );
    // ---- New shapes (ruleset 8 misses; the hill-climb) ----
    add(
        "new/dop",
        format!("tok dop_v1_{hex64} ok"),
        vec![format!("dop_v1_{hex64}")],
        vec!["tok ".into()],
        true,
    );
    add(
        "new/doo",
        format!("tok doo_v1_{hex64} ok"),
        vec![format!("doo_v1_{hex64}")],
        vec!["tok ".into()],
        true,
    );
    add(
        "new/dor",
        format!("tok dor_v1_{hex64} ok"),
        vec![format!("dor_v1_{hex64}")],
        vec!["tok ".into()],
        false,
    );
    add(
        "new/ya29",
        format!("tok ya29.{} ok", "C".repeat(68)),
        vec![format!("ya29.{}", "C".repeat(68))],
        vec!["tok ".into()],
        true,
    );
    add(
        "new/gsk",
        format!("key gsk_{} end", "A".repeat(52)),
        vec![format!("gsk_{}", "A".repeat(52))],
        vec!["key ".into()],
        false,
    );
    add(
        "new/age",
        format!("key AGE-SECRET-KEY-1{} end", "D".repeat(43)),
        vec![format!("AGE-SECRET-KEY-1{}", "D".repeat(43))],
        vec!["key ".into()],
        false,
    );
    add(
        "new/xoxc",
        "tok xoxc-1234567890-ABCDEFGHIJabcdefghij ok".into(),
        vec!["xoxc-1234567890-ABCDEFGHIJabcdefghij".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new/discord",
        format!(
            "see https://discord.com/api/webhooks/1234567890/{}?wait=true end",
            "C".repeat(68)
        ),
        vec![format!("1234567890/{}", "C".repeat(68))],
        vec![
            "https://discord.com/api/webhooks/1234567890/".into(),
            "?wait=true".into(),
        ],
        false,
    );
    add(
        "new/discord-ptb",
        format!(
            "see https://ptb.discord.com/api/webhooks/1234567890/{} end",
            "C".repeat(68)
        ),
        vec!["C".repeat(68)],
        vec!["https://ptb.discord.com/api/webhooks/1234567890/".into()],
        false,
    );
    add(
        "new/teams",
        "hook https://tenant.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghi end".into(),
        vec!["/webhookb2/abc/IncomingWebhook/def/ghi".into()],
        vec!["https://tenant.webhook.office.com".into()],
        false,
    );
    add(
        "new/cli-short",
        "mysql --password hunter2 -h db".into(),
        vec!["hunter2".into()],
        vec!["--password [REDACTED] -h db".into()],
        true,
    );
    add(
        "new/cli-token",
        "deploy --token abc123 --verbose".into(),
        vec!["abc123".into()],
        vec!["--token [REDACTED]".into()],
        true,
    );
    add(
        "new/cli-cont",
        "run --secret Hunter2X9 \\\n  --flag v".into(),
        vec!["Hunter2X9".into()],
        vec!["--secret [REDACTED]".into()],
        true,
    );
    add(
        "new/query-pwd",
        "https://h.test/login?password=SYNTHx9Q2&next=/dash ok".into(),
        vec!["SYNTHx9Q2".into()],
        vec!["?password=[REDACTED]".into()],
        true,
    );
    add(
        "new/query-short-token",
        "https://h.test/x?token=abc123&x=1 ok".into(),
        vec!["token=abc123".into()],
        vec!["?token=[REDACTED]".into()],
        true,
    );
    add(
        "new/query-empty",
        "https://h.test/x?token=&x=1 ok".into(),
        vec![],
        vec!["?token=&x=1".into()],
        true,
    );
    add(
        "new/query-hash",
        "https://h.test/x#token=abc123XYZ ok".into(),
        vec!["abc123XYZ".into()],
        vec!["#token=[REDACTED]".into()],
        true,
    );
    add(
        "new/ssn",
        "ssn 078-05-1120 here".into(),
        vec!["078-05-1120".into()],
        vec!["ssn ".into()],
        false,
    );
    add(
        "new/ip-priv",
        "db at 10.1.2.3:5432 ok".into(),
        vec!["10.1.2.3".into()],
        vec![":5432".into()],
        false,
    );
    add(
        "new/ip-192",
        "route 192.168.1.10/24 ok".into(),
        vec!["192.168.1.10".into()],
        vec!["/24".into()],
        false,
    );
    add(
        "new/ip-172",
        "peer 172.16.5.4 ok".into(),
        vec!["172.16.5.4".into()],
        vec!["peer ".into()],
        false,
    );
    add(
        "new/ip-loopback",
        "lo 127.0.0.1 ok".into(),
        vec!["127.0.0.1".into()],
        vec!["lo ".into()],
        false,
    );
    add(
        "new/ip-metadata",
        "curl 169.254.169.254/latest ok".into(),
        vec!["169.254.169.254".into()],
        vec!["/latest".into()],
        false,
    );

    // ---- PII: default policy preserves by contract (see the
    // `pii_policy_redacts_email_and_ssn` test for Policy::Pii) ----

    add(
        "pii/userinfo",
        "open postgresql://bob:hunter2xQ9@example.com/db ok".into(),
        vec!["hunter2xQ9".into()],
        vec!["postgresql://bob:".into(), "@example.com".into()],
        true,
    );

    add(
        "ctx/quoted",
        format!("{{\"password\": \"{a16}\", \"user\": \"ops\"}}"),
        vec![a16.clone()],
        vec!["\"password\": \"[REDACTED]\"".into()],
        true,
    );
    add(
        "ctx/assign-env",
        format!("DB_PASSWORD={a16} ok"),
        vec![a16.clone()],
        vec!["DB_PASSWORD=".into()],
        true,
    );
    add(
        "ctx/fallback",
        "the secret -> aB3dE5fG7hJ9kL2mN4pQ6sT8uV1wX4yZ7 is rotated".into(),
        vec!["aB3dE5fG7hJ9kL2mN4pQ6sT8uV1wX4yZ7".into()],
        vec!["the secret -> [REDACTED]".into()],
        true,
    );
    add(
        "ctx/unclosed",
        format!("\"password\": \"{a12} trailing"),
        vec![a12.clone()],
        // Unterminated: the redaction runs to end of input, so no closing quote.
        vec!["\"password\": \"[REDACTED]".into()],
        true,
    );
    add(
        "ctx/idempotency-public",
        "idempotency_key=public-replay-42 keep".into(),
        vec![],
        vec!["idempotency_key=public-replay-42".into()],
        true,
    );
    add(
        "ctx/idempotency-credential",
        format!("idempotency_key=ghp_{a12} keep"),
        vec![format!("ghp_{a12}")],
        vec!["idempotency_key=".into()],
        true,
    );

    // ---- Batch 2: verified v8 behavior (no code change, pinned by evals) ----
    add(
        "base/pgp-private",
        "k -----BEGIN PGP PRIVATE KEY BLOCK----- AAAABBBBCCCCSYNTH -----END PGP PRIVATE KEY BLOCK----- d".into(),
        vec!["AAAABBBBCCCCSYNTH".into()],
        vec!["k ".into()],
        true,
    );
    add(
        "base/ec-key",
        "k -----BEGIN EC PRIVATE KEY----- AAAABBBBCCCCSYNTH -----END EC PRIVATE KEY----- d".into(),
        vec!["AAAABBBBCCCCSYNTH".into()],
        vec!["k ".into()],
        true,
    );
    add(
        "base/proxy-auth",
        "hdr Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA== ok".into(),
        vec!["dXNlcjpwYXNzd29yZA==".into()],
        vec!["Proxy-Authorization: ".into()],
        true,
    );
    add(
        "base/x-auth-token-short",
        "h X-Auth-Token: abc123short ok".into(),
        vec!["abc123short".into()],
        vec!["X-Auth-Token:".into()],
        true,
    );
    add(
        "base/private-token-short",
        "h Private-Token: abc123short ok".into(),
        vec!["abc123short".into()],
        vec!["Private-Token:".into()],
        true,
    );
    add(
        "base/docker-auths",
        r#"{"auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNzd29yZA=="}}}"#.into(),
        vec!["dXNlcjpwYXNzd29yZA==".into()],
        vec!["\"auth\": \"[REDACTED]\"".into()],
        true,
    );
    add(
        "base/jaas",
        r#"password="hunter2short" username="ops""#.into(),
        vec!["hunter2short".into()],
        vec!["password=".into()],
        true,
    );
    add(
        "base/token-user-url",
        "open https://mytoken123xQ9@registry.test/v2/ ok".into(),
        vec!["mytoken123xQ9".into()],
        vec!["https://".into(), "@registry.test".into()],
        false,
    );
    add(
        // The canonical assignment rule redacts any `*_key=` value, including
        // public-ish consumer keys: pinned, not fought.
        "base/oauth-consumer-key",
        "https://h.test/x?oauth_consumer_key=abc123 ok".into(),
        vec!["abc123".into()],
        vec!["?oauth_consumer_key=[REDACTED]".into()],
        true,
    );

    add(
        "new2/max-token-number",
        r#"{"max_token": 4096, "token": null}"#.into(),
        vec!["4096".into()],
        vec!["\"max_token\": ".into()],
        true,
    );
    add(
        "new2/cookie-all",
        "Cookie: theme=dark; locale=en ok".into(),
        vec!["theme=dark".into(), "locale=en".into()],
        vec!["Cookie: ".into()],
        true,
    );
    // ---- Batch 2: new shapes ----
    add(
        "new2/dapi",
        format!("tok dapi{} ok", &hex64[..32]),
        vec![format!("dapi{}", &hex64[..32])],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/pypi",
        format!("tok pypi-AgEIc3ludGhldGlj{} ok", "B".repeat(52)),
        vec![format!("pypi-AgEIc3ludGhldGlj{}", "B".repeat(52))],
        vec!["tok ".into()],
        true,
    );
    add(
        "new2/replicate",
        format!("tok r8_{} ok", "A".repeat(40)),
        vec![format!("r8_{}", "A".repeat(40))],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/tailscale",
        "tok tskey-auth-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["tskey-auth-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/doppler",
        "tok dp.pt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["dp.pt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/vault",
        "tok hvs.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["hvs.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/onepassword",
        "tok ops_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["ops_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/pulumi",
        "tok pul-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["pul-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/postman",
        "tok PMAK-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["PMAK-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/brevo",
        "tok xkeysib-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["xkeysib-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/newrelic",
        "tok NRAK-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["NRAK-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/sentry",
        "tok sntrys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["sntrys_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/sonar",
        "tok squ_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["squ_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/supabase",
        "tok sbp_AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["sbp_AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/xai",
        "tok xai-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["xai-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/perplexity",
        "tok pplx-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["pplx-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/gitlab-deploy",
        "tok gldt-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["gldt-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/gitlab-runner",
        "tok glrt-AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["glrt-AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/mailchimp",
        format!("key {}-us1 ok", &hex64[..32]),
        vec![format!("{}-us1", &hex64[..32])],
        vec!["key ".into()],
        false,
    );
    add(
        "new2/atlasv1",
        "tok AAAABBBBCCCCCCCCCCCC.atlasv1 ok".into(),
        vec!["AAAABBBBCCCCCCCCCCCC.atlasv1".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/notion",
        format!("tok secret_{} ok", "A".repeat(40)),
        vec![format!("secret_{}", "A".repeat(40))],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/docker-pat",
        "tok dckr_pat_AAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["dckr_pat_AAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/linear",
        "tok lin_api_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok".into(),
        vec!["lin_api_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
        vec!["tok ".into()],
        false,
    );
    add(
        "new2/telegram",
        "tg 123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDs0 ok".into(),
        vec!["123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDs0".into()],
        vec!["tg ".into()],
        false,
    );
    add(
        "new2/webhook-site",
        "hook https://webhook.site/abc12345-1234-1234-1234-abc123456789 ok".into(),
        vec!["abc12345-1234-1234-1234-abc123456789".into()],
        vec!["https://webhook.site".into()],
        false,
    );
    add(
        "new2/ansible",
        "vault $ANSIBLE_VAULT;1.1;AES256 6231336538313331656632633961623133386538313331656632633961 ok".into(),
        vec!["6231336538313331656632633961623133386538313331656632633961".into()],
        vec!["vault ".into()],
        false,
    );
    add(
        "new2/xml",
        "xml <password>hunter2short</password> ok".into(),
        vec!["hunter2short".into()],
        vec!["<password>[REDACTED]</password>".into()],
        false,
    );
    add(
        "new2/xml-token",
        "cfg <api-key>AK7qW9zmP2xL5</api-key> ok".into(),
        vec!["AK7qW9zmP2xL5".into()],
        vec!["<api-key>[REDACTED]</api-key>".into()],
        false,
    );
    add(
        "new2/cookie",
        "Cookie: theme=dark; sid=hunter2short; Path=/ ok".into(),
        vec!["sid=hunter2short".into()],
        vec!["Cookie: ".into()],
        true,
    );
    add(
        "new2/set-cookie",
        "Set-Cookie: sessionid=abc123XYZ; Path=/; HttpOnly ok".into(),
        vec!["sessionid=abc123XYZ".into()],
        vec!["Set-Cookie: ".into()],
        true,
    );
    add(
        "new2/apikey-scheme",
        "h Authorization: ApiKey abc123short ok".into(),
        vec!["abc123short".into()],
        vec!["Authorization: ".into()],
        true,
    );
    add(
        "new2/kube",
        "cfg client-key-data: LS0tLS1CRUdJTiBQUklWQVRFIEtFWQ0KQUJDRA== ok".into(),
        vec!["LS0tLS1CRUdJTiBQUklWQVRFIEtFWQ0KQUJDRA==".into()],
        vec!["client-key-data: ".into()],
        false,
    );
    add(
        "new2/redis",
        "open redis://:hunter2xQ9@db.internal:6379/0 ok".into(),
        vec!["hunter2xQ9".into()],
        vec!["redis://:[REDACTED]@db.internal:6379".into()],
        true,
    );
    add(
        "new2/otpauth",
        "url otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=Y ok".into(),
        vec!["JBSWY3DPEHPK3PXP".into()],
        vec!["?secret=[REDACTED]".into()],
        true,
    );
    add(
        "new2/amz-sig",
        "url https://s3.test/x?X-Amz-Signature=abcdef0123456789abcdef0123456789abcdef0123456789abcdef01&x-id=1 ok".into(),
        vec!["abcdef0123456789abcdef0123456789abcdef0123456789abcdef01".into()],
        vec!["X-Amz-Signature=[REDACTED] &x-id=1".into()],
        false,
    );
    add(
        "new2/oauth1",
        "url https://h.test/x?oauth_token=abc123XYZ&oauth_token_secret=def456UVW ok".into(),
        vec!["abc123XYZ".into(), "def456UVW".into()],
        vec!["?oauth_token=[REDACTED]".into()],
        true,
    );

    cases
}

/// Inputs that must survive byte-for-byte: the no-false-positive guard.
fn preserve_cases() -> Vec<(&'static str, String)> {
    vec![
        ("fp/uuid", "session 550e8400-e29b-41d4-a716-446655440000 started".into()),
        ("fp/git-sha", "commit a346a7a9e1b2c3d4e5f60718293a4b5c6d7e8f0 done".into()),
        ("fp/short-sha", "merge a346a7a ok".into()),
        ("fp/sha256", "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a  dist/app.tar.gz".into()),
        ("fp/arn", "role arn:aws:iam::123456789012:role/sessions-pipeline-ingest ok".into()),
        ("fp/counts", r#"{"input_tokens": 1234, "output_tokens": 98}"#.into()),
        ("fp/words", r#"{"oauth": "enabled", "author": "ops"}"#.into()),
        ("fp/token-prose", "The token budget is 200000 and the secret sauce is caching.".into()),
        ("fp/password-prose", "Reset the password from the settings page.".into()),
        ("fp/path", "see src/token/TokenRefreshService.java here".into()),
        ("fp/member", "const x = token.getAccessTokenSilently()".into()),
        ("fp/cf-short", "cfut_short and cfk_notreal ok".into()),
        ("fp/empty", r#"{"password": ""}"#.into()),
        ("fp/redacted", r#"{"password": "[REDACTED]"}"#.into()),
        (
            "fp/pem-prose",
            "unencrypted PKCS#8 RSA private key (BEGIN PRIVATE KEY; 3072-bit) signs all".into(),
        ),
        (
            "fp/begin-cert",
            "cert -----BEGIN CERTIFICATE-----\nMIIBc3ludGhldGljY2VydGlmaWNhdGU=\n-----END CERTIFICATE----- ok".into(),
        ),
        ("fp/branch", "git checkout feature/secret-RotateCloudflareKeys2026 ok".into()),
        ("fp/integrity", r#""integrity": "sha512-SGVsbG8sIHdvcmxkISBUaGlzIGlzIG5vdCBhIHNlY3JldC4SGVsbG8sIHdvcmxkIQ==""#.into()),
        ("fp/no-secret-key", r#"{"tokens":12,"author":"ops","oauth":"enabled","key":"k1"}"#.into()),
        ("fp/op-ref", r#"{"secret": "op://Engineering/cloudflare/credential"}"#.into()),
        ("fp/op-env", r#"CF_TOKEN_REF="op://Engineering/cloudflare/credential""#.into()),
        ("fp/agent-addr", "muse-relayscrubber-session@dogpatch-mini-245838049384067072".into()),
        ("fp/ip-public", "dns 8.8.8.8 and version 1.2.3.4 ok".into()),
        ("fp/ip-bad", "net 999.1.1.1 and 1.2.3 and 1.2.3.4.5 ok".into()),
        ("fp/ip-big-octet", "net 10.1.2.300 ok".into()),
        (
            "fp/ssn-bad",
            "ids 000-12-3456 666-12-3456 900-12-3456 078-00-1120 078-05-0000 ok".into(),
        ),
        ("fp/cli-eol", "run cmd --password".into()),
        ("fp/cli-envref", "run --password $DB_PASS ok".into()),
        ("fp/pgp-public", "k -----BEGIN PGP PUBLIC KEY BLOCK----- AAAABBBBCCCC -----END PGP PUBLIC KEY BLOCK----- d".into()),
        ("fp/age-recipient", "age1ql3z7hj432v2jl2alunwwun8ujt8nd4rylljdd4ph9mah8q8q0zg2x6d ok".into()),
        ("fp/client-id", "https://h.test/x?client_id=abc123&x=1 ok".into()),
        ("fp/oauth-consumer-secret-name", "use oauth_consumer_secret ok".into()),
        ("fp/phc", "phc_abcdefghijklmnopqrstuvwxyz123456 ok".into()),
        ("fp/signed-headers", "https://s.test/x?X-Goog-SignedHeaders=host&x=1 ok".into()),
        ("fp/sas-policy", "https://s.test/x?se=2025-01-01&sp=r&sv=1 ok".into()),
        (
            "fp/generic-key",
            format!("key-{} ok", "abcdef0123456789".repeat(2)),
        ),
        ("fp/resend-short", "re_abc123 ok".into()),
        ("fp/plist-key", "<plist><dict><key>token</key><string>abc</string></dict></plist>".into()),
        ("fp/ansible-header-only", "vault $ANSIBLE_VAULT;1.1;AES256 ok".into()),
        ("fp/xml-mismatch", "xml <password>abc</pass> ok".into()),
        ("fp/kube-short", "cfg client-key-data: key.pem ok".into()),
        ("fp/email-default", "contact jane.doe@example.com please".into()),
        ("fp/phone-intl", "call +1 (415) 555-0132 tomorrow".into()),
        ("fp/phone-nanp", "call 415-555-0132 tomorrow".into()),
        ("fp/card", "card 4111 1111 1111 1111 charged".into()),
        ("fp/home-dir", "path /Users/ops/projects ok".into()),
    ]
}

fn base_ok(case: &Case) -> bool {
    let out = scrub_long(&case.input);
    case.gone.iter().all(|g| !out.contains(g)) && case.kept.iter().all(|k| out.contains(k))
}

fn check(case: &Case) {
    let out = scrub_enhanced(&case.input);
    for g in &case.gone {
        assert!(!out.contains(g), "{}: leaked {g:?} -> {out:?}", case.name);
    }
    for k in &case.kept {
        assert!(out.contains(k), "{}: lost {k:?} -> {out:?}", case.name);
    }
    assert_eq!(
        base_ok(case),
        case.base_catches,
        "{}: base flag drift",
        case.name
    );
    let twice = scrub_enhanced(&out);
    assert_eq!(twice, out, "{}: not idempotent", case.name);
}

#[test]
fn relay_history_replays_are_captured() {
    for case in text_cases().iter().filter(|c| c.name.starts_with("relay/")) {
        check(case);
    }
}

#[test]
fn canonical_providers_stay_captured() {
    for case in text_cases().iter().filter(|c| {
        c.name.starts_with("prov/") || c.name.starts_with("pii/") || c.name.starts_with("ctx/")
    }) {
        check(case);
    }
}

#[test]
fn new_shapes_are_captured() {
    for case in text_cases().iter().filter(|c| {
        c.name.starts_with("new/") || c.name.starts_with("new2/") || c.name.starts_with("base/")
    }) {
        check(case);
    }
}

#[test]
fn nothing_benign_is_redacted() {
    for (name, input) in preserve_cases() {
        let out = scrub_enhanced(&input);
        assert_eq!(out, input, "{name}: false positive -> {out:?}");
        assert_eq!(scrub_long(&input), input, "{name}: base flag drift");
    }
}

#[test]
fn json_entry_points_cover_new_shapes() {
    let value = json!({
        "webhook": "https://discord.com/api/webhooks/1234567890/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "db": "10.1.2.3",
        "password": "hunter2",
        "nested": {"token": "gsk_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "n": 3},
        "public": "550e8400-e29b-41d4-a716-446655440000",
    });
    let (clean, count) = scrub_json_enhanced(&value);
    let text = clean.to_string();
    assert!(!text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    assert!(!text.contains("10.1.2.3"));
    assert!(!text.contains("hunter2"));
    assert!(!text.contains("gsk_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"));
    assert!(text.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(count >= 4, "count was {count}");
    let (from_text, text_count) =
        scrub_json_text_enhanced(&serde_json::to_string(&value).unwrap()).unwrap();
    assert_eq!(from_text, clean);
    assert_eq!(text_count, count);
    let reserialized = serde_json::to_string(&clean).unwrap();
    let (twice, twice_count) = scrub_json_text_enhanced(&reserialized).unwrap();
    assert_eq!(twice, clean);
    assert_eq!(twice_count, 0);
}

#[test]
fn long_segmented_inputs_keep_new_shapes_redacted() {
    let filler = "ordinary log line 200000 token budget ok ".repeat(7000);
    assert!(filler.len() > 262_144);
    // A CLI flag straddling the 262,144 boundary: flag in one segment, value in the next.
    let cut = 262_144 - "mysql --password ".len() / 2;
    let head = format!("{}mysql --password ", &filler[..cut]);
    let input = format!(
        "{head}hunter2 mid dop_v1_{} ssn 078-05-1120 ip 10.9.9.9 tail",
        "0123456789abcdef".repeat(4)
    );
    let out = scrub_enhanced(&input);
    for secret in [
        "hunter2",
        &"0123456789abcdef".repeat(4),
        "078-05-1120",
        "10.9.9.9",
    ] {
        assert!(!out.contains(secret), "leaked {secret}");
    }
    assert_eq!(scrub_enhanced(&out), out);
}

#[test]
fn pii_policy_redacts_email_and_ssn() {
    let email = "contact jane.doe@example.com please";
    let out = scrub_enhanced_with_policy(email, Policy::Pii);
    assert!(
        !out.contains("jane.doe@example.com"),
        "pii/email leaked -> {out:?}"
    );
    assert!(
        out.contains("contact "),
        "pii/email lost context -> {out:?}"
    );
    assert_eq!(
        scrub_enhanced_with_policy(&out, Policy::Pii),
        out,
        "pii/email not idempotent"
    );
    let ssn = "ssn 078-05-1120 here";
    let out = scrub_enhanced_with_policy(ssn, Policy::Pii);
    assert!(!out.contains("078-05-1120"), "pii/ssn leaked -> {out:?}");
    // Default policy preserves both by contract.
    assert_eq!(scrub_enhanced(email), email);
}

#[test]
fn accuracy_summary_reports_v8_and_enhanced() {
    let cases = text_cases();
    let preserves = preserve_cases();
    let mut base_hit = 0;
    let mut enh_hit = 0;
    let mut enh_miss = Vec::new();
    for case in &cases {
        if base_ok(case) {
            base_hit += 1;
        }
        let out = scrub_enhanced(&case.input);
        if case.gone.iter().all(|g| !out.contains(g)) && case.kept.iter().all(|k| out.contains(k)) {
            enh_hit += 1;
        } else {
            enh_miss.push(case.name);
        }
    }
    let mut fp = 0;
    for (name, input) in &preserves {
        if scrub_enhanced(input) != *input {
            fp += 1;
            enh_miss.push(name);
        }
    }
    println!(
        "accuracy: base {base_hit}/{} enhanced {enh_hit}/{} false-positives {fp}/{}",
        cases.len(),
        cases.len(),
        preserves.len()
    );
    assert!(enh_miss.is_empty(), "misses: {enh_miss:?}");
    assert_eq!(enh_hit, cases.len());
    assert_eq!(fp, 0);
}
