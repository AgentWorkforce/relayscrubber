//! Independent synthetic ground truth. Does not import engine rules or regexes.
#![allow(dead_code)]
use std::ops::Range;

pub struct Case {
    pub class: &'static str,
    pub text: String,
    pub secrets: Vec<Range<usize>>,
}
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn body(&mut self, len: usize, alphabet: &[u8]) -> String {
        // All generated credentials carry a visible SYNTHETIC marker. Shapes
        // with restricted alphabets are synthetic by construction and seed.
        (0..len)
            .map(|_| alphabet[self.next() as usize % alphabet.len()] as char)
            .collect()
    }
}

fn case(class: &'static str, prefix: &str, secret: &str, suffix: &str) -> Case {
    Case {
        class,
        text: format!("{prefix}{secret}{suffix}"),
        secrets: std::iter::once(prefix.len()..prefix.len() + secret.len()).collect(),
    }
}

pub fn recall(seed: u64, rounds: usize) -> Vec<Case> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::new();
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for round in 0..rounds {
        let body = format!("SYNTHETIC{}", rng.body(64, ALNUM));
        let provider = [
            ("openai", format!("sk-proj-{body}")),
            ("anthropic", format!("sk-ant-api03-{body}")),
            ("github", format!("ghp_{}", &body[..36])),
            ("github_fine", format!("github_pat_{body}")),
            ("gitlab", format!("glpat-{}", &body[..32])),
            (
                "aws",
                format!(
                    "AKIASYNTHETIC{}",
                    rng.body(7, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                ),
            ),
            ("stripe", format!("sk_live_{}", &body[..32])),
            ("stripe_restricted", format!("rk_test_{}", &body[..32])),
            ("stripe_webhook", format!("whsec_{}", &body[..32])),
            (
                "slack",
                format!(
                    "xoxb-{}-{}-{}",
                    rng.body(12, b"0123456789"),
                    rng.body(12, b"0123456789"),
                    &body[..24]
                ),
            ),
            (
                "slack_app",
                format!("xapp-1-{}-{body}", rng.body(12, b"0123456789")),
            ),
            ("npm", format!("npm_{}", &body[..36])),
            ("pypi", format!("pypi-{body}")),
            ("google", format!("AIza{}", &body[..35])),
            ("google_extended", format!("AIza{body}")),
            (
                "google_embedded_prefix",
                format!("AIza{}-ghp_{}", &body[..10], &body[..24]),
            ),
            ("google_oauth", format!("ya29.{body}")),
            ("sendgrid", format!("SG.{}.{}", &body[..22], &body[..43])),
            (
                "digitalocean",
                format!("dop_v1_{}", rng.body(64, b"0123456789abcdef")),
            ),
            ("cloudflare", format!("cfut_{body}")),
            ("cloudflare_account", format!("cfat_{body}")),
            ("cloudflare_global", format!("cfk_{body}")),
            ("slack_refresh", format!("xoxe-1-{body}")),
            ("relay", format!("relay_ag_{body}")),
            ("relayhistory", format!("rth_at_{body}")),
            ("capy", format!("capy_{body}")),
            ("cursor", format!("crsr_{body}")),
            ("vercel", format!("vercel_{body}")),
            ("huggingface", format!("hf_{}", &body[..30])),
            (
                "jwt",
                format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJTWU5USEVUSUMifQ.{body}"),
            ),
            (
                "slack_webhook",
                format!("https://hooks.slack.com/services/T000TEST/B000TEST/{body}"),
            ),
        ];
        for (class, token) in provider {
            let (prefix, suffix) = match round % 5 {
                0 => ("INFO response received: ", " next operation succeeded\n"),
                1 => ("const fixture = \"", "\"; // synthetic\n"),
                2 => ("chat: 値=", "\nnext message"),
                3 => ("{\"debug\":\"", "\",\"status\":200}"),
                _ => ("shell$ echo '", "'\n"),
            };
            out.push(case(class, prefix, &token, suffix));
        }
        let names = [
            "password",
            "api_key",
            "clientSecret",
            "AWS_SECRET_ACCESS_KEY",
            "session_id",
            "refresh-token",
        ];
        let separators = ["=", ":", "%3D", "%253d", "%u003d", "\\u003d", "\\x3d"];
        let quotes = [
            "\"", "'", "`", "%22", "%2522", "%u0022", "\\u0022", "\\x22", "\\\"",
        ];
        for name in names {
            let sep = separators[round % separators.len()];
            let q = quotes[round % quotes.len()];
            let secret = format!("SYNTH_ALPHA_{} SYNTH_BETA_{}", rng.next(), rng.next());
            out.push(case(
                "quoted_assignment",
                &format!("{name}{sep}{q}"),
                &secret,
                q,
            ));
            out.push(case(
                "malformed_quote",
                &format!("{name}{sep}{q}"),
                &secret,
                "",
            ));
            out.push(case(
                "public_nested",
                &format!("idempotency_key={q}{name}{sep}"),
                &secret,
                q,
            ));
            out.push(case(
                "newline_credential",
                &format!("{name}{sep}{q}"),
                &secret.replace(' ', "\n"),
                q,
            ));
        }
        out.push(case("authorization", "Authorization: Basic ", &body, "\n"));
        out.push(case("bearer", "request Bearer ", &body, "\n"));
        out.push(case("cookie", "Cookie: session=", &body, "\n"));
        out.push(case("cli", "tool --password ", &body, " --verbose"));
        out.push(case(
            "connection_string",
            "Server=db;Password=",
            &body,
            ";User=app",
        ));
        out.push(case(
            "url_userinfo",
            "postgres://user:",
            &body,
            "@db.test/app",
        ));
        out.push(case(
            "signed_url",
            "https://storage.test/object?X-Amz-Signature=",
            &body,
            "&mode=read",
        ));
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC{}\n-----END PRIVATE KEY-----",
            rng.body(128, ALNUM)
        );
        out.push(case("pem", "before\n", &pem, "\nafter"));
    }
    out
}

pub fn benign(seed: u64, rounds: usize) -> Vec<(&'static str, String)> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::new();
    for i in 0..rounds {
        let hash = rng.body(64, b"0123456789abcdef");
        out.push((
            "hashes",
            format!(
                "commit {} sha256:{hash} integrity sha512-{}\n",
                &hash[..40],
                rng.body(
                    88,
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                )
            ),
        ));
        out.push((
            "identifiers",
            format!(
                "const token_count = {i}; function getApiKey() {{ return config.public_key; }}\n"
            ),
        ));
        out.push(("paths",format!("/Users/example/project/{i}.rs C:\\Users\\example\\project\\{i}.ts /home/example/code\n")));
        out.push((
            "urls",
            format!("https://example.test/items/{i}?state=ready&code={i}&key=arrow\n"),
        ));
        out.push(("prose",format!("Review issue #{i}, version 1.2.3 at 2026-11-10T09:00:00Z. Email person{i}@example.test.\n")));
        out.push((
            "public_selectors",
            format!("idempotency_key=public-replay-{i} public_key=ssh-ed25519 {hash}\n"),
        ));
        out.push(("uuid", format!("12345678-1234-4234-8234-{i:012}\n")));
        out.push((
            "base64_assets",
            format!(
                "data:image/png;base64,{}\n",
                rng.body(
                    256,
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                )
            ),
        ));
    }
    out
}
