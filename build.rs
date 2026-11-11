//! Generate the canonical source identity without target-dependent inputs.
use sha2::{Digest, Sha256};

fn main() {
    // Ordered path sentinels prevent ambiguous concatenations. LF is canonical.
    let mut hash = Sha256::new();
    for path in [
        "build.rs",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "src/lib.rs",
        "src/engine.rs",
        "src/syntax.rs",
        "src/normalize.rs",
        "src/json.rs",
        "src/wasm.rs",
    ] {
        println!("cargo:rerun-if-changed={path}");
        hash.update(path.as_bytes());
        hash.update(b"\n");
        let disk_path = if path == "Cargo.toml" && std::path::Path::new("Cargo.toml.orig").exists()
        {
            "Cargo.toml.orig"
        } else {
            path
        };
        let source = std::fs::read_to_string(disk_path)
            .expect("ruleset source")
            .replace("\r\n", "\n");
        hash.update(source.as_bytes());
        hash.update(b"\n");
    }
    println!(
        "cargo:rustc-env=RELAY_SCRUB_SOURCE_SHA256={:x}",
        hash.finalize()
    );
}
