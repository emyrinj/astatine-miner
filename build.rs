use std::{env, fs, path::PathBuf};

fn main() {
    let path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets manifest dir"))
        .join("support/release-repository.txt");
    println!("cargo:rerun-if-changed={}", path.display());

    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read release repository identity: {error}"));
    let repository = contents.trim();
    let Some((owner, name)) = repository.split_once('/') else {
        panic!("release repository identity must be exactly OWNER/REPOSITORY");
    };
    let valid_component = |component: &str| {
        component
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && !component.ends_with('.')
    };
    if !valid_component(owner) || !valid_component(name) || name.contains('/') {
        panic!("release repository identity is not a canonical OWNER/REPOSITORY pair");
    }
    println!("cargo:rustc-env=ASTATINE_RELEASE_REPOSITORY={repository}");
}
