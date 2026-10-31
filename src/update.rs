use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use semver::Version;
use serde::Deserialize;
#[cfg(windows)]
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const REPOSITORY: &str = env!("ASTATINE_RELEASE_REPOSITORY");
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_RELEASE_LIST_BYTES: usize = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_ASSET_BYTES: usize = 128 * 1024 * 1024;
const SIGNATURE_BYTES: usize = 384;

const RSA_MODULUS_BASE64: &str = "1Qxetx4KvnfuhGEP17i09JKEg2WYQ5ExtGc8ioSsVi4zsghLCaDL2WKs0ibGyTa2Gju2x0UTGHRuUBHEaDtaAs4oirYtVwwvj5Jca14zc2ggL1ZcwBiN+B3GvTwOot+kd/QBcp+yFiGj2YdUtt9PZcIweIi0LZnbJGyl+khfWQ3iHa+1bpCzin5KLGcPFD2UevErRx/WbKJzg2qdxkGKESDLQc9panAqZTbEkYzKQhrIJBJPBuOGJZc+K+KzeLd+iLNx31UUUaRcUtJ0g3NOgIA8z3EVM6dRnbVmT1Wk5UV5RFNAujfb7ptVx7q3fzxkV7d5Fuk0VFlSU4WddWyNsGHFpZj/U/n3yh0vRzyt08yLVsYRKpKqKFvZSN/Ad4ARYto7POee4Alu6kWHALdqIwWqR9TT5IYyiCze37ZwZcU3Mqq1t6VytWdP9GMHlWVw87v7/BglcSgb+h7e7+YN9ok5BTW/eZYqd5B1/xljaiUUHanhzQ6dX2vPnCwF5jz7";
const RSA_EXPONENT_BASE64: &str = "AQAB";

const TARGETS: [&str; 5] = [
    "macos-aarch64",
    "macos-x86_64",
    "linux-aarch64",
    "linux-x86_64",
    "windows-x86_64",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestAsset {
    filename: String,
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UpdateManifest {
    version: String,
    assets: BTreeMap<String, ManifestAsset>,
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    prerelease: bool,
    draft: bool,
}

struct UpdateLock {
    _file: File,
}

impl UpdateLock {
    fn acquire(directory: &Path) -> Result<Self> {
        let path = directory.join(".astatine-update.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = options.open(&path).context("open Astatine update lock")?;
        let metadata = file.metadata().context("inspect Astatine update lock")?;
        if !metadata.is_file() || is_reparse_point(&metadata) {
            bail!("Astatine update lock is not a regular file");
        }
        file.try_lock()
            .context("another Astatine update is already in progress")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .context("restrict Astatine update lock permissions")?;
        }
        Ok(Self { _file: file })
    }
}

#[cfg(windows)]
#[derive(Serialize)]
struct WindowsUpdatePlan {
    expected_version: String,
    executable: String,
    lock: String,
    log: String,
    files: Vec<WindowsUpdateFile>,
}

#[cfg(windows)]
#[derive(Serialize)]
struct WindowsUpdateFile {
    destination: String,
    staged: String,
    backup: String,
}

pub async fn run() -> Result<()> {
    if current_target() == "unsupported-platform" {
        bail!("authenticated updates are unavailable for this operating system or architecture");
    }
    let executable = std::env::current_exe()
        .context("locate the running Astatine executable")?
        .canonicalize()
        .context("resolve the running Astatine executable path")?;
    let executable_directory = executable
        .parent()
        .context("running executable has no parent directory")?;
    let _update_lock = UpdateLock::acquire(executable_directory)?;
    let Some((tag, manifest)) = latest_signed_update().await? else {
        println!("Astatine {CURRENT_VERSION} is current for the Testnet release channel.");
        return Ok(());
    };
    let client = http_client()?;
    let target = current_target();
    let binary_key = format!("binary.{target}");
    let binary_asset = manifest
        .assets
        .get(&binary_key)
        .context("signed update manifest has no binary for this platform")?;
    let binary = download_verified_asset(&client, &tag, binary_asset).await?;
    let mit_license = download_verified_asset(
        &client,
        &tag,
        manifest
            .assets
            .get("license.LICENSE-MIT")
            .context("signed update manifest has no MIT license notice")?,
    )
    .await?;
    let third_party_licenses = download_verified_asset(
        &client,
        &tag,
        manifest
            .assets
            .get("license.THIRD_PARTY_LICENSES.md")
            .context("signed update manifest has no third-party license notices")?,
    )
    .await?;

    let installed = install_verified_update(
        &executable,
        &binary,
        &mit_license,
        &third_party_licenses,
        &manifest.version,
    )?;
    if installed {
        println!(
            "Updated Astatine to {} from an authenticated release.",
            manifest.version
        );
    }
    Ok(())
}

pub async fn run_check() -> Result<()> {
    match check_for_update().await? {
        Some(version) => println!(
            "Authenticated Astatine update {version} is available; run `astatine update` to install it."
        ),
        None => println!("Astatine {CURRENT_VERSION} is current for the Testnet release channel."),
    }
    Ok(())
}

pub async fn check_for_update() -> Result<Option<String>> {
    Ok(latest_signed_update()
        .await?
        .map(|(_, manifest)| manifest.version))
}

async fn latest_signed_update() -> Result<Option<(String, UpdateManifest)>> {
    let current = Version::parse(CURRENT_VERSION).context("parse the compiled Astatine version")?;
    let client = http_client()?;
    let releases_api = format!("https://api.github.com/repos/{REPOSITORY}/releases?per_page=50");
    let response = client
        .get(&releases_api)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .context("check the signed Astatine release index")?
        .error_for_status()
        .context("GitHub release index returned an unsuccessful status")?;
    let release_bytes = limited_response(response, MAX_RELEASE_LIST_BYTES)
        .await
        .context("read the bounded GitHub release index")?;
    let releases: Vec<GitHubRelease> =
        serde_json::from_slice(&release_bytes).context("parse the GitHub release index")?;

    let latest = latest_testnet_release(releases, &current);
    let Some((version, tag)) = latest else {
        return Ok(None);
    };
    if tag != format!("v{version}") {
        bail!("GitHub release tag is not the canonical Astatine version tag");
    }

    let manifest_url =
        format!("https://github.com/{REPOSITORY}/releases/download/{tag}/update-manifest.txt");
    let signature_url =
        format!("https://github.com/{REPOSITORY}/releases/download/{tag}/update-manifest.sig");
    let manifest_bytes = get_limited(&client, &manifest_url, MAX_MANIFEST_BYTES)
        .await
        .context("download the candidate release manifest")?;
    let signature = get_limited(&client, &signature_url, SIGNATURE_BYTES)
        .await
        .context("download the candidate release signature")?;
    verify_manifest_signature(&manifest_bytes, &signature)
        .context("authenticate the candidate release manifest")?;
    let manifest =
        parse_manifest(&manifest_bytes).context("validate the signed release manifest")?;
    validate_manifest(&manifest, &tag).context("validate Testnet release identity and assets")?;
    if manifest.version != version.to_string() {
        bail!("signed manifest version differs from its GitHub release tag");
    }
    Ok(Some((tag, manifest)))
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::limited(6))
        .user_agent(concat!("astatine/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("configure authenticated update HTTP client")
}

async fn get_limited(client: &reqwest::Client, url: &str, limit: usize) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("request {url}"))?
        .error_for_status()
        .with_context(|| format!("download from {url}"))?;
    limited_response(response, limit).await
}

async fn limited_response(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("update response exceeds its {} byte size limit", limit);
    }
    let capacity = response
        .content_length()
        .unwrap_or_default()
        .min(limit as u64) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read update response body")?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            bail!("update response exceeds its {} byte size limit", limit);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn download_verified_asset(
    client: &reqwest::Client,
    tag: &str,
    asset: &ManifestAsset,
) -> Result<Vec<u8>> {
    let url = format!(
        "https://github.com/{REPOSITORY}/releases/download/{tag}/{}",
        asset.filename
    );
    let bytes = get_limited(client, &url, MAX_ASSET_BYTES)
        .await
        .with_context(|| format!("download signed release asset {}", asset.filename))?;
    verify_asset_bytes(asset, &bytes)?;
    Ok(bytes)
}

fn verify_asset_bytes(asset: &ManifestAsset, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 != asset.size {
        bail!(
            "release asset {} has an unexpected byte length",
            asset.filename
        );
    }
    let digest = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != asset.sha256 {
        bail!(
            "release asset {} failed its signed SHA-256 check",
            asset.filename
        );
    }
    Ok(())
}

fn latest_testnet_release(
    releases: Vec<GitHubRelease>,
    current: &Version,
) -> Option<(Version, String)> {
    releases
        .into_iter()
        .filter(|release| release.prerelease && !release.draft)
        .filter_map(|release| {
            let version = release.tag_name.strip_prefix('v')?;
            let parsed = parse_supported_testnet_version(version).ok()?;
            let current_base_matches = parsed.major == current.major
                && parsed.minor == current.minor
                && parsed.patch == current.patch;
            (current_base_matches && parsed > *current).then_some((parsed, release.tag_name))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
}

const MAX_SUPPORTED_VERSION_COMPONENT: u64 = i32::MAX as u64;

fn parse_supported_testnet_version(text: &str) -> Result<Version> {
    let version = Version::parse(text).context("Astatine version is not valid SemVer")?;
    if version.major > MAX_SUPPORTED_VERSION_COMPONENT
        || version.minor > MAX_SUPPORTED_VERSION_COMPONENT
        || version.patch > MAX_SUPPORTED_VERSION_COMPONENT
        || !version.build.is_empty()
    {
        bail!("Astatine version is outside the supported numeric SemVer range");
    }
    let identifiers = version.pre.as_str().split('.').collect::<Vec<_>>();
    if identifiers.len() != 2 || identifiers[0] != "testnet" {
        bail!("Astatine prerelease identifier must be exactly testnet.N");
    }
    let sequence = identifiers[1];
    if sequence.is_empty()
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || (sequence.len() > 1 && sequence.starts_with('0'))
    {
        bail!("Astatine Testnet prerelease sequence must be a canonical integer");
    }
    let sequence = sequence
        .parse::<u64>()
        .context("Astatine Testnet prerelease sequence is outside the supported range")?;
    if sequence > MAX_SUPPORTED_VERSION_COMPONENT {
        bail!("Astatine Testnet prerelease sequence is outside the supported range");
    }
    Ok(version)
}

fn parse_executable_version_output(output: &str) -> Result<Version> {
    let line = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    if line.contains('\n') || line.contains('\r') {
        bail!("executable --version output must contain exactly one version line");
    }
    let version = line
        .strip_prefix("astatine ")
        .context("executable --version output must begin with `astatine `")?;
    parse_supported_testnet_version(version)
        .context("executable --version output is malformed or unsupported")
}

fn verify_executable_version_output(output: &str, expected_version: &str) -> Result<()> {
    let actual = parse_executable_version_output(output)?;
    let expected = parse_supported_testnet_version(expected_version)
        .context("signed manifest contains an unsupported Testnet version")?;
    if actual != expected {
        bail!("executable --version output does not match the signed version exactly");
    }
    Ok(())
}

fn verify_manifest_signature(manifest: &[u8], signature: &[u8]) -> Result<()> {
    if signature.len() != SIGNATURE_BYTES {
        bail!("release manifest signature has an invalid length");
    }
    let modulus = STANDARD
        .decode(RSA_MODULUS_BASE64)
        .context("decode pinned release signing modulus")?;
    let exponent = STANDARD
        .decode(RSA_EXPONENT_BASE64)
        .context("decode pinned release signing exponent")?;
    verify_signature_with_key(&modulus, &exponent, manifest, signature)
}

fn parse_manifest(bytes: &[u8]) -> Result<UpdateManifest> {
    let text = std::str::from_utf8(bytes).context("release manifest is not UTF-8")?;
    let mut lines = text.lines();
    if lines.next() != Some("astatine-update-manifest-v1") {
        bail!("release manifest has an unsupported format header");
    }
    let mut fields = BTreeMap::<String, String>::new();
    for (index, line) in lines.enumerate() {
        if line.is_empty() {
            bail!("release manifest contains an empty interior line");
        }
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("release manifest line {} has no key separator", index + 2))?;
        if key.is_empty()
            || value.is_empty()
            || fields.insert(key.to_owned(), value.to_owned()).is_some()
        {
            bail!("release manifest has an empty or duplicate field");
        }
    }
    let repository = fields
        .remove("repository")
        .context("release manifest has no repository identity")?;
    if repository != REPOSITORY {
        bail!("release manifest belongs to a different repository");
    }
    let channel = fields
        .remove("channel")
        .context("release manifest has no release channel")?;
    if channel != "testnet" {
        bail!("release manifest is not for the Testnet channel");
    }
    let version = fields
        .remove("version")
        .context("release manifest has no version")?;
    parse_supported_testnet_version(&version)
        .context("release manifest version is invalid or outside the Testnet channel")?;

    let mut assets = BTreeMap::new();
    for (key, value) in fields {
        let asset_key = key
            .strip_prefix("asset.")
            .with_context(|| format!("release manifest contains an unknown field {key}"))?;
        let mut parts = value.split('|');
        let filename = parts.next().unwrap_or_default();
        let sha256 = parts.next().unwrap_or_default();
        let size_text = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || filename.is_empty()
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("release manifest asset record {asset_key} is malformed");
        }
        let size = size_text
            .parse::<u64>()
            .with_context(|| format!("release manifest asset {asset_key} size is invalid"))?;
        if size == 0 || size > MAX_ASSET_BYTES as u64 {
            bail!("release manifest asset {asset_key} has an unsupported size");
        }
        assets.insert(
            asset_key.to_owned(),
            ManifestAsset {
                filename: filename.to_owned(),
                sha256: sha256.to_owned(),
                size,
            },
        );
    }
    Ok(UpdateManifest { version, assets })
}

fn validate_manifest(manifest: &UpdateManifest, tag: &str) -> Result<()> {
    let expected_version = tag
        .strip_prefix('v')
        .context("release tag has no version prefix")?;
    if manifest.version != expected_version {
        bail!("signed release manifest version does not match its tag");
    }
    parse_supported_testnet_version(&manifest.version)
        .context("signed release manifest version is not a supported Testnet SemVer")?;
    let mut expected_keys = BTreeSet::new();
    for target in TARGETS {
        let binary_key = format!("binary.{target}");
        let binary_name = if target == "windows-x86_64" {
            format!("astatine-{target}.exe")
        } else {
            format!("astatine-{target}")
        };
        validate_expected_asset(manifest, &binary_key, &binary_name)?;
        expected_keys.insert(binary_key);

        let package_key = format!("package.{target}");
        let package_name = if target == "windows-x86_64" {
            format!("astatine-{target}.zip")
        } else {
            format!("astatine-{target}.tar.gz")
        };
        validate_expected_asset(manifest, &package_key, &package_name)?;
        expected_keys.insert(package_key);
    }
    for filename in ["LICENSE-MIT", "THIRD_PARTY_LICENSES.md"] {
        let key = format!("license.{filename}");
        validate_expected_asset(manifest, &key, filename)?;
        expected_keys.insert(key);
    }
    if manifest.assets.keys().cloned().collect::<BTreeSet<_>>() != expected_keys {
        bail!("signed release manifest does not contain exactly the supported assets");
    }
    Ok(())
}

fn validate_expected_asset(manifest: &UpdateManifest, key: &str, filename: &str) -> Result<()> {
    let asset = manifest
        .assets
        .get(key)
        .with_context(|| format!("signed release manifest is missing {key}"))?;
    if asset.filename != filename {
        bail!("signed release manifest has an unexpected filename for {key}");
    }
    Ok(())
}

fn current_target() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return "macos-aarch64";
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return "macos-x86_64";
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return "linux-aarch64";
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return "linux-x86_64";
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return "windows-x86_64";
    }
    #[allow(unreachable_code)]
    "unsupported-platform"
}

fn install_verified_update(
    executable: &Path,
    binary: &[u8],
    mit_license: &[u8],
    third_party_licenses: &[u8],
    expected_version: &str,
) -> Result<bool> {
    if current_target() == "unsupported-platform" {
        bail!("authenticated updates are unavailable for this operating system or architecture");
    }
    let executable_directory = executable
        .parent()
        .context("running executable has no parent directory")?;
    let licenses_directory = executable_directory.join("licenses");
    ensure_real_directory(&licenses_directory)?;
    let mit_license_path = licenses_directory.join("LICENSE-MIT");
    let third_party_license_path = licenses_directory.join("THIRD_PARTY_LICENSES.md");

    let mut replacements = Vec::new();
    for (destination, contents, is_executable, index) in [
        (executable, binary, true, 0),
        (mit_license_path.as_path(), mit_license, false, 1),
        (
            third_party_license_path.as_path(),
            third_party_licenses,
            false,
            2,
        ),
    ] {
        match stage_replacement(destination, contents, is_executable, index) {
            Ok(replacement) => replacements.push(replacement),
            Err(error) => {
                for replacement in &replacements {
                    let _ = fs::remove_file(&replacement.staged);
                }
                return Err(error).context("stage authenticated update files");
            }
        }
    }
    if let Err(error) = smoke_test_binary(&replacements[0].staged, expected_version) {
        for replacement in &replacements {
            let _ = fs::remove_file(&replacement.staged);
        }
        return Err(error);
    }

    #[cfg(unix)]
    {
        install_unix(&replacements, expected_version)?;
        Ok(true)
    }
    #[cfg(windows)]
    {
        install_windows(&replacements, expected_version)?;
        Ok(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("authenticated updates are unavailable on this platform")
    }
}

#[derive(Debug)]
struct StagedReplacement {
    destination: PathBuf,
    staged: PathBuf,
    backup: PathBuf,
    #[cfg(unix)]
    had_original: bool,
}

fn stage_replacement(
    destination: &Path,
    contents: &[u8],
    executable: bool,
    index: usize,
) -> Result<StagedReplacement> {
    let parent = destination
        .parent()
        .context("update target has no parent directory")?;
    ensure_real_directory(parent)?;
    let file_name = destination
        .file_name()
        .context("update target has no file name")?
        .to_string_lossy();
    let pid = std::process::id();
    #[cfg(windows)]
    let staged = parent.join(if executable {
        format!(".{file_name}.update-{pid}-{index}.exe")
    } else {
        format!(".{file_name}.update-{pid}-{index}")
    });
    #[cfg(not(windows))]
    let staged = parent.join(format!(".{file_name}.update-{pid}-{index}"));
    let backup = parent.join(format!(".{file_name}.backup-{pid}-{index}"));
    if staged.exists() || backup.exists() {
        bail!("a previous update attempt left a conflicting staging file");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .with_context(|| format!("create update staging file {}", staged.display()))?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&staged);
        return Err(error).context("write update staging file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &staged,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
        )
        .context("set update staging file permissions")?;
    }
    #[cfg(windows)]
    let _ = executable;

    let had_original = match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_file() && !is_reparse_point(&metadata) => true,
        Ok(_) => bail!("update destination is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect update destination"),
    };
    #[cfg(not(unix))]
    let _ = had_original;
    Ok(StagedReplacement {
        destination: destination.to_owned(),
        staged,
        backup,
        #[cfg(unix)]
        had_original,
    })
}

fn ensure_real_directory(directory: &Path) -> Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() && !is_reparse_point(&metadata) => Ok(()),
        Ok(_) => bail!(
            "update directory is not a real directory: {}",
            directory.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(directory)
                .with_context(|| format!("create update directory {}", directory.display()))?;
            let metadata =
                fs::symlink_metadata(directory).context("verify newly created update directory")?;
            if metadata.is_dir() && !is_reparse_point(&metadata) {
                Ok(())
            } else {
                bail!("update directory was replaced by a non-directory entry")
            }
        }
        Err(error) => Err(error).context("inspect update directory"),
    }
}

#[cfg(unix)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(not(any(unix, windows)))]
fn is_reparse_point(_: &std::fs::Metadata) -> bool {
    false
}

fn smoke_test_binary(path: &Path, expected_version: &str) -> Result<()> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .context("smoke-test the authenticated update before installation")?;
    if !output.status.success() {
        bail!("authenticated update failed its --version smoke test");
    }
    let version_output = String::from_utf8_lossy(&output.stdout);
    verify_executable_version_output(&version_output, expected_version)
        .context("authenticated update reported a malformed or mismatched version")
}

#[cfg(unix)]
fn install_unix(replacements: &[StagedReplacement], expected_version: &str) -> Result<()> {
    let mut backed_up = Vec::<usize>::new();
    let mut replaced = Vec::<usize>::new();
    let result = (|| -> Result<()> {
        for (index, replacement) in replacements.iter().enumerate() {
            if replacement.had_original {
                fs::copy(&replacement.destination, &replacement.backup)
                    .with_context(|| format!("back up {}", replacement.destination.display()))?;
                File::open(&replacement.backup)
                    .context("open update backup")?
                    .sync_all()
                    .context("flush update backup")?;
                backed_up.push(index);
            }
            fs::rename(&replacement.staged, &replacement.destination).with_context(|| {
                format!("atomically replace {}", replacement.destination.display())
            })?;
            replaced.push(index);
        }
        smoke_test_binary(&replacements[0].destination, expected_version)
            .context("installed update failed its rollback-protected smoke test")?;
        Ok(())
    })();

    if let Err(error) = result {
        for index in replaced.into_iter().rev() {
            let replacement = &replacements[index];
            if backed_up.contains(&index) {
                fs::rename(&replacement.backup, &replacement.destination)
                    .with_context(|| format!("roll back {}", replacement.destination.display()))?;
            } else {
                let _ = fs::remove_file(&replacement.destination);
            }
        }
        for index in backed_up {
            let _ = fs::remove_file(&replacements[index].backup);
        }
        for replacement in replacements {
            let _ = fs::remove_file(&replacement.staged);
        }
        return Err(error).context("update failed; the previous installation was restored");
    }

    for index in backed_up {
        if let Err(error) = fs::remove_file(&replacements[index].backup) {
            eprintln!(
                "astatine: update succeeded but backup cleanup failed for {}: {error}",
                replacements[index].backup.display()
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn install_windows(replacements: &[StagedReplacement], expected_version: &str) -> Result<()> {
    let temp = std::env::temp_dir();
    let pid = std::process::id();
    let plan_path = temp.join(format!("astatine-update-{pid}.json"));
    let script_path = temp.join(format!("astatine-update-{pid}.ps1"));
    let log_path = temp.join(format!("astatine-update-{pid}.log"));
    let plan = WindowsUpdatePlan {
        expected_version: expected_version.to_owned(),
        executable: replacements[0].destination.to_string_lossy().into_owned(),
        lock: replacements[0]
            .destination
            .parent()
            .context("Windows update executable has no parent directory")?
            .join(".astatine-update.lock")
            .to_string_lossy()
            .into_owned(),
        log: log_path.to_string_lossy().into_owned(),
        files: replacements
            .iter()
            .map(|replacement| WindowsUpdateFile {
                destination: replacement.destination.to_string_lossy().into_owned(),
                staged: replacement.staged.to_string_lossy().into_owned(),
                backup: replacement.backup.to_string_lossy().into_owned(),
            })
            .collect(),
    };
    write_new_file(&plan_path, &serde_json::to_vec(&plan)?)?;
    if let Err(error) = write_new_file(
        &script_path,
        include_bytes!("../support/update-windows.ps1"),
    ) {
        let _ = fs::remove_file(&plan_path);
        for replacement in replacements {
            let _ = fs::remove_file(&replacement.staged);
        }
        return Err(error).context("write Windows update helper");
    }
    let spawned = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script_path)
        .arg("-ParentPid")
        .arg(pid.to_string())
        .arg("-PlanPath")
        .arg(&plan_path)
        .spawn();
    if let Err(error) = spawned {
        for replacement in replacements {
            let _ = fs::remove_file(&replacement.staged);
        }
        let _ = fs::remove_file(plan_path);
        let _ = fs::remove_file(script_path);
        return Err(error).context("start the Windows rollback-protected update helper");
    }
    println!(
        "The verified update is staged. The Windows helper will replace the executable after this process exits; diagnostics: {}",
        log_path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write {}", path.display()))
}

fn verify_signature_with_key(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    RsaPublicKeyComponents { n, e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
        .map_err(|_| anyhow::anyhow!("release manifest signature is invalid"))
}

#[cfg(test)]
mod tests {
    use super::{
        GitHubRelease, ManifestAsset, REPOSITORY, UpdateLock, latest_testnet_release,
        parse_executable_version_output, parse_manifest, parse_supported_testnet_version,
        validate_manifest, verify_asset_bytes, verify_executable_version_output,
        verify_signature_with_key,
    };
    #[cfg(unix)]
    use super::{smoke_test_binary, stage_replacement};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::Digest;
    use std::collections::BTreeMap;

    fn manifest_assets() -> BTreeMap<String, ManifestAsset> {
        let mut assets = BTreeMap::new();
        for target in [
            "macos-aarch64",
            "macos-x86_64",
            "linux-aarch64",
            "linux-x86_64",
            "windows-x86_64",
        ] {
            let binary = if target == "windows-x86_64" {
                format!("astatine-{target}.exe")
            } else {
                format!("astatine-{target}")
            };
            assets.insert(
                format!("binary.{target}"),
                ManifestAsset {
                    filename: binary,
                    sha256: "a".repeat(64),
                    size: 1,
                },
            );
            let package = if target == "windows-x86_64" {
                format!("astatine-{target}.zip")
            } else {
                format!("astatine-{target}.tar.gz")
            };
            assets.insert(
                format!("package.{target}"),
                ManifestAsset {
                    filename: package,
                    sha256: "b".repeat(64),
                    size: 1,
                },
            );
        }
        for filename in ["LICENSE-MIT", "THIRD_PARTY_LICENSES.md"] {
            assets.insert(
                format!("license.{filename}"),
                ManifestAsset {
                    filename: filename.to_owned(),
                    sha256: "c".repeat(64),
                    size: 1,
                },
            );
        }
        assets
    }

    fn manifest_text() -> String {
        let mut text = format!(
            "astatine-update-manifest-v1\nrepository={REPOSITORY}\nchannel=testnet\nversion=0.1.0-testnet.9\n"
        );
        for (key, asset) in manifest_assets() {
            text.push_str(&format!(
                "asset.{key}={}|{}|{}\n",
                asset.filename, asset.sha256, asset.size
            ));
        }
        text
    }

    #[test]
    fn signed_manifest_parser_and_asset_policy_are_strict() {
        let manifest = parse_manifest(manifest_text().as_bytes()).unwrap();
        validate_manifest(&manifest, "v0.1.0-testnet.9").unwrap();
        assert_eq!(manifest.assets.len(), 12);

        let mut bad = manifest_text();
        bad.push_str("asset.binary.linux-x86_64=other|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|1\n");
        assert!(parse_manifest(bad.as_bytes()).is_err());

        let mut bad = manifest_text();
        bad.push_str("unexpected=value\n");
        assert!(parse_manifest(bad.as_bytes()).is_err());

        let mut bad = manifest_text();
        bad = bad.replace("channel=testnet", "channel=mainnet");
        assert!(parse_manifest(bad.as_bytes()).is_err());

        let bad_versions = [
            "0.1.0-testnet.foo",
            "0.1.0-testnet.13.extra",
            "0.1.0-testnet.013",
            "0.1.0+build.1",
            "2147483648.0.0-testnet.1",
            "0.1.0-testnet.2147483648",
        ];
        for version in bad_versions {
            let bad = manifest_text().replace("0.1.0-testnet.9", version);
            assert!(parse_manifest(bad.as_bytes()).is_err(), "{version}");
        }
    }

    #[test]
    fn rsa_verification_rejects_changed_manifest_bytes() {
        const TEST_N: &str = "wj5E3bq8XxdECPjXRhO1JfJp1clvJ+oM209/IytsJOOHfsCDPS/qsbLsUMF+v5ReQ3t2MFDaUpLD+I2y0ZDYNrrRK12NrUk/eyEafNRfslersXOLeGYgYf74ei7aVQJIRLdFqwUoOoMJWxFNQo1RnllVEPpDJA9ndt3MRbeTUgmuW7dXAftDZvzvE+WFNVaQ7zx7/GMCrUEuFtrMNRy5ewy8cWRLq/MSsiwUFhQsDmpkZQOlZJYuDsqplc463fP8RuQTQuMtK08S/uKWTqGBD4AMkagDXdLnGLWqtoI96ffoB/ndsHfs4Ou6xCoUvFK74BnamtrwUdR9PA+dmUNBOw==";
        const TEST_E: &str = "AQAB";
        const TEST_MESSAGE: &[u8] = b"astatine signed release test vector";
        let test_signature = STANDARD
            .decode("UzFAPx2lyjysZqYj/ucn2mRlzpr7K/PoQx8xiRfLFl0z/ut1b0BSLsLnyYS8KDKR/21bhFCpN8f03j2pchaX62omJ8kckovK1x5nxlQ93AJnrRpODOohiAzUhcvbW+BIQU89KwI8zljWjc8QFuYWWgNDgaHr1ujB6UEZrOfOCO+hReAFd978aT787AUwC3EVO7hVSEAWFT71vyJenS/iLu9PBszbG0HYMttaluxCwor1ihZYjOSZiA0q2XChFGgTI30jpkllsKKjGJKFMb0AKmijnn3AvFcEnpWrGfi8+IWRT8VylddzoV2mvjj9UIsS2lgqxXX1ZUgfXfLK5XfdFA==")
            .unwrap();
        let n = STANDARD.decode(TEST_N).unwrap();
        let e = STANDARD.decode(TEST_E).unwrap();
        assert!(verify_signature_with_key(&n, &e, TEST_MESSAGE, &test_signature).is_ok());
        assert!(verify_signature_with_key(&n, &e, b"tampered release", &test_signature).is_err());
    }

    #[test]
    fn selects_highest_compatible_numeric_testnet_prerelease() {
        let current = semver::Version::parse("0.1.0-testnet.12").unwrap();
        let releases = vec![
            GitHubRelease {
                tag_name: "v0.1.0-testnet.8".to_owned(),
                prerelease: true,
                draft: false,
            },
            GitHubRelease {
                tag_name: "v0.1.0-testnet.10".to_owned(),
                prerelease: true,
                draft: false,
            },
            GitHubRelease {
                tag_name: "v0.1.0-testnet.11".to_owned(),
                prerelease: true,
                draft: false,
            },
            GitHubRelease {
                tag_name: "v0.1.0-testnet.12".to_owned(),
                prerelease: true,
                draft: false,
            },
            GitHubRelease {
                tag_name: "v0.1.0-testnet.13".to_owned(),
                prerelease: true,
                draft: false,
            },
            GitHubRelease {
                tag_name: "v0.2.0-testnet.10".to_owned(),
                prerelease: true,
                draft: false,
            },
            GitHubRelease {
                tag_name: "v0.1.0".to_owned(),
                prerelease: false,
                draft: false,
            },
        ];
        assert_eq!(
            latest_testnet_release(releases, &current),
            Some((
                semver::Version::parse("0.1.0-testnet.13").unwrap(),
                "v0.1.0-testnet.13".to_owned(),
            ))
        );
    }

    #[test]
    fn rust_updater_only_selects_canonical_numeric_testnet_versions() {
        let current = semver::Version::parse("0.1.0-testnet.13").unwrap();
        let releases = [
            ("v0.1.0-testnet.13", true),
            ("v0.1.0-testnet.130", true),
            ("v0.1.0-testnet.foo", true),
            ("v0.1.0-testnet.13.extra", true),
            ("v0.1.0-testnet.013", true),
            ("v0.1.0+build.1", true),
            ("v0.1.1-testnet.1", false),
        ]
        .into_iter()
        .map(|(tag_name, prerelease)| GitHubRelease {
            tag_name: tag_name.to_owned(),
            prerelease,
            draft: false,
        })
        .collect();
        assert_eq!(
            latest_testnet_release(releases, &current),
            Some((
                semver::Version::parse("0.1.0-testnet.130").unwrap(),
                "v0.1.0-testnet.130".to_owned()
            ))
        );
        for invalid in [
            "0.1.0-testnet.foo",
            "0.1.0-testnet.13.extra",
            "0.1.0-testnet.013",
        ] {
            assert!(
                parse_supported_testnet_version(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn executable_version_output_must_be_one_exact_supported_version() {
        let expected = semver::Version::parse("0.1.0-testnet.13").unwrap();
        for output in [
            "astatine 0.1.0-testnet.13\n",
            "astatine 0.1.0-testnet.13\r\n",
        ] {
            assert_eq!(parse_executable_version_output(output).unwrap(), expected);
            assert!(verify_executable_version_output(output, "0.1.0-testnet.13").is_ok());
        }
        for output in [
            "astatine 0.1.0-testnet.130\n",
            "astatine 0.1.0-testnet.12\n",
        ] {
            assert!(parse_executable_version_output(output).is_ok());
            assert!(
                verify_executable_version_output(output, "0.1.0-testnet.13").is_err(),
                "{output:?} must not match .13"
            );
        }
        for output in [
            "0.1.0-testnet.13\n",
            "astatine 0.1.0-testnet.foo\n",
            "astatine 0.1.0-testnet.13 \n",
            "astatine 0.1.0-testnet.13\nextra output\n",
            "astatine 0.1.0-testnet.13\n\n",
            "not an Astatine version\n",
        ] {
            assert!(
                parse_executable_version_output(output).is_err(),
                "{output:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_binary_smoke_rejects_substrings_malformed_output_and_extra_lines() {
        use std::{fs, os::unix::fs::PermissionsExt};
        use tempfile::tempdir;

        let directory = tempdir().unwrap();
        let executable = directory.path().join("astatine");
        for (output, expected_to_pass) in [
            ("astatine 0.1.0-testnet.13\n", true),
            ("astatine 0.1.0-testnet.130\n", false),
            ("astatine 0.1.0-testnet.foo\n", false),
            ("astatine 0.1.0-testnet.12\n", false),
            ("astatine 0.1.0-testnet.13\nextra output\n", false),
            ("malformed version output\n", false),
        ] {
            fs::write(&executable, format!("#!/bin/sh\nprintf '%s' '{output}'\n")).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                smoke_test_binary(&executable, "0.1.0-testnet.13").is_ok(),
                expected_to_pass,
                "version output: {output:?}"
            );
        }
    }

    #[test]
    fn signed_asset_digest_and_length_must_both_match() {
        let contents = b"release executable";
        let digest = super::Sha256::digest(contents)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let asset = ManifestAsset {
            filename: "astatine-linux-x86_64".to_owned(),
            sha256: digest,
            size: contents.len() as u64,
        };
        assert!(verify_asset_bytes(&asset, contents).is_ok());
        assert!(verify_asset_bytes(&asset, b"modified executable").is_err());
        assert!(
            verify_asset_bytes(
                &ManifestAsset {
                    size: asset.size + 1,
                    ..asset.clone()
                },
                contents
            )
            .is_err()
        );
    }

    #[test]
    fn update_lock_excludes_parallel_installs_and_recovers_after_owner_exits() {
        use tempfile::tempdir;

        let directory = tempdir().unwrap();
        let lock = UpdateLock::acquire(directory.path()).unwrap();
        assert!(UpdateLock::acquire(directory.path()).is_err());
        drop(lock);
        assert!(UpdateLock::acquire(directory.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn unix_update_rolls_back_binary_and_license_files_after_failed_smoke_test() {
        use super::install_unix;
        use std::{fs, os::unix::fs::PermissionsExt};
        use tempfile::tempdir;

        let directory = tempdir().unwrap();
        let executable = directory.path().join("astatine");
        let licenses = directory.path().join("licenses");
        fs::create_dir(&licenses).unwrap();
        fs::write(
            &executable,
            b"#!/bin/sh\nprintf '%s\\n' 'astatine 0.1.0-testnet.8'\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(licenses.join("LICENSE-MIT"), b"old MIT\n").unwrap();
        fs::write(
            licenses.join("THIRD_PARTY_LICENSES.md"),
            b"old third-party\n",
        )
        .unwrap();

        let replacements = [
            stage_replacement(&executable, b"#!/bin/sh\nexit 1\n", true, 0).unwrap(),
            stage_replacement(&licenses.join("LICENSE-MIT"), b"new MIT\n", false, 1).unwrap(),
            stage_replacement(
                &licenses.join("THIRD_PARTY_LICENSES.md"),
                b"new third-party\n",
                false,
                2,
            )
            .unwrap(),
        ];
        assert!(install_unix(&replacements, "0.1.0-testnet.9").is_err());
        assert!(
            fs::read_to_string(executable)
                .unwrap()
                .contains("testnet.8")
        );
        assert_eq!(
            fs::read(licenses.join("LICENSE-MIT")).unwrap(),
            b"old MIT\n"
        );
        assert_eq!(
            fs::read(licenses.join("THIRD_PARTY_LICENSES.md")).unwrap(),
            b"old third-party\n"
        );
        assert!(!replacements[0].backup.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_update_replaces_executable_and_notices_after_smoke_test() {
        use super::install_unix;
        use std::{fs, os::unix::fs::PermissionsExt};
        use tempfile::tempdir;

        let directory = tempdir().unwrap();
        let executable = directory.path().join("astatine");
        let licenses = directory.path().join("licenses");
        fs::create_dir(&licenses).unwrap();
        fs::write(
            &executable,
            b"#!/bin/sh\nprintf '%s\\n' 'astatine 0.1.0-testnet.8'\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(licenses.join("LICENSE-MIT"), b"old MIT\n").unwrap();
        fs::write(
            licenses.join("THIRD_PARTY_LICENSES.md"),
            b"old third-party\n",
        )
        .unwrap();

        let replacements = [
            stage_replacement(
                &executable,
                b"#!/bin/sh\nprintf '%s\\n' 'astatine 0.1.0-testnet.9'\n",
                true,
                0,
            )
            .unwrap(),
            stage_replacement(&licenses.join("LICENSE-MIT"), b"new MIT\n", false, 1).unwrap(),
            stage_replacement(
                &licenses.join("THIRD_PARTY_LICENSES.md"),
                b"new third-party\n",
                false,
                2,
            )
            .unwrap(),
        ];
        install_unix(&replacements, "0.1.0-testnet.9").unwrap();
        assert!(
            fs::read_to_string(executable)
                .unwrap()
                .contains("testnet.9")
        );
        assert_eq!(
            fs::read(licenses.join("LICENSE-MIT")).unwrap(),
            b"new MIT\n"
        );
        assert_eq!(
            fs::read(licenses.join("THIRD_PARTY_LICENSES.md")).unwrap(),
            b"new third-party\n"
        );
        assert!(!replacements[0].backup.exists());
    }
}
