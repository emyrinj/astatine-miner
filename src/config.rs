use crate::cli::Network;
use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::{Deserialize, Serialize};
#[cfg(any(unix, windows))]
use std::fs::File;
use std::{
    env, fs,
    fs::OpenOptions,
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};
use tempfile::{NamedTempFile, PersistError};

const CONFIG_FILE: &str = "config.toml";
const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;
const MAX_TRANSACTION_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRANSACTION_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024;
const WEI_PER_INJ: u128 = 1_000_000_000_000_000_000;
const DEFAULT_TRANSACTION_CONFIRMATIONS: u8 = 2;
const MAX_TRANSACTION_CONFIRMATIONS: u8 = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u32,
    pub network: Network,
    pub wallet_address: Option<String>,
    pub cpu_threads: usize,
    pub minimum_reserve_inj: String,
    pub per_session_spending_limit_inj: String,
    #[serde(default)]
    pub testnet_rpc: Option<String>,
    #[serde(default)]
    pub mainnet_rpc: Option<String>,
    #[serde(default = "default_transaction_confirmations")]
    pub transaction_confirmations: u8,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            network: Network::Testnet,
            wallet_address: None,
            cpu_threads: conservative_thread_budget(),
            minimum_reserve_inj: "0.1".to_owned(),
            per_session_spending_limit_inj: "0".to_owned(),
            testnet_rpc: None,
            mainnet_rpc: None,
            transaction_confirmations: DEFAULT_TRANSACTION_CONFIRMATIONS,
        }
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!(
                "unsupported configuration schema version {}",
                self.schema_version
            );
        }
        if !(1..=256).contains(&self.cpu_threads) {
            bail!("CPU thread budget must be in the range 1..=256");
        }
        parse_inj_wei(&self.minimum_reserve_inj)
            .context("minimum reserve must be a decimal INJ amount with at most 18 decimals")?;
        parse_inj_wei(&self.per_session_spending_limit_inj)
            .context("spending limit must be a decimal INJ amount with at most 18 decimals")?;
        if !(1..=MAX_TRANSACTION_CONFIRMATIONS).contains(&self.transaction_confirmations) {
            bail!(
                "transaction confirmation threshold must be within 1..={MAX_TRANSACTION_CONFIRMATIONS} blocks"
            );
        }
        if let Some(address) = &self.wallet_address {
            Address::from_str(address).context("configured wallet address is invalid")?;
        }
        if let Some(rpc) = &self.testnet_rpc {
            validate_rpc_url(rpc).context("Testnet RPC override is invalid")?;
        }
        if let Some(rpc) = &self.mainnet_rpc {
            validate_rpc_url(rpc).context("Mainnet RPC override is invalid")?;
        }
        Ok(())
    }

    pub fn rpc_override(&self, network: Network) -> Option<&str> {
        match network {
            Network::Testnet => self.testnet_rpc.as_deref(),
            Network::Mainnet => self.mainnet_rpc.as_deref(),
        }
    }

    pub fn set_rpc_override(&mut self, network: Network, rpc: Option<String>) {
        match network {
            Network::Testnet => self.testnet_rpc = rpc,
            Network::Mainnet => self.mainnet_rpc = rpc,
        }
    }
}

pub fn validate_rpc_url(endpoint: &str) -> Result<Url> {
    if endpoint.is_empty() || endpoint.len() > 4096 {
        bail!("RPC URL is empty or exceeds the supported length");
    }
    let url = Url::parse(endpoint).context("parse RPC URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("RPC URL must not embed username or password credentials");
    }
    if url.fragment().is_some() {
        bail!("RPC URL must not contain a fragment");
    }
    let host = url.host_str().context("RPC URL must include a host")?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        "http" => bail!("remote RPC endpoints must use HTTPS"),
        _ => bail!("RPC URL scheme must be HTTP or HTTPS"),
    }
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn default_transaction_confirmations() -> u8 {
    DEFAULT_TRANSACTION_CONFIRMATIONS
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    root: PathBuf,
}

impl ConfigStore {
    pub fn system_default() -> Result<Self> {
        Ok(Self {
            root: system_config_dir()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn at_root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn wallet_dir(&self) -> PathBuf {
        self.root.join("wallets")
    }

    pub fn prepare_wallet_dir(&self) -> Result<PathBuf> {
        ensure_private_directory(&self.root)?;
        let directory = self.wallet_dir();
        ensure_private_directory(&directory)?;
        Ok(directory)
    }

    pub fn load(&self) -> Result<AppConfig> {
        let path = self.root.join(CONFIG_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AppConfig::default());
            }
            Err(error) => return Err(error).context("inspect configuration file"),
        }
        ensure_private_directory(&self.root)?;
        let text = String::from_utf8(read_regular_limited(&path, MAX_CONFIG_BYTES, true)?)
            .context("configuration file is not valid UTF-8")?;
        let config: AppConfig = toml::from_str(&text).context("parse configuration file")?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, config: &AppConfig) -> Result<()> {
        config.validate()?;
        ensure_private_directory(&self.root)?;
        let mut text = toml::to_string_pretty(config).context("serialize configuration")?;
        text.push('\n');
        atomic_write(&self.root.join(CONFIG_FILE), text.as_bytes(), true)
            .context("atomically write configuration")
    }

    pub fn keystore_path(&self, address: Address) -> PathBuf {
        self.wallet_dir()
            .join(format!("{:#x}.json", address).to_ascii_lowercase())
    }

    pub fn read_keystore(&self, address: Address) -> Result<Vec<u8>> {
        let path = self.keystore_path(address);
        ensure_private_directory(&self.root)?;
        ensure_private_directory(&self.wallet_dir())?;
        let contents = read_regular_limited(&path, MAX_KEYSTORE_BYTES, true)
            .context("read encrypted wallet file")?;
        if contents.is_empty() {
            bail!("wallet file is empty");
        }
        Ok(contents)
    }

    pub fn store_keystore(&self, address: Address, data: &[u8]) -> Result<PathBuf> {
        if data.is_empty() || data.len() as u64 > MAX_KEYSTORE_BYTES {
            bail!("encrypted wallet file is empty or exceeds the supported size limit");
        }
        self.prepare_wallet_dir()?;
        let path = self.keystore_path(address);
        atomic_write(&path, data, false).context("atomically store encrypted wallet")?;
        Ok(path)
    }

    pub(crate) fn read_transaction_journal(&self) -> Result<Option<Vec<u8>>> {
        let path = self.transaction_journal_path()?;
        match fs::symlink_metadata(&path) {
            Ok(_) => read_regular_limited(&path, MAX_TRANSACTION_JOURNAL_BYTES, true)
                .map(Some)
                .context("read private transaction journal"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("inspect private transaction journal"),
        }
    }

    pub(crate) fn write_transaction_journal(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() as u64 > MAX_TRANSACTION_JOURNAL_BYTES {
            bail!("transaction journal is empty or exceeds its 8 MiB size limit");
        }
        let path = self.transaction_journal_path()?;
        atomic_write(&path, data, true).context("atomically write private transaction journal")
    }

    pub(crate) fn write_transaction_archive(&self, name: &str, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() as u64 > MAX_TRANSACTION_ARCHIVE_BYTES {
            bail!("transaction archive is empty or exceeds its 8 MiB size limit");
        }
        let path = self.transaction_archive_path(name)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let existing = read_regular_limited(&path, MAX_TRANSACTION_ARCHIVE_BYTES, true)?;
                if existing != data {
                    bail!("transaction archive identifier already exists with different contents");
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_write(&path, data, false)
                    .context("atomically create private transaction archive")
            }
            Err(error) => Err(error).context("inspect private transaction archive"),
        }
    }

    pub(crate) fn read_transaction_archive(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.transaction_archive_path(name)?;
        read_regular_limited(&path, MAX_TRANSACTION_ARCHIVE_BYTES, true)
            .context("read private transaction archive")
    }

    pub(crate) fn lock_transaction_journal(&self) -> Result<File> {
        let path = self
            .transaction_journal_path()?
            .with_file_name("miner.lock");
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
        let file = options
            .open(&path)
            .context("open transaction journal lock")?;
        let metadata = file
            .metadata()
            .context("inspect transaction journal lock")?;
        if !metadata.is_file() {
            bail!("transaction journal lock is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .context("restrict transaction journal lock permissions")?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                bail!("transaction journal lock is a reparse point");
            }
        }
        file.try_lock()
            .context("another astatine mining process already holds the transaction journal")?;
        Ok(file)
    }

    fn transaction_journal_path(&self) -> Result<PathBuf> {
        ensure_private_directory(&self.root)?;
        let directory = self.root.join("transactions");
        ensure_private_directory(&directory)?;
        Ok(directory.join("journal.json"))
    }

    fn transaction_archive_path(&self, name: &str) -> Result<PathBuf> {
        if !name.starts_with("archive-")
            || !name.ends_with(".json")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            bail!("transaction archive name is invalid");
        }
        ensure_private_directory(&self.root)?;
        let transaction_dir = self.root.join("transactions");
        ensure_private_directory(&transaction_dir)?;
        let directory = transaction_dir.join("archives");
        ensure_private_directory(&directory)?;
        Ok(directory.join(name))
    }
}

fn system_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        windows_config_dir(env::var_os("APPDATA").as_deref())
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").filter(|value| !value.is_empty());
        let home =
            home.context("HOME is not set; cannot locate the user configuration directory")?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Astatine"))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        xdg_config_dir(
            env::var_os("XDG_CONFIG_HOME").as_deref(),
            env::var_os("HOME").as_deref(),
        )
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let home = env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .filter(|value| !value.is_empty());
        let home = home.context("home directory is not set; cannot locate configuration")?;
        Ok(PathBuf::from(home).join(".astatine"))
    }
}

#[cfg(target_os = "windows")]
fn windows_config_dir(app_data: Option<&std::ffi::OsStr>) -> Result<PathBuf> {
    let app_data = app_data
        .filter(|value| !value.is_empty())
        .context("APPDATA is not set; cannot locate the user configuration directory")?;
    let app_data = PathBuf::from(app_data);
    if !app_data.is_absolute() {
        bail!("APPDATA must be an absolute user configuration directory");
    }
    Ok(app_data.join("Astatine"))
}

#[cfg(all(unix, any(not(target_os = "macos"), test)))]
fn xdg_config_dir(
    config_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    if let Some(config_home) = config_home.filter(|value| !value.is_empty()) {
        let config_home = PathBuf::from(config_home);
        if config_home.is_absolute() {
            return Ok(config_home.join("astatine"));
        }
    }
    let home = home
        .filter(|value| !value.is_empty())
        .context("HOME is not set; cannot locate the user configuration directory")?;
    Ok(PathBuf::from(home).join(".config").join("astatine"))
}

pub fn conservative_thread_budget() -> usize {
    std::thread::available_parallelism()
        .map(|available| (available.get() / 2).clamp(1, 256))
        .unwrap_or(1)
}

/// Parse a finite, non-negative decimal INJ amount without floating-point rounding.
pub fn parse_inj_wei(amount: &str) -> Result<U256> {
    if amount.is_empty() || amount.starts_with(['+', '-']) || amount.trim() != amount {
        bail!("invalid decimal amount");
    }
    let mut parts = amount.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 18
    {
        bail!("invalid decimal amount");
    }
    let whole = U256::from_str(whole).context("whole INJ amount is out of range")?;
    let mut fractional_padded = fractional.to_owned();
    fractional_padded.extend(std::iter::repeat_n('0', 18 - fractional.len()));
    let fractional = if fractional_padded.is_empty() {
        U256::ZERO
    } else {
        U256::from_str(&fractional_padded).context("fractional INJ amount is invalid")?
    };
    whole
        .checked_mul(U256::from(WEI_PER_INJ))
        .and_then(|base| base.checked_add(fractional))
        .context("INJ amount is out of range")
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(path).context("create private storage directory")?;
        }
        Err(error) => return Err(error).context("inspect private storage directory"),
    }
    let metadata = fs::symlink_metadata(path).context("recheck sensitive storage directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("sensitive storage path is not a real directory; refusing to follow it");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            bail!("sensitive storage path is a Windows reparse point; refusing to follow it");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("open sensitive storage directory without following symlinks")?;
        if !directory
            .metadata()
            .context("inspect opened storage directory")?
            .is_dir()
        {
            bail!("sensitive storage path changed and is no longer a directory");
        }
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .context("restrict private storage directory permissions")?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
    };

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !windows_reparse_point(&metadata) => return Ok(()),
        Ok(_) => return Err(std::io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() && !windows_reparse_point(&metadata) => {}
            Ok(_) => return Err(std::io::ErrorKind::NotADirectory.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(parent)?;
            }
            Err(error) => return Err(error),
        }
    }

    struct LocalDescriptor(*mut core::ffi::c_void);
    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    // Set the protected DACL atomically at creation; standard users cannot
    // reliably rewrite an inherited DACL after creating a directory.
    let security_sddl = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            security_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = LocalDescriptor(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(windows)]
fn windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

/// Read a regular file through a no-follow handle and enforce a hard size limit.
pub(crate) fn read_regular_limited(
    path: &Path,
    maximum: u64,
    restrict_windows_permissions: bool,
) -> Result<Vec<u8>> {
    let file = open_regular_file(path, restrict_windows_permissions)?;
    let metadata = file.metadata().context("inspect opened file")?;
    if metadata.len() > maximum {
        bail!("file exceeds the supported size limit");
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut contents)
        .context("read opened file")?;
    if contents.len() as u64 > maximum {
        bail!("file exceeds the supported size limit");
    }
    Ok(contents)
}

fn open_regular_file(path: &Path, _restrict_windows_permissions: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .context("open regular file without following links")?;
    let metadata = file.metadata().context("inspect opened file")?;
    if !metadata.is_file() {
        bail!("path is not a regular file; refusing to follow it");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            bail!("path is a Windows reparse point; refusing to follow it");
        }
    }
    Ok(file)
}

fn atomic_write(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("destination has no parent directory")?;
    ensure_private_directory(parent)?;
    let mut temporary = NamedTempFile::new_in(parent).context("create private temporary file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("restrict temporary file permissions")?;
    }
    temporary.write_all(data).context("write staged file")?;
    temporary
        .as_file()
        .sync_all()
        .context("flush staged file")?;
    if replace {
        persist_replace(temporary, path)?;
    } else {
        persist_create(temporary, path)?;
    }
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("flush containing directory")?;
    Ok(())
}

fn persist_replace(file: NamedTempFile, path: &Path) -> Result<()> {
    file.persist(path)
        .map(|_| ())
        .map_err(|error| persist_error(error, "replace destination"))
}

fn persist_create(file: NamedTempFile, path: &Path) -> Result<()> {
    file.persist_noclobber(path)
        .map(|_| ())
        .map_err(|error| persist_error(error, "create destination"))
}

fn persist_error(error: PersistError, operation: &str) -> anyhow::Error {
    anyhow::Error::new(error.error).context(format!("cannot {operation} atomically"))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::read_regular_limited;
    #[cfg(windows)]
    use super::windows_config_dir;
    #[cfg(unix)]
    use super::xdg_config_dir;
    use super::{AppConfig, ConfigStore, parse_inj_wei, validate_rpc_url};
    use crate::cli::Network;
    use alloy_primitives::U256;
    use std::{ffi::OsStr, path::PathBuf};

    #[test]
    fn decimal_inj_conversion_is_exact() {
        assert_eq!(
            parse_inj_wei("0.1").unwrap(),
            U256::from(100_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_inj_wei("2").unwrap(),
            U256::from(2_000_000_000_000_000_000u128)
        );
        assert_eq!(
            parse_inj_wei("0.000000000000000001").unwrap(),
            U256::from(1)
        );
        assert!(parse_inj_wei("0.0000000000000000001").is_err());
        assert!(parse_inj_wei("1e-3").is_err());
    }

    #[test]
    fn confirmation_threshold_defaults_and_is_bounded() {
        let config = AppConfig::default();
        assert_eq!(config.transaction_confirmations, 2);
        assert!(config.validate().is_ok());
        let invalid = AppConfig {
            transaction_confirmations: 13,
            ..config
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn legacy_config_and_network_scoped_rpc_overrides_are_backward_compatible() {
        let legacy: AppConfig = toml::from_str(
            r#"
schema_version = 1
network = "testnet"
wallet_address = "0x0000000000000000000000000000000000000001"
cpu_threads = 2
minimum_reserve_inj = "0.1"
per_session_spending_limit_inj = "0"
transaction_confirmations = 2
"#,
        )
        .unwrap();
        assert_eq!(legacy.rpc_override(Network::Testnet), None);
        assert_eq!(legacy.rpc_override(Network::Mainnet), None);

        let temporary = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(temporary.path().join("config"));
        let mut config = AppConfig::default();
        config.set_rpc_override(
            Network::Testnet,
            Some("https://rpc.test.example/v1/private-token?key=secret".to_owned()),
        );
        store.save(&config).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.rpc_override(Network::Testnet),
            Some("https://rpc.test.example/v1/private-token?key=secret")
        );
        assert_eq!(loaded.rpc_override(Network::Mainnet), None);
    }

    #[test]
    fn rpc_url_transport_and_credential_rules_allow_only_local_http() {
        for url in [
            "https://rpc.example.org/evm",
            "http://localhost:8545",
            "http://127.0.0.1:8545",
            "http://[::1]:8545",
        ] {
            assert!(validate_rpc_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://rpc.example.org/evm",
            "ftp://rpc.example.org/evm",
            "https://user:pass@rpc.example.org/evm",
            "https://rpc.example.org/evm#fragment",
            "not a URL",
        ] {
            let error = validate_rpc_url(url).unwrap_err();
            assert!(
                !format!("{error:#}").contains(url),
                "RPC validation errors must not echo URL tokens"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn linux_config_directory_obeys_xdg_and_falls_back_for_relative_values() {
        assert_eq!(
            xdg_config_dir(
                Some(OsStr::new("/tmp/xdg-config")),
                Some(OsStr::new("/home/miner")),
            )
            .unwrap(),
            PathBuf::from("/tmp/xdg-config/astatine")
        );
        assert_eq!(
            xdg_config_dir(
                Some(OsStr::new("relative-config")),
                Some(OsStr::new("/home/miner")),
            )
            .unwrap(),
            PathBuf::from("/home/miner/.config/astatine")
        );
        assert!(xdg_config_dir(None, None).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_config_directory_requires_appdata() {
        assert!(windows_config_dir(None).is_err());
        assert!(windows_config_dir(Some(OsStr::new(""))).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_config_directory_uses_appdata_and_private_storage_handles_unicode_paths() {
        let app_data = OsStr::new(r"C:\Users\miner\AppData\Roaming");
        assert_eq!(
            windows_config_dir(Some(app_data)).unwrap(),
            PathBuf::from(r"C:\Users\miner\AppData\Roaming\Astatine")
        );

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("Astatine ü data");
        let store = ConfigStore::at_root(root);
        let config = AppConfig {
            network: Network::Testnet,
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        assert_eq!(store.load().unwrap(), config);

        let address = alloy_primitives::Address::with_last_byte(0x42);
        store
            .store_keystore(address, b"private-keystore-bytes")
            .unwrap();
        assert_eq!(
            store.read_keystore(address).unwrap(),
            b"private-keystore-bytes"
        );

        let first_lock = store.lock_transaction_journal().unwrap();
        assert!(store.lock_transaction_journal().is_err());
        drop(first_lock);
        assert!(store.lock_transaction_journal().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_storage_roots_are_rejected() {
        use std::process::Command;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        let junction = temporary.path().join("private-root-junction");
        std::fs::create_dir(&target).unwrap();
        let result = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "could not create test junction: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            ConfigStore::at_root(junction)
                .save(&AppConfig::default())
                .is_err()
        );
    }

    #[test]
    fn config_round_trip_preserves_wallet_when_network_changes() {
        let root =
            std::env::temp_dir().join(format!("astatine-config-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = ConfigStore::at_root(PathBuf::from(&root));
        let mut config = AppConfig {
            wallet_address: Some("0x0000000000000000000000000000000000000001".to_owned()),
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(root.join("config.toml"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        config.network = Network::Mainnet;
        store.save(&config).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.network, Network::Mainnet);
        assert_eq!(loaded.wallet_address, config.wallet_address);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_file_reads_do_not_follow_symlinks() {
        let root =
            std::env::temp_dir().join(format!("astatine-symlink-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target.json");
        let symlink = root.join("wallet.json");
        std::fs::write(&target, b"encrypted test data").unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        assert!(read_regular_limited(&symlink, 1_024, false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_storage_root_does_not_follow_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        let linked_root = temporary.path().join("linked-root");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &linked_root).unwrap();

        let store = ConfigStore::at_root(linked_root);
        assert!(store.prepare_wallet_dir().is_err());
        assert!(!target.join("wallets").exists());
    }
}
