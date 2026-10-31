use crate::{
    cli::ImportArgs,
    config::{AppConfig, ConfigStore, read_regular_limited},
    startup::StartupProgress,
};
use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher},
};
use alloy_primitives::{Address, hex, keccak256};
use anyhow::{Context, Result, bail};
use bip32::secp256k1::ecdsa::SigningKey;
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic, WordCount};
use ctr::Ctr128BE;
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, thread_rng};
use scrypt::{Params as ScryptParams, scrypt};
use serde_json::Value;
use sha2::Sha256;
use std::{
    fs,
    io::{self, Write},
    path::Path,
    str::FromStr,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
const NEW_WALLET_PASSWORD_MIN_CHARS: usize = 12;
const SHORT_WALLET_PASSWORD_WARNING_CHARS: usize = 16;
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;
const MAX_SCRYPT_N: u64 = 262_144;
const MAX_PBKDF2_ROUNDS: u64 = 2_000_000;
const NEW_KEYSTORE_SCRYPT_LOG_N: u8 = 18;
const NEW_KEYSTORE_SCRYPT_R: u32 = 8;
const NEW_KEYSTORE_SCRYPT_P: u32 = 1;

type Aes128Ctr = Ctr128BE<Aes128>;

pub fn create_interactive(store: &ConfigStore, config: &mut AppConfig) -> Result<Address> {
    let mnemonic =
        Mnemonic::generate_in_with(&mut thread_rng(), Language::English, WordCount::Words24)
            .context("generate a BIP-39 recovery phrase")?;
    let phrase = Zeroizing::new(mnemonic.to_string());

    println!("Recovery phrase — write it down and keep it offline. It will not be stored:");
    println!("\n{}\n", phrase.as_str());
    confirm_backup()?;

    let signer = derive_signer(phrase.as_str(), "", DEFAULT_DERIVATION_PATH)?;
    let password = prompt_new_password()?;
    let address = store_signer(store, config, &signer, password.as_bytes())?;
    println!("Encrypted Ethereum V3 wallet created: {address:#x}");
    Ok(address)
}

pub fn import_interactive(
    store: &ConfigStore,
    config: &mut AppConfig,
    args: ImportArgs,
) -> Result<Address> {
    if let Some(path) = args.keystore {
        return import_keystore(store, config, &path);
    }

    let phrase = Zeroizing::new(rpassword::prompt_password(
        "Recovery phrase (input hidden): ",
    )?);
    if phrase.is_empty() {
        bail!("recovery phrase cannot be empty");
    }
    let bip39_passphrase = Zeroizing::new(rpassword::prompt_password(
        "Optional BIP-39 passphrase (input hidden; empty if unused): ",
    )?);
    if bip39_passphrase.len() > MAX_PASSWORD_BYTES {
        bail!("BIP-39 passphrase exceeds the supported 1024-byte limit");
    }

    let signer = derive_signer(
        phrase.as_str(),
        bip39_passphrase.as_str(),
        &args.derivation_path,
    )?;
    let password = prompt_new_password()?;
    let address = store_signer(store, config, &signer, password.as_bytes())?;
    println!("Encrypted Ethereum V3 wallet imported: {address:#x}");
    Ok(address)
}

pub fn selected_address(config: &AppConfig) -> Result<Address> {
    let value = config
        .wallet_address
        .as_deref()
        .context("no wallet is selected; run `astatine init` or `astatine wallet create`")?;
    Address::from_str(value).context("configured wallet address is invalid")
}

pub(crate) fn unlock_selected_interactive(
    store: &ConfigStore,
    config: &AppConfig,
) -> Result<SigningKey> {
    unlock_selected_interactive_inner(store, config, None)
}

pub(crate) fn unlock_selected_interactive_with_progress(
    store: &ConfigStore,
    config: &AppConfig,
    progress: &StartupProgress,
) -> Result<SigningKey> {
    unlock_selected_interactive_inner(store, config, Some(progress))
}

fn unlock_selected_interactive_inner(
    store: &ConfigStore,
    config: &AppConfig,
    progress: Option<&StartupProgress>,
) -> Result<SigningKey> {
    let address = selected_address(config)?;
    let keyfile = store.read_keystore(address)?;
    if validate_v3_keystore(&keyfile)? != address {
        bail!("selected wallet keyfile address does not match configuration");
    }
    if let Some(progress) = progress {
        progress.pause_for_prompt("Unlock wallet");
    }
    let password = Zeroizing::new(rpassword::prompt_password(
        "Ethereum V3 keystore password (input hidden): ",
    )?);
    if let Some(progress) = progress {
        progress.resume_after_prompt("Decrypting Ethereum V3 keystore");
    }
    let private_key = decrypt_v3_keystore(&keyfile, password.as_bytes())?;
    let signer = SigningKey::from_slice(private_key.as_slice())
        .context("decrypted V3 keyfile does not contain a valid secp256k1 private key")?;
    if signer_address(&signer) != address {
        bail!("decrypted private key does not match the selected wallet address");
    }
    Ok(signer)
}

pub fn print_address(store: &ConfigStore, config: &AppConfig) -> Result<()> {
    let address = selected_address(config)?;
    let keyfile = store.read_keystore(address)?;
    if validate_v3_keystore(&keyfile)? != address {
        bail!("selected wallet keyfile address does not match configuration");
    }
    println!("Wallet: {address:#x}");
    Ok(())
}

fn derive_signer(phrase: &str, passphrase: &str, path: &str) -> Result<SigningKey> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .context("invalid English BIP-39 recovery phrase")?;
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let path = path
        .parse::<DerivationPath>()
        .context("invalid BIP-44 derivation path")?;
    let extended =
        XPrv::derive_from_path(seed.as_ref(), &path).context("derive BIP-44 Ethereum key")?;
    Ok(extended.private_key().clone())
}

pub(crate) fn signer_address(signer: &SigningKey) -> Address {
    let public_key = signer.verifying_key().to_sec1_point(false);
    let digest = keccak256(&public_key.as_ref()[1..]);
    Address::from_slice(&digest.as_slice()[12..])
}

fn store_signer(
    store: &ConfigStore,
    config: &mut AppConfig,
    signer: &SigningKey,
    password: &[u8],
) -> Result<Address> {
    let address = signer_address(signer);
    let private_key = Zeroizing::new(signer.to_bytes());
    let contents = encrypt_v3_keystore(private_key.as_slice(), address, password)?;
    if validate_v3_keystore(&contents)? != address {
        bail!("encrypted keyfile address does not match the derived wallet");
    }

    let destination = store.store_keystore(address, &contents)?;
    config.wallet_address = Some(format!("{address:#x}"));
    if let Err(error) = store.save(config) {
        let _ = fs::remove_file(&destination);
        return Err(error).context("save selected wallet configuration");
    }
    Ok(address)
}

fn import_keystore(store: &ConfigStore, config: &mut AppConfig, source: &Path) -> Result<Address> {
    let contents = read_regular_limited(source, MAX_KEYSTORE_BYTES, false)
        .context("read external Ethereum V3 keyfile")?;
    if contents.is_empty() {
        bail!("keyfile is empty or exceeds the supported size limit");
    }
    let embedded_address = validate_v3_keystore(&contents)?;
    let password = Zeroizing::new(rpassword::prompt_password(
        "Ethereum V3 keystore password (input hidden): ",
    )?);
    validate_import_password(&password)?;

    let private_key = decrypt_v3_keystore(&contents, password.as_bytes())?;
    let signer = SigningKey::from_slice(private_key.as_slice())
        .context("decrypted V3 keyfile does not contain a valid secp256k1 private key")?;
    let address = signer_address(&signer);
    if address != embedded_address {
        bail!("decrypted private key does not match the keyfile address");
    }
    drop(signer);

    let destination = store.store_keystore(address, &contents)?;
    config.wallet_address = Some(format!("{address:#x}"));
    if let Err(error) = store.save(config) {
        let _ = fs::remove_file(&destination);
        return Err(error).context("save imported wallet configuration");
    }
    Ok(address)
}

fn encrypt_v3_keystore(private_key: &[u8], address: Address, password: &[u8]) -> Result<Vec<u8>> {
    if private_key.len() != 32 {
        bail!("Ethereum private key must be exactly 32 bytes");
    }
    let password_text =
        std::str::from_utf8(password).context("new keystore password must be valid UTF-8")?;
    validate_new_password(password_text)?;
    if password.len() > MAX_PASSWORD_BYTES {
        bail!("keystore password exceeds the supported 1024-byte limit");
    }

    let mut rng = thread_rng();
    let mut salt = [0_u8; 32];
    let mut iv = [0_u8; 16];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    let params = ScryptParams::new(
        NEW_KEYSTORE_SCRYPT_LOG_N,
        NEW_KEYSTORE_SCRYPT_R,
        NEW_KEYSTORE_SCRYPT_P,
    )
    .context("configure Ethereum V3 scrypt parameters")?;
    let mut derived_key = Zeroizing::new(vec![0_u8; 32]);
    scrypt(password, &salt, &params, derived_key.as_mut_slice())
        .context("derive Ethereum V3 encryption key")?;

    let mut ciphertext = private_key.to_vec();
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
        .context("initialize Ethereum V3 AES-128-CTR")?;
    cipher.apply_keystream(&mut ciphertext);

    let mut mac_input = Zeroizing::new(Vec::with_capacity(48));
    mac_input.extend_from_slice(&derived_key[16..]);
    mac_input.extend_from_slice(&ciphertext);
    let mac = keccak256(mac_input.as_slice());
    let address = format!("{address:#x}");
    let address = address.strip_prefix("0x").unwrap_or(&address);
    let keyfile = serde_json::json!({
        "version": 3,
        "id": random_uuid_v4(&mut rng),
        "address": address,
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": { "iv": hex::encode(iv) },
            "ciphertext": hex::encode(ciphertext),
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 1_u64 << NEW_KEYSTORE_SCRYPT_LOG_N,
                "p": NEW_KEYSTORE_SCRYPT_P,
                "r": NEW_KEYSTORE_SCRYPT_R,
                "salt": hex::encode(salt)
            },
            "mac": hex::encode(mac)
        }
    });
    serde_json::to_vec_pretty(&keyfile).context("serialize Ethereum V3 keystore")
}

fn random_uuid_v4(rng: &mut impl RngCore) -> String {
    let mut bytes = [0_u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn decrypt_v3_keystore(contents: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    validate_v3_keystore(contents)?;
    let json: Value = serde_json::from_slice(contents).context("parse Ethereum V3 keyfile")?;
    let crypto = json
        .get("crypto")
        .or_else(|| json.get("Crypto"))
        .context("V3 keyfile has no crypto object")?;
    let params = crypto
        .get("kdfparams")
        .context("V3 keyfile KDF parameters are missing")?;
    let dklen = params
        .get("dklen")
        .and_then(Value::as_u64)
        .context("V3 keyfile KDF output length is invalid")? as usize;
    let salt = hex::decode(
        params
            .get("salt")
            .and_then(Value::as_str)
            .context("V3 keyfile KDF salt is missing")?,
    )
    .context("decode V3 keyfile KDF salt")?;
    let mut derived_key = Zeroizing::new(vec![0_u8; dklen]);
    match crypto.get("kdf").and_then(Value::as_str) {
        Some("scrypt") => {
            let n = params.get("n").and_then(Value::as_u64).unwrap();
            let r = params.get("r").and_then(Value::as_u64).unwrap() as u32;
            let p = params.get("p").and_then(Value::as_u64).unwrap() as u32;
            let scrypt_params = ScryptParams::new(n.trailing_zeros() as u8, r, p)
                .context("configure V3 keyfile scrypt parameters")?;
            scrypt(password, &salt, &scrypt_params, derived_key.as_mut_slice())
                .context("derive V3 keyfile decryption key")?;
        }
        Some("pbkdf2") => {
            let rounds = params.get("c").and_then(Value::as_u64).unwrap() as u32;
            pbkdf2_hmac::<Sha256>(password, &salt, rounds, derived_key.as_mut_slice());
        }
        _ => bail!("V3 keyfile KDF must be scrypt or PBKDF2"),
    }

    let ciphertext = hex::decode(
        crypto
            .get("ciphertext")
            .and_then(Value::as_str)
            .context("V3 keyfile ciphertext is missing")?,
    )
    .context("decode V3 keyfile ciphertext")?;
    let expected_mac = hex::decode(
        crypto
            .get("mac")
            .and_then(Value::as_str)
            .context("V3 keyfile MAC is missing")?,
    )
    .context("decode V3 keyfile MAC")?;
    let mut mac_input = Zeroizing::new(Vec::with_capacity(derived_key.len()));
    mac_input.extend_from_slice(&derived_key[16..]);
    mac_input.extend_from_slice(&ciphertext);
    let actual_mac = keccak256(mac_input.as_slice());
    if expected_mac.ct_eq(actual_mac.as_slice()).unwrap_u8() != 1 {
        bail!("Ethereum V3 keystore password or MAC is invalid");
    }

    let iv = hex::decode(
        crypto
            .get("cipherparams")
            .and_then(|value| value.get("iv"))
            .and_then(Value::as_str)
            .context("V3 keyfile cipher IV is missing")?,
    )
    .context("decode V3 keyfile cipher IV")?;
    let mut plaintext = Zeroizing::new(ciphertext);
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
        .context("initialize V3 keyfile AES-128-CTR")?;
    cipher.apply_keystream(plaintext.as_mut_slice());
    Ok(plaintext)
}

pub(crate) fn validate_v3_keystore(contents: &[u8]) -> Result<Address> {
    let json: Value = serde_json::from_slice(contents).context("parse Ethereum V3 keyfile")?;
    if json.get("version").and_then(Value::as_u64) != Some(3) {
        bail!("only Ethereum Web3 Secret Storage V3 keyfiles are supported");
    }
    let address = json
        .get("address")
        .and_then(Value::as_str)
        .context("V3 keyfile has no public address")?;
    let address = Address::from_str(address).context("V3 keyfile address is invalid")?;
    let crypto = json
        .get("crypto")
        .or_else(|| json.get("Crypto"))
        .context("V3 keyfile has no crypto object")?;
    if crypto.get("cipher").and_then(Value::as_str) != Some("aes-128-ctr") {
        bail!("V3 keyfile cipher must be aes-128-ctr");
    }
    let iv = crypto
        .get("cipherparams")
        .and_then(|params| params.get("iv"))
        .and_then(Value::as_str)
        .context("V3 keyfile cipher IV is missing")?;
    let ciphertext = crypto
        .get("ciphertext")
        .and_then(Value::as_str)
        .context("V3 keyfile ciphertext is missing")?;
    let mac = crypto
        .get("mac")
        .and_then(Value::as_str)
        .context("V3 keyfile MAC is missing")?;
    if hex::decode(iv).context("V3 keyfile IV is malformed")?.len() != 16
        || hex::decode(ciphertext)
            .context("V3 keyfile ciphertext is malformed")?
            .len()
            != 32
        || hex::decode(mac)
            .context("V3 keyfile MAC is malformed")?
            .len()
            != 32
    {
        bail!("V3 keyfile cryptographic fields have invalid lengths");
    }
    let params = crypto
        .get("kdfparams")
        .context("V3 keyfile KDF parameters are missing")?;
    let dklen = params
        .get("dklen")
        .and_then(Value::as_u64)
        .context("V3 keyfile KDF output length is invalid")?;
    if dklen != 32 {
        bail!("V3 keyfile KDF output length is unsupported");
    }
    let salt = params
        .get("salt")
        .and_then(Value::as_str)
        .context("V3 keyfile KDF salt is missing")?;
    if hex::decode(salt)
        .context("V3 keyfile KDF salt is malformed")?
        .len()
        != 32
    {
        bail!("V3 keyfile KDF salt must be 32 bytes");
    }
    match crypto.get("kdf").and_then(Value::as_str) {
        Some("scrypt") => {
            let n = params
                .get("n")
                .and_then(Value::as_u64)
                .context("V3 keyfile scrypt cost is invalid")?;
            let r = params
                .get("r")
                .and_then(Value::as_u64)
                .context("V3 keyfile scrypt block size is invalid")?;
            let p = params
                .get("p")
                .and_then(Value::as_u64)
                .context("V3 keyfile scrypt parallelization is invalid")?;
            if !n.is_power_of_two()
                || !(4_096..=MAX_SCRYPT_N).contains(&n)
                || r != 8
                || !(1..=8).contains(&p)
                || n.saturating_mul(p) > MAX_SCRYPT_N
            {
                bail!("V3 keyfile scrypt parameters exceed supported bounds");
            }
        }
        Some("pbkdf2") => {
            let rounds = params
                .get("c")
                .and_then(Value::as_u64)
                .context("V3 keyfile PBKDF2 rounds are invalid")?;
            if !(1..=MAX_PBKDF2_ROUNDS).contains(&rounds)
                || params.get("prf").and_then(Value::as_str) != Some("hmac-sha256")
            {
                bail!("V3 keyfile PBKDF2 parameters exceed supported bounds");
            }
        }
        _ => bail!("V3 keyfile KDF must be scrypt or PBKDF2"),
    }
    Ok(address)
}

fn prompt_new_password() -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(rpassword::prompt_password(
        "Create keystore password (input hidden; use at least 12 characters): ",
    )?);
    validate_new_password(&password)?;
    if should_warn_short_password(&password) {
        eprintln!("Security note: a longer unique passphrase better protects this wallet.");
    }
    let confirmation = Zeroizing::new(rpassword::prompt_password(
        "Confirm keystore password (input hidden): ",
    )?);
    validate_password_confirmation(&password, &confirmation)?;
    Ok(password)
}

fn should_warn_short_password(password: &str) -> bool {
    password.chars().count() < SHORT_WALLET_PASSWORD_WARNING_CHARS
}

pub(crate) fn is_password_prompt_interrupted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::Interrupted)
}

fn validate_new_password(password: &str) -> Result<()> {
    if password.chars().count() < NEW_WALLET_PASSWORD_MIN_CHARS
        || password.len() > MAX_PASSWORD_BYTES
    {
        bail!(
            "new keystore password must be at least 12 Unicode characters and no more than 1024 bytes"
        );
    }
    Ok(())
}

fn validate_password_confirmation(password: &str, confirmation: &str) -> Result<()> {
    if password != confirmation {
        bail!("password confirmation did not match");
    }
    Ok(())
}

fn validate_import_password(password: &str) -> Result<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        bail!("keystore password exceeds the supported 1024-byte limit");
    }
    Ok(())
}

fn confirm_backup() -> Result<()> {
    print!("Type BACKED UP after writing the phrase down: ");
    io::stdout()
        .flush()
        .context("flush recovery phrase confirmation prompt")?;
    let mut confirmation = String::new();
    io::stdin()
        .read_line(&mut confirmation)
        .context("read recovery phrase confirmation")?;
    if confirmation.trim() != "BACKED UP" {
        bail!("wallet creation cancelled; no wallet was stored");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Aes128Ctr, DEFAULT_DERIVATION_PATH, MAX_PASSWORD_BYTES, decrypt_v3_keystore, derive_signer,
        should_warn_short_password, signer_address, store_signer, validate_import_password,
        validate_new_password, validate_password_confirmation, validate_v3_keystore,
    };
    use crate::config::{AppConfig, ConfigStore};
    use aes::cipher::{KeyIvInit, StreamCipher};
    use alloy_primitives::{Address, hex, keccak256};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use std::{io, path::PathBuf, str::FromStr};
    use tempfile::tempdir;

    // Standard public BIP-39 test vector; it is not a user or funded wallet.
    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_PASSWORD: &str = "test-only-keystore-password";

    #[test]
    fn derives_standard_ethereum_bip44_address() {
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        assert_eq!(
            signer_address(&signer),
            Address::from_str("0x9858EfFD232B4033E47d90003D41EC34EcaEda94").unwrap()
        );
    }

    #[test]
    fn encrypted_keystore_round_trip_is_v3_and_contains_no_mnemonic() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let mut config = AppConfig::default();
        store_signer(&store, &mut config, &signer, TEST_PASSWORD.as_bytes()).unwrap();

        let keyfile = store.read_keystore(address).unwrap();
        let embedded_address = validate_v3_keystore(&keyfile).unwrap();
        assert_eq!(embedded_address, address);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(store.wallet_dir())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(store.keystore_path(address))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let value: serde_json::Value = serde_json::from_slice(&keyfile).unwrap();
        assert_eq!(
            value.get("version").and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(value["crypto"]["kdf"], "scrypt");
        assert_eq!(value["crypto"]["kdfparams"]["n"], 1_u64 << 18);
        assert_eq!(value["crypto"]["kdfparams"]["r"], 8);
        assert_eq!(value["crypto"]["kdfparams"]["p"], 1);
        assert!(
            !String::from_utf8(keyfile.clone())
                .unwrap()
                .contains(TEST_PHRASE)
        );

        let private_key = decrypt_v3_keystore(&keyfile, TEST_PASSWORD.as_bytes()).unwrap();
        let decrypted = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        assert_eq!(private_key.as_slice(), decrypted.to_bytes().as_slice());
        assert_eq!(signer_address(&decrypted), address);
        assert_eq!(
            config.wallet_address.as_deref(),
            Some(format!("{address:#x}").as_str())
        );
    }

    #[test]
    fn new_wallet_password_requires_at_least_twelve_unicode_characters() {
        for (password, expected) in [
            ("", false),
            ("abc", false),
            ("12345678901", false),
            ("twelve-chars", true),
            ("longer-unique-passphrase", true),
        ] {
            assert_eq!(
                validate_new_password(password).is_ok(),
                expected,
                "unexpected result for a {}-character password",
                password.chars().count()
            );
        }
    }

    #[test]
    fn new_wallet_password_counts_unicode_characters_and_limits_encoded_bytes() {
        let short_unicode_password = "🔐".repeat(11);
        assert_eq!(short_unicode_password.chars().count(), 11);
        assert!(validate_new_password(&short_unicode_password).is_err());

        let unicode_password = "🔐".repeat(12);
        assert_eq!(unicode_password.chars().count(), 12);
        assert!(unicode_password.len() > unicode_password.chars().count());
        assert!(validate_new_password(&unicode_password).is_ok());

        assert!(validate_new_password(&"x".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert!(validate_new_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    #[test]
    fn incorrect_new_wallet_password_confirmation_is_rejected() {
        assert!(validate_password_confirmation("abcd", "abce").is_err());
        assert!(validate_password_confirmation("abcd", "abcd").is_ok());
    }

    #[test]
    fn near_minimum_password_warning_uses_unicode_character_count() {
        assert!(should_warn_short_password("twelve-chars"));
        assert!(!should_warn_short_password("sixteen-character"));
        assert!(should_warn_short_password(&"🔐".repeat(12)));
        assert!(!should_warn_short_password(&"🔐".repeat(16)));
    }

    #[test]
    fn interrupted_hidden_password_prompt_is_identified_as_cancellation() {
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        assert!(super::is_password_prompt_interrupted(&error));
        assert!(!super::is_password_prompt_interrupted(&anyhow::anyhow!(
            "bad password"
        )));
    }

    #[test]
    fn twelve_character_password_round_trips_through_ethereum_v3_keystore() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let mut config = AppConfig::default();
        let password = "twelve-chars";
        validate_new_password(password).unwrap();
        store_signer(&store, &mut config, &signer, password.as_bytes()).unwrap();

        let keyfile = store.read_keystore(address).unwrap();
        let decrypted = decrypt_v3_keystore(&keyfile, password.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
        assert_eq!(validate_v3_keystore(&keyfile).unwrap(), address);
    }

    #[test]
    fn existing_v3_import_passwords_are_not_subject_to_new_wallet_minimum() {
        assert!(validate_import_password("x").is_ok());
    }

    #[test]
    fn imports_a_standard_pbkdf2_v3_keyfile() {
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let mut derived_key = [0_u8; 32];
        let salt = [0x51_u8; 32];
        let iv = [0x27_u8; 16];
        pbkdf2_hmac::<Sha256>(TEST_PASSWORD.as_bytes(), &salt, 2_048, &mut derived_key);
        let mut ciphertext = signer.to_bytes().to_vec();
        Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let mut mac_input = derived_key[16..].to_vec();
        mac_input.extend_from_slice(&ciphertext);
        let mac = keccak256(mac_input);
        let address = format!("{address:#x}");
        let keyfile = serde_json::json!({
            "version": 3,
            "id": "f0e1d2c3-b4a5-4678-89ab-cdef01234567",
            "address": address.strip_prefix("0x").unwrap(),
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": hex::encode(iv) },
                "ciphertext": hex::encode(ciphertext),
                "kdf": "pbkdf2",
                "kdfparams": {
                    "c": 2_048,
                    "dklen": 32,
                    "prf": "hmac-sha256",
                    "salt": hex::encode(salt)
                },
                "mac": hex::encode(mac)
            }
        });
        let keyfile = serde_json::to_vec(&keyfile).unwrap();
        let decrypted = decrypt_v3_keystore(&keyfile, TEST_PASSWORD.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
        assert!(decrypt_v3_keystore(&keyfile, b"wrong").is_err());
    }

    #[test]
    fn imports_existing_ethereum_v3_keyfile_with_its_three_character_password() {
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let address = signer_address(&signer);
        let password = "old";
        let mut derived_key = [0_u8; 32];
        let salt = [0x61_u8; 32];
        let iv = [0x37_u8; 16];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 2_048, &mut derived_key);
        let mut ciphertext = signer.to_bytes().to_vec();
        Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let mut mac_input = derived_key[16..].to_vec();
        mac_input.extend_from_slice(&ciphertext);
        let mac = keccak256(mac_input);
        let address = format!("{address:#x}");
        let keyfile = serde_json::json!({
            "version": 3,
            "id": "f0e1d2c3-b4a5-4678-89ab-cdef01234567",
            "address": address.strip_prefix("0x").unwrap(),
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": hex::encode(iv) },
                "ciphertext": hex::encode(ciphertext),
                "kdf": "pbkdf2",
                "kdfparams": {
                    "c": 2_048,
                    "dklen": 32,
                    "prf": "hmac-sha256",
                    "salt": hex::encode(salt)
                },
                "mac": hex::encode(mac)
            }
        });
        let keyfile = serde_json::to_vec(&keyfile).unwrap();

        validate_import_password(password).unwrap();
        let decrypted = decrypt_v3_keystore(&keyfile, password.as_bytes()).unwrap();
        assert_eq!(decrypted.as_slice(), signer.to_bytes().as_slice());
        assert!(decrypt_v3_keystore(&keyfile, b"bad").is_err());
    }

    #[test]
    fn v3_import_validation_rejects_unsafe_scrypt_costs() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(temp.path()));
        let signer = derive_signer(TEST_PHRASE, "", DEFAULT_DERIVATION_PATH).unwrap();
        let mut config = AppConfig::default();
        store_signer(&store, &mut config, &signer, TEST_PASSWORD.as_bytes()).unwrap();
        let bytes = store.read_keystore(signer_address(&signer)).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["crypto"]["kdfparams"]["n"] = serde_json::Value::from(1_u64 << 30);
        assert!(validate_v3_keystore(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
