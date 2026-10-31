use alloy_primitives::Address;
use clap::{Arg, ArgMatches, Command as ClapCommand};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroUsize, path::PathBuf, str::FromStr};

#[cfg(test)]
use std::ffi::OsString;

#[derive(Debug, Eq, PartialEq)]
pub struct Cli {
    pub command: Command,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Init(InitArgs),
    Mine(MineArgs),
    Wallet(WalletCommand),
    NetworkUse(Network),
    GetRpc {
        network: Option<Network>,
    },
    SetRpc {
        network: Option<Network>,
        endpoint: Option<String>,
    },
    Nodes,
    Status,
    Rewards,
    Devices,
    Benchmark(BenchmarkArgs),
    Update(UpdateArgs),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkArgs {
    pub seconds: u8,
    pub threads: Option<NonZeroUsize>,
    pub batch_size: Option<usize>,
    pub workgroup_size: Option<u32>,
    pub runs: u8,
    pub profile: bool,
    pub compare_full_sha: bool,
    pub serial: bool,
    pub output_json: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceChoice {
    #[default]
    Cpu,
    Gpu,
    Auto,
}

impl FromStr for DeviceChoice {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "cpu" => Ok(Self::Cpu),
            "gpu" => Ok(Self::Gpu),
            "auto" => Ok(Self::Auto),
            _ => Err("device must be cpu, gpu, or auto".to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateArgs {
    pub check_only: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct MineArgs {
    pub device: DeviceChoice,
    pub compute_only: bool,
    pub threads: Option<NonZeroUsize>,
    pub nodes: Vec<u8>,
    pub send_rewards_to: Option<Address>,
    pub new_session: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InitArgs {
    pub network: Option<Network>,
    pub threads: Option<NonZeroUsize>,
    pub minimum_reserve_inj: Option<String>,
    pub spending_limit_inj: Option<String>,
    pub transaction_confirmations: Option<u8>,
    pub rpc: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum WalletCommand {
    Create,
    Import(ImportArgs),
    Address,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ImportArgs {
    pub keystore: Option<PathBuf>,
    pub derivation_path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Testnet,
    Mainnet,
}

pub fn parse() -> Cli {
    let matches = command().get_matches();
    Cli {
        command: parse_matches(&matches),
    }
}

fn parse_reward_destination(value: &str) -> Result<Address, String> {
    let address =
        Address::from_str(value).map_err(|_| "expected a 20-byte EVM address".to_owned())?;
    if address.is_zero() {
        return Err("reward destination cannot be the zero address".to_owned());
    }
    let body = value.strip_prefix("0x").unwrap_or_default();
    let has_lower = body.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = body.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper {
        Address::parse_checksummed(value, None).map_err(|_| {
            "mixed-case reward destination has an invalid EIP-55 checksum".to_owned()
        })?;
    }
    Ok(address)
}

#[cfg(test)]
pub fn try_parse_from<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = command().try_get_matches_from(arguments)?;
    Ok(Cli {
        command: parse_matches(&matches),
    })
}

fn command() -> ClapCommand {
    ClapCommand::new("astatine")
        .version(env!("CARGO_PKG_VERSION"))
        .about("A native command-line miner for Astatine")
        .long_about(
            "Astatine is a non-custodial CPU/GPU miner. CPU is the default backend. GPU candidates are checked again by the canonical CPU WorkHasher before entering the bounded proof pipeline. Testnet transaction authorizations count their maximum possible INJ exposure cumulatively for the session; RPC receipts never refund signing authority. Permissionless finalization can spend gas for empty windows or windows won by another miner. Automatic AST reward forwarding is disabled because the selected RPC can fabricate reward evidence; verify rewards independently and transfer manually. --compute-only never signs or submits transactions. Mainnet transaction signing is disabled.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            ClapCommand::new("init")
                .about("Configure the local wallet, network, CPU, spending cap, and confirmation depth")
                .arg(
                    Arg::new("network")
                        .long("network")
                        .value_name("NETWORK")
                        .value_parser(["testnet", "mainnet"]),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .value_name("N")
                        .value_parser(clap::value_parser!(NonZeroUsize)),
                )
                .arg(
                    Arg::new("minimum-reserve-inj")
                        .long("minimum-reserve-inj")
                        .value_name("INJ"),
                )
                .arg(
                    Arg::new("spending-limit-inj")
                        .long("spending-limit-inj")
                        .value_name("INJ"),
                )
                .arg(
                    Arg::new("confirmation-blocks")
                        .long("confirmation-blocks")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8).range(1..=12)),
                )
                .arg(
                    Arg::new("rpc")
                        .long("rpc")
                        .value_name("URL")
                        .help("Use and save a custom RPC for the selected network"),
                ),
        )
        .subcommand(
            ClapCommand::new("mine")
                .about("Mine eligible Astatine work using the local CPU or a validated GPU")
                .arg(
                    Arg::new("device")
                        .long("device")
                        .value_name("DEVICE")
                        .value_parser(clap::value_parser!(DeviceChoice))
                        .default_value("cpu")
                        .help("Compute backend: cpu (default), gpu, or auto"),
                )
                .arg(
                    Arg::new("compute-only")
                        .long("compute-only")
                        .action(clap::ArgAction::SetTrue)
                        .help("Hash verified work locally without signing or sending transactions"),
                )
                .arg(
                    Arg::new("new-session")
                        .long("new-session")
                        .action(clap::ArgAction::SetTrue)
                        .conflicts_with("compute-only")
                        .help("Explicitly authorize a separate spending session after prior spending"),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .value_name("N")
                        .value_parser(clap::value_parser!(NonZeroUsize))
                        .help("Maximum number of CPU worker threads to use"),
                )
                .arg(
                    Arg::new("nodes")
                        .long("nodes")
                        .value_name("ID,...")
                        .num_args(1..)
                        .value_delimiter(',')
                        .value_parser(clap::value_parser!(u8).range(1..=9))
                        .help("Restrict mining to comma-separated node IDs (1-9)"),
                )
                .arg(
                    Arg::new("send-rewards-to")
                        .long("send-rewards-to")
                        .value_name("ADDRESS")
                        .value_parser(parse_reward_destination)
                        .help("Disabled in Testnet.13: RPC reward evidence cannot authorize AST transfers"),
                ),
        )
        .subcommand(
            ClapCommand::new("get")
                .about("Read local configuration")
                .subcommand_required(true)
                .subcommand(
                    ClapCommand::new("rpc")
                        .about("Show the active RPC and bundled fallback without connecting")
                        .arg(
                            Arg::new("network")
                                .long("network")
                                .value_name("NETWORK")
                                .value_parser(["testnet", "mainnet"]),
                        ),
                ),
        )
        .subcommand(
            ClapCommand::new("set")
                .about("Update local configuration")
                .subcommand_required(true)
                .subcommand(
                    ClapCommand::new("rpc")
                        .about("Set a trusted RPC, or restore the bundled default")
                        .arg(Arg::new("url").value_name("URL").num_args(0..=1))
                        .arg(
                            Arg::new("network")
                                .long("network")
                                .value_name("NETWORK")
                                .value_parser(["testnet", "mainnet"]),
                        ),
                ),
        )
        .subcommand(wallet_command())
        .subcommand(network_command())
        .subcommand(ClapCommand::new("nodes").about("Show the configured mining nodes"))
        .subcommand(ClapCommand::new("devices").about("List compute devices and run GPU SHA-256d self-tests"))
        .subcommand(
            ClapCommand::new("benchmark")
                .about("Measure canonical CPU/GPU SHA-256d throughput without RPC or transactions")
                .arg(
                    Arg::new("seconds")
                        .long("seconds")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8).range(1..=60))
                        .default_value("10")
                        .help("Measurement duration per sample (1-60 seconds)"),
                )
                .arg(
                    Arg::new("threads")
                        .long("threads")
                        .value_name("N")
                        .value_parser(clap::value_parser!(NonZeroUsize))
                        .help("CPU baseline thread count (defaults to the conservative CPU budget)"),
                )
                .arg(
                    Arg::new("batch-size")
                        .long("batch-size")
                        .value_name("N")
                        .value_parser([
                            "2048", "8192", "16384", "32768", "65536", "131072", "262144",
                        ])
                        .help("Test one bounded GPU nonce batch size"),
                )
                .arg(
                    Arg::new("workgroup-size")
                        .long("workgroup-size")
                        .value_name("N")
                        .value_parser(["32", "64", "128", "256"])
                        .help("Test one supported GPU workgroup size"),
                )
                .arg(
                    Arg::new("runs")
                        .long("runs")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8).range(3..=10))
                        .default_value("3")
                        .help("Measured repetitions per backend/configuration (3-10)"),
                )
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .action(clap::ArgAction::SetTrue)
                        .help("Sweep all supported GPU batch and workgroup sizes"),
                )
                .arg(
                    Arg::new("compare-full-sha")
                        .long("compare-full-sha")
                        .action(clap::ArgAction::SetTrue)
                        .help("Run matched full-SHA and cached-midstate GPU configurations"),
                )
                .arg(
                    Arg::new("serial")
                        .long("serial")
                        .action(clap::ArgAction::SetTrue)
                        .help("Disable the bounded two-batch overlap for a synchronous comparison"),
                )
                .arg(
                    Arg::new("output-json")
                        .long("output-json")
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Write raw benchmark samples and hardware details as JSON"),
                ),
        )
        .subcommand(ClapCommand::new("status").about("Show local miner status"))
        .subcommand(ClapCommand::new("rewards").about("Show the selected RPC's AST token balance"))
        .subcommand(
            ClapCommand::new("update")
                .about("Check for and install an authenticated release update")
                .arg(
                    Arg::new("check")
                        .long("check")
                        .action(clap::ArgAction::SetTrue)
                        .help("Check for a newer authenticated release without installing it"),
                ),
        )
}

fn wallet_command() -> ClapCommand {
    ClapCommand::new("wallet")
        .about("Manage the local wallet")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(ClapCommand::new("create").about("Create a new encrypted local wallet"))
        .subcommand(
            ClapCommand::new("import")
                .about("Import a mnemonic or encrypted Ethereum V3 keystore")
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Import an encrypted V3 keyfile; the password is read securely"),
                )
                .arg(
                    Arg::new("derivation-path")
                        .long("derivation-path")
                        .value_name("PATH")
                        .default_value("m/44'/60'/0'/0/0")
                        .help("BIP-44 path used for mnemonic import"),
                ),
        )
        .subcommand(
            ClapCommand::new("address").about("Display the selected wallet's public address"),
        )
}

fn network_command() -> ClapCommand {
    ClapCommand::new("network")
        .about("Select a network profile")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            ClapCommand::new("use")
                .about("Select the network profile")
                .arg(
                    Arg::new("network")
                        .required(true)
                        .value_name("NETWORK")
                        .value_parser(["testnet", "mainnet"]),
                ),
        )
}

fn parse_matches(matches: &ArgMatches) -> Command {
    match matches.subcommand() {
        Some(("init", args)) => Command::Init(InitArgs {
            network: args
                .get_one::<String>("network")
                .map(|value| match value.as_str() {
                    "testnet" => Network::Testnet,
                    "mainnet" => Network::Mainnet,
                    _ => unreachable!("network value parser restricts the accepted values"),
                }),
            threads: args.get_one::<NonZeroUsize>("threads").copied(),
            minimum_reserve_inj: args.get_one::<String>("minimum-reserve-inj").cloned(),
            spending_limit_inj: args.get_one::<String>("spending-limit-inj").cloned(),
            transaction_confirmations: args.get_one::<u8>("confirmation-blocks").copied(),
            rpc: args.get_one::<String>("rpc").cloned(),
        }),
        Some(("mine", args)) => Command::Mine(MineArgs {
            device: args
                .get_one::<DeviceChoice>("device")
                .copied()
                .unwrap_or_default(),
            compute_only: args.get_flag("compute-only"),
            threads: args.get_one::<NonZeroUsize>("threads").copied(),
            nodes: args
                .get_many::<u8>("nodes")
                .map(|nodes| nodes.copied().collect())
                .unwrap_or_default(),
            send_rewards_to: args.get_one::<Address>("send-rewards-to").copied(),
            new_session: args.get_flag("new-session"),
        }),
        Some(("wallet", args)) => match args.subcommand() {
            Some(("create", _)) => Command::Wallet(WalletCommand::Create),
            Some(("import", args)) => Command::Wallet(WalletCommand::Import(ImportArgs {
                keystore: args.get_one::<PathBuf>("keystore").cloned(),
                derivation_path: args
                    .get_one::<String>("derivation-path")
                    .expect("derivation path has a default")
                    .clone(),
            })),
            Some(("address", _)) => Command::Wallet(WalletCommand::Address),
            _ => unreachable!("wallet requires a known subcommand"),
        },
        Some(("network", args)) => match args.subcommand() {
            Some(("use", args)) => {
                let network = match args
                    .get_one::<String>("network")
                    .expect("network is required")
                    .as_str()
                {
                    "testnet" => Network::Testnet,
                    "mainnet" => Network::Mainnet,
                    _ => unreachable!("network value parser restricts the accepted values"),
                };
                Command::NetworkUse(network)
            }
            _ => unreachable!("network requires a known subcommand"),
        },
        Some(("get", args)) => match args.subcommand() {
            Some(("rpc", args)) => Command::GetRpc {
                network: parse_network_option(args),
            },
            _ => unreachable!("get requires a known subcommand"),
        },
        Some(("set", args)) => match args.subcommand() {
            Some(("rpc", args)) => Command::SetRpc {
                network: parse_network_option(args),
                endpoint: args.get_one::<String>("url").cloned(),
            },
            _ => unreachable!("set requires a known subcommand"),
        },
        Some(("nodes", _)) => Command::Nodes,
        Some(("status", _)) => Command::Status,
        Some(("rewards", _)) => Command::Rewards,
        Some(("devices", _)) => Command::Devices,
        Some(("benchmark", args)) => Command::Benchmark(BenchmarkArgs {
            seconds: *args
                .get_one::<u8>("seconds")
                .expect("benchmark duration has a default"),
            threads: args.get_one::<NonZeroUsize>("threads").copied(),
            batch_size: args
                .get_one::<String>("batch-size")
                .map(|value| value.parse().expect("batch-size parser accepts numbers")),
            workgroup_size: args.get_one::<String>("workgroup-size").map(|value| {
                value
                    .parse()
                    .expect("workgroup-size parser accepts numbers")
            }),
            runs: *args
                .get_one::<u8>("runs")
                .expect("benchmark repetitions have a default"),
            profile: args.get_flag("profile"),
            compare_full_sha: args.get_flag("compare-full-sha"),
            serial: args.get_flag("serial"),
            output_json: args.get_one::<PathBuf>("output-json").cloned(),
        }),
        Some(("update", args)) => Command::Update(UpdateArgs {
            check_only: args.get_flag("check"),
        }),
        _ => unreachable!("top-level command is required and restricted to known commands"),
    }
}

fn parse_network_option(args: &ArgMatches) -> Option<Network> {
    args.get_one::<String>("network")
        .map(|value| match value.as_str() {
            "testnet" => Network::Testnet,
            "mainnet" => Network::Mainnet,
            _ => unreachable!("network parser restricts the accepted values"),
        })
}

#[cfg(test)]
mod tests {
    use super::{
        BenchmarkArgs, Command, DeviceChoice, ImportArgs, InitArgs, Network, NonZeroUsize,
        WalletCommand, try_parse_from,
    };
    use alloy_primitives::Address;
    use std::path::PathBuf;

    #[test]
    fn parses_primary_commands_and_safe_mining_options() {
        let cli = try_parse_from([
            "astatine",
            "mine",
            "--compute-only",
            "--threads",
            "4",
            "--nodes",
            "1,3,5",
        ])
        .expect("planned mine command should parse");

        let Command::Mine(args) = cli.command else {
            panic!("expected mine subcommand");
        };
        assert_eq!(args.device, DeviceChoice::Cpu);
        assert!(args.compute_only);
        assert_eq!(args.threads.map(|threads| threads.get()), Some(4));
        assert_eq!(args.nodes, [1, 3, 5]);
        assert_eq!(args.send_rewards_to, None);
        assert!(!args.new_session);
    }

    #[test]
    fn mine_defaults_to_autonomous_mode_and_keeps_compute_only_opt_in() {
        let cli = try_parse_from(["astatine", "mine"]).expect("mine command should parse");
        let Command::Mine(args) = cli.command else {
            panic!("expected mine subcommand");
        };
        assert!(!args.compute_only);
        assert_eq!(args.device, DeviceChoice::Cpu);
        assert_eq!(args.send_rewards_to, None);
        assert!(!args.new_session);
    }

    #[test]
    fn parses_explicit_gpu_device_modes() {
        for (name, expected) in [
            ("cpu", DeviceChoice::Cpu),
            ("gpu", DeviceChoice::Gpu),
            ("auto", DeviceChoice::Auto),
        ] {
            let cli = try_parse_from(["astatine", "mine", "--device", name])
                .expect("device choice should parse");
            let Command::Mine(args) = cli.command else {
                panic!("expected mine subcommand");
            };
            assert_eq!(args.device, expected);
        }
        assert!(try_parse_from(["astatine", "mine", "--device", "cuda"]).is_err());
    }

    #[test]
    fn parses_benchmark_as_a_bounded_read_only_command() {
        assert_eq!(
            try_parse_from(["astatine", "devices"]).unwrap().command,
            Command::Devices
        );
        let default = try_parse_from(["astatine", "benchmark"]).unwrap();
        assert_eq!(
            default.command,
            Command::Benchmark(BenchmarkArgs {
                seconds: 10,
                threads: None,
                batch_size: None,
                workgroup_size: None,
                runs: 3,
                profile: false,
                compare_full_sha: false,
                serial: false,
                output_json: None,
            })
        );
        let explicit =
            try_parse_from(["astatine", "benchmark", "--seconds", "8", "--threads", "4"]).unwrap();
        assert_eq!(
            explicit.command,
            Command::Benchmark(BenchmarkArgs {
                seconds: 8,
                threads: NonZeroUsize::new(4),
                batch_size: None,
                workgroup_size: None,
                runs: 3,
                profile: false,
                compare_full_sha: false,
                serial: false,
                output_json: None,
            })
        );
        assert!(try_parse_from(["astatine", "benchmark", "--seconds", "0"]).is_err());
        assert!(try_parse_from(["astatine", "benchmark", "--seconds", "61"]).is_err());
        assert!(try_parse_from(["astatine", "benchmark", "--batch-size", "4096"]).is_err());
        assert!(try_parse_from(["astatine", "benchmark", "--workgroup-size", "16"]).is_err());
        assert!(try_parse_from(["astatine", "benchmark", "--runs", "2"]).is_err());

        let profile = try_parse_from([
            "astatine",
            "benchmark",
            "--batch-size",
            "65536",
            "--workgroup-size",
            "128",
            "--runs",
            "5",
            "--profile",
            "--compare-full-sha",
            "--serial",
            "--output-json",
            "profile.json",
        ])
        .unwrap();
        assert_eq!(
            profile.command,
            Command::Benchmark(BenchmarkArgs {
                seconds: 10,
                threads: None,
                batch_size: Some(65_536),
                workgroup_size: Some(128),
                runs: 5,
                profile: true,
                compare_full_sha: true,
                serial: true,
                output_json: Some(PathBuf::from("profile.json")),
            })
        );
    }

    #[test]
    fn parses_reward_destination_and_enforces_mixed_case_checksum() {
        let lowercase = try_parse_from([
            "astatine",
            "mine",
            "--device",
            "gpu",
            "--nodes",
            "1,2,3,4,5,6,7,8,9",
            "--threads",
            "16",
            "--send-rewards-to",
            "0x0000000000000000000000000000000000000001",
        ])
        .expect("lowercase EVM destination should parse");
        let Command::Mine(args) = lowercase.command else {
            panic!("expected mine subcommand");
        };
        assert_eq!(args.device, DeviceChoice::Gpu);
        assert_eq!(args.nodes, (1..=9).collect::<Vec<_>>());
        assert_eq!(args.threads.map(|threads| threads.get()), Some(16));
        assert_eq!(args.send_rewards_to, Some(Address::with_last_byte(1)));

        let gpu_compute = try_parse_from(["astatine", "mine", "--device", "gpu", "--compute-only"])
            .expect("GPU compute-only mode should parse");
        let Command::Mine(args) = gpu_compute.command else {
            panic!("expected mine subcommand");
        };
        assert_eq!(args.device, DeviceChoice::Gpu);
        assert!(args.compute_only);

        let checksummed = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        assert!(try_parse_from(["astatine", "mine", "--send-rewards-to", checksummed]).is_ok());
        assert!(
            try_parse_from([
                "astatine",
                "mine",
                "--send-rewards-to",
                "0xD8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            ])
            .is_err()
        );
        assert!(
            try_parse_from([
                "astatine",
                "mine",
                "--send-rewards-to",
                "0x0000000000000000000000000000000000000000"
            ])
            .is_err()
        );
        assert!(
            try_parse_from([
                "astatine",
                "mine",
                "--compute-only",
                "--send-rewards-to",
                checksummed
            ])
            .is_ok(),
            "the mining runtime rejects the deprecated option with the RPC-trust explanation"
        );
    }

    #[test]
    fn init_accepts_a_small_confirmation_depth() {
        let cli = try_parse_from([
            "astatine",
            "init",
            "--network",
            "testnet",
            "--confirmation-blocks",
            "4",
        ])
        .expect("init confirmation threshold should parse");
        let Command::Init(args) = cli.command else {
            panic!("expected init subcommand");
        };
        assert_eq!(args.transaction_confirmations, Some(4));
        assert_eq!(args.rpc, None);
        assert!(try_parse_from(["astatine", "init", "--confirmation-blocks", "0"]).is_err());
        assert!(try_parse_from(["astatine", "init", "--confirmation-blocks", "13"]).is_err());
    }

    #[test]
    fn rejects_zero_threads_and_unknown_nodes() {
        assert!(try_parse_from(["astatine", "mine", "--threads", "0"]).is_err());
        assert!(try_parse_from(["astatine", "mine", "--nodes", "1,10"]).is_err());
    }

    #[test]
    fn parses_wallet_and_network_command_paths() {
        let wallet = try_parse_from(["astatine", "wallet", "import"])
            .expect("wallet import command should parse");
        assert_eq!(
            wallet.command,
            Command::Wallet(WalletCommand::Import(ImportArgs {
                keystore: None,
                derivation_path: "m/44'/60'/0'/0/0".to_owned(),
            }))
        );

        let network = try_parse_from(["astatine", "network", "use", "mainnet"])
            .expect("network selection command should parse");
        assert_eq!(network.command, Command::NetworkUse(Network::Mainnet));

        let update = try_parse_from(["astatine", "update"]).expect("update command should parse");
        assert_eq!(
            update.command,
            Command::Update(super::UpdateArgs { check_only: false })
        );
        let check = try_parse_from(["astatine", "update", "--check"])
            .expect("update check command should parse");
        assert_eq!(
            check.command,
            Command::Update(super::UpdateArgs { check_only: true })
        );
    }

    #[test]
    fn parses_rpc_management_and_explicit_new_session_commands() {
        assert_eq!(
            try_parse_from(["astatine", "get", "rpc"]).unwrap().command,
            Command::GetRpc { network: None }
        );
        assert_eq!(
            try_parse_from(["astatine", "get", "rpc", "--network", "testnet"])
                .unwrap()
                .command,
            Command::GetRpc {
                network: Some(Network::Testnet)
            }
        );
        assert_eq!(
            try_parse_from([
                "astatine",
                "set",
                "rpc",
                "https://rpc.example.org/evm",
                "--network",
                "mainnet",
            ])
            .unwrap()
            .command,
            Command::SetRpc {
                network: Some(Network::Mainnet),
                endpoint: Some("https://rpc.example.org/evm".to_owned()),
            }
        );
        assert_eq!(
            try_parse_from(["astatine", "set", "rpc", "default"])
                .unwrap()
                .command,
            Command::SetRpc {
                network: None,
                endpoint: Some("default".to_owned()),
            }
        );
        assert_eq!(
            try_parse_from(["astatine", "set", "rpc"]).unwrap().command,
            Command::SetRpc {
                network: None,
                endpoint: None,
            }
        );
        assert_eq!(
            try_parse_from(["astatine", "init", "--rpc", "https://rpc.example.org"])
                .unwrap()
                .command,
            Command::Init(InitArgs {
                network: None,
                threads: None,
                minimum_reserve_inj: None,
                spending_limit_inj: None,
                transaction_confirmations: None,
                rpc: Some("https://rpc.example.org".to_owned()),
            })
        );

        let new_session = try_parse_from(["astatine", "mine", "--new-session"]).unwrap();
        let Command::Mine(args) = new_session.command else {
            panic!("expected mine subcommand");
        };
        assert!(args.new_session);
        assert!(try_parse_from(["astatine", "mine", "--new-session", "--compute-only"]).is_err());
    }
}
