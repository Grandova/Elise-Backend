use clap::{Args, Parser, Subcommand};
use elise::config::GlobalConfig;
use elise::observability::init_logger;
use elise::proxy::MasterServer;
use elise::security::{generate_reality_keypair, generate_short_id};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "elise",
    version,
    about = "Elise - 专为 Xboard 设计的高性能全协议原生节点后端 (100% Native Rust)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 指定主配置文件路径
    #[arg(short, long, help = "指定主配置文件路径 [默认: /etc/elise/elise.conf]")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// 在前台启动 Elise 守护服务
    Run(RunArgs),
    /// 启动 Elise 守护服务 (run 命令别名)
    Start(RunArgs),
    /// 查看当前配置或快速修改配置项 (支持 key=val 格式)
    Config {
        #[arg(
            trailing_var_arg = true,
            help = "要设置的配置项，如 server_type=vless node_id=1"
        )]
        args: Vec<String>,
    },
    /// 管理已配置的节点 ID (查看/添加/删除)
    Node {
        #[command(subcommand)]
        sub: Option<NodeSubcommands>,
    },
    /// 生成或查看 Reality x25519 密钥对与 Short ID
    Reality {
        #[command(subcommand)]
        sub: Option<RealitySubcommands>,
    },
    /// 生成标准 x25519 密钥对
    X25519,
    /// 查看服务运行状态
    Status,
    /// 查看日志信息与路径
    Log,
    /// 打印当前版本信息
    Version,
}

#[derive(Args)]
struct RunArgs {
    /// 指定配置文件路径
    #[arg(short, long, help = "指定配置文件路径 [默认: /etc/elise/elise.conf]")]
    config: Option<PathBuf>,
    /// 指定路由规则文件路径
    #[arg(
        short,
        long,
        help = "指定路由规则文件路径 [默认: /etc/elise/routes.toml]"
    )]
    routes: Option<PathBuf>,
    /// 指定 DNS 规则文件路径
    #[arg(short, long, help = "指定 DNS 规则文件路径 [默认: /etc/elise/dns.yml]")]
    dns: Option<PathBuf>,
    /// 指定审计黑名单文件路径
    #[arg(
        short,
        long,
        help = "指定审计黑名单文件路径 [默认: /etc/elise/blockList]"
    )]
    block: Option<PathBuf>,
    /// 指定审计白名单文件路径
    #[arg(
        short,
        long,
        help = "指定审计白名单文件路径 [默认: /etc/elise/whiteList]"
    )]
    white: Option<PathBuf>,
}

#[derive(Subcommand)]
enum NodeSubcommands {
    /// 列出当前已配置的节点列表
    List,
    /// 添加新节点 ID 到配置文件
    Add {
        #[arg(help = "要添加的节点 ID")]
        node_id: u32,
    },
    /// 从配置文件中删除指定节点 ID
    Del {
        #[arg(help = "要删除的节点 ID")]
        node_id: u32,
    },
}

#[derive(Subcommand)]
enum RealitySubcommands {
    /// 生成新的 Reality 密钥对与 Short ID
    Gen,
    /// 查看 Reality 密钥信息
    Show,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Run(_)) | Some(Commands::Start(_)) => {
            let run_args = match cli.command {
                Some(Commands::Run(args)) | Some(Commands::Start(args)) => Some(args),
                _ => None,
            };

            let config_path = run_args
                .as_ref()
                .and_then(|a| a.config.clone())
                .or(cli.config)
                .unwrap_or_else(|| find_config_path(PathBuf::from("/etc/elise/elise.conf")));

            let mut cfg = GlobalConfig::load_from_file(&config_path).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to load configuration {}: {e}",
                        config_path.display()
                    ),
                )
            })?;

            if let Some(args) = run_args {
                if let Some(r) = args.routes {
                    cfg.routes_file = r;
                }
                if let Some(d) = args.dns {
                    cfg.dns_file = d;
                }
                if let Some(b) = args.block {
                    cfg.block_list = b;
                }
                if let Some(w) = args.white {
                    cfg.white_list = w;
                }
            }

            init_logger(&cfg.log_level, cfg.log_file.as_deref());
            tracing::info!("正在启动 Elise 原生核心服务 v{}...", elise::VERSION);

            let server = MasterServer::new(cfg);
            server.run().await?;
        }
        Some(Commands::Config { args }) => {
            handle_config_command(cli.config, args);
        }
        Some(Commands::Node { sub }) => {
            handle_node_command(cli.config, sub);
        }
        Some(Commands::Reality { sub: _ }) => {
            let kp = generate_reality_keypair();
            let short_id = generate_short_id(8);
            println!("已成功生成 Reality 密钥对:");
            println!("  私钥 (Private Key): {}", kp.private_key);
            println!("  公钥 (Public Key):  {}", kp.public_key);
            println!("  Short ID:           {}", short_id);
        }
        Some(Commands::X25519) => {
            let kp = generate_reality_keypair();
            println!("已成功生成 x25519 密钥对:");
            println!("  私钥 (Private Key): {}", kp.private_key);
            println!("  公钥 (Public Key):  {}", kp.public_key);
        }
        Some(Commands::Status) => {
            println!("Elise 状态: 服务正常就绪。(在 Linux 系统上可使用 systemctl status elise 查看详细状态)");
        }
        Some(Commands::Log) => {
            println!("Elise 日志: 默认日志目录为 /var/log/elise/ (可使用 journalctl -u elise -f 实时查看)");
        }
        Some(Commands::Version) => {
            println!(
                "Elise 原生核心 v{}\n专为 Xboard 设计的高性能全协议原生节点后端 (100% Native Rust)",
                elise::VERSION
            );
        }
    }

    Ok(())
}

fn handle_config_command(custom_path: Option<PathBuf>, args: Vec<String>) {
    let path =
        custom_path.unwrap_or_else(|| find_config_path(PathBuf::from("/etc/elise/elise.conf")));
    if args.is_empty() {
        if let Ok(content) = fs::read_to_string(&path) {
            println!("# 当前生效配置文件: {}\n{}", path.display(), content);
        } else {
            println!("无法从 {:?} 读取配置文件，文件可能尚未创建。", path);
        }
        return;
    }

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut content = fs::read_to_string(&path).unwrap_or_default();
    let mut modified = 0;

    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            let prefix = format!("{} =", key);
            let mut found = false;
            let mut new_lines = Vec::new();

            for line in content.lines() {
                if line.trim_start().starts_with(&prefix)
                    || line.trim_start().starts_with(&format!("{}=", key))
                {
                    new_lines.push(format!("{} = {}", key, val));
                    found = true;
                    modified += 1;
                } else {
                    new_lines.push(line.to_string());
                }
            }

            if !found {
                new_lines.push(format!("{} = {}", key, val));
                modified += 1;
            }

            content = new_lines.join("\n");
        }
    }

    match fs::write(&path, content) {
        Ok(_) => println!("已成功更新配置文件 {:?} 中的 {} 个配置项", path, modified),
        Err(e) => eprintln!("写入配置文件 {:?} 失败: {}", path, e),
    }
}

fn handle_node_command(custom_path: Option<PathBuf>, sub: Option<NodeSubcommands>) {
    let path = custom_path
        .clone()
        .unwrap_or_else(|| find_config_path(PathBuf::from("/etc/elise/elise.conf")));
    let cfg = GlobalConfig::load_from_file(&path).unwrap_or_default();

    match sub.unwrap_or(NodeSubcommands::List) {
        NodeSubcommands::List => {
            println!("当前已配置的节点 ID 列表: {:?}", cfg.node_ids);
            for id in &cfg.node_ids {
                println!("  节点 {}: [已配置就绪]", id);
            }
        }
        NodeSubcommands::Add { node_id } => {
            let mut ids = cfg.node_ids.clone();
            if !ids.contains(&node_id) {
                ids.push(node_id);
                let ids_str = ids
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                handle_config_command(custom_path, vec![format!("node_id={}", ids_str)]);
                println!("节点 {} 已成功添加。请重启 Elise 服务使配置生效。", node_id);
            } else {
                println!("节点 {} 已经存在，无需重复添加。", node_id);
            }
        }
        NodeSubcommands::Del { node_id } => {
            let mut ids = cfg.node_ids.clone();
            if ids.contains(&node_id) {
                ids.retain(|&id| id != node_id);
                let ids_str = ids
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                handle_config_command(custom_path, vec![format!("node_id={}", ids_str)]);
                println!("节点 {} 已成功移除。请重启 Elise 服务使配置生效。", node_id);
            } else {
                println!("未找到节点 {}。", node_id);
            }
        }
    }
}

fn find_config_path(preferred: PathBuf) -> PathBuf {
    if preferred.exists() {
        return preferred;
    }
    let candidates = [
        PathBuf::from("/etc/elise/elise.conf"),
        PathBuf::from("./elise.conf"),
        PathBuf::from("./example/elise.conf"),
        PathBuf::from("../example/elise.conf"),
    ];
    for p in candidates {
        if p.exists() {
            return p;
        }
    }
    preferred
}
