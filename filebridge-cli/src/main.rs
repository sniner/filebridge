use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use filebridge::{Error, FileBridgeClient};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Optional token for HMAC authentication (can also be set via FILEBRIDGE_TOKEN env var)
    #[arg(long, env = "FILEBRIDGE_TOKEN", global = true)]
    token: Option<String>,

    /// Optional base URL of the Filebridge server (e.g., http://host:8000)
    #[arg(short = 'b', long, env = "FILEBRIDGE_BASE_URL", global = true)]
    base_url: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Download a file from the server
    Get {
        /// Target path (e.g., /loc/path/to/file)
        target: String,

        /// Local path to save the file (optional, defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Upload a file to the server
    Put {
        /// Target path (e.g., /loc/path/to/file) if no source is given (stdin),
        /// OR Source local file if two arguments are given.
        arg1: String,

        /// Target path (if first argument is the local source file).
        arg2: Option<String>,
    },
    /// List files in a location
    List {
        /// Target path (e.g., /loc)
        target: String,

        /// Output the list recursively as a tree
        #[arg(short, long)]
        tree: bool,
    },
    /// Check if a file exists (exit code 0 if exists, 1 if not)
    Exists {
        /// Target path (e.g., /loc/path/to/file)
        target: String,
    },
    /// Get detailed information about a file
    Info {
        /// Target path (e.g., /loc/path/to/file)
        target: String,
    },
    /// Delete a file from the server
    Delete {
        /// Target path (e.g., /loc/path/to/file)
        target: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let base_url_opt = cli.base_url.as_deref();

    match cli.command {
        Commands::Get { target, output } => {
            let (base_url, dir_id, filepath) = parse_target(&target, true, base_url_opt)?;
            let client = FileBridgeClient::new(&base_url)?;
            let loc = client.location(&dir_id, cli.token.clone());

            if let Some(path) = output {
                let mut file = tokio::fs::File::create(&path).await?;
                match loc.read_stream(&filepath, &mut file).await {
                    Ok(_) => {}
                    Err(Error::IsDirectory) => {
                        anyhow::bail!(
                            "{:?} is a directory. Use 'list' to see its content.",
                            filepath
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
            } else {
                let mut stdout = tokio::io::stdout();
                match loc.read_stream(&filepath, &mut stdout).await {
                    Ok(_) => {}
                    Err(Error::IsDirectory) => {
                        anyhow::bail!(
                            "{:?} is a directory. Use 'list' to see its content.",
                            filepath
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Commands::Put { arg1, arg2 } => {
            let (target, source_file) = if let Some(target) = arg2 {
                (target, Some(PathBuf::from(arg1)))
            } else {
                (arg1, None)
            };

            let (base_url, dir_id, filepath) = parse_target(&target, true, base_url_opt)?;
            let client = FileBridgeClient::new(&base_url)?;
            let loc = client.location(&dir_id, cli.token);

            if let Some(path) = source_file {
                let file = tokio::fs::File::open(&path)
                    .await
                    .context(format!("Failed to open file {:?}", path))?;
                loc.write_stream(&filepath, file).await?;
            } else {
                let stdin = tokio::io::stdin();
                loc.write_stream(&filepath, stdin).await?;
            }
        }
        Commands::List { target, tree } => {
            let (base_url, dir_id, filepath) = parse_target(&target, false, base_url_opt)?;
            let client = FileBridgeClient::new(&base_url)?;
            let loc = client.location(&dir_id, cli.token);

            let path_opt = if filepath.is_empty() {
                None
            } else {
                Some(filepath.as_str())
            };

            if tree {
                let root_name = if filepath.is_empty() {
                    dir_id.clone()
                } else {
                    filepath.split('/').next_back().unwrap_or(&filepath).to_string()
                };
                println!("{}", root_name);
                let path_str = path_opt.map(|s| s.to_string());
                print_tree(&loc, path_str, String::new()).await?;
            } else {
                let items = loc.list(path_opt).await?;
                for item in items {
                    if item.is_dir {
                        println!("{}/", item.name);
                    } else {
                        println!("{}", item.name);
                    }
                }
            }
        }
        Commands::Exists { target } => {
            let (base_url, dir_id, filepath) = parse_target(&target, true, base_url_opt)?;
            let client = FileBridgeClient::new(&base_url)?;
            let loc = client.location(&dir_id, cli.token);

            match loc.info(&filepath).await {
                Ok(_) => {}
                Err(Error::Api(status, _)) if status.as_u16() == 404 => {
                    anyhow::bail!("Not found: {}", filepath);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Commands::Info { target } => {
            let (base_url, dir_id, filepath) = parse_target(&target, true, base_url_opt)?;
            let client = FileBridgeClient::new(&base_url)?;
            let loc = client.location(&dir_id, cli.token);

            let info = loc.info(&filepath).await?;
            println!("Name: {}", info.name);
            println!("Type: {}", if info.is_dir { "Directory" } else { "File" });
            if let Some(size) = info.size {
                println!("Size: {} bytes", size);
            }
            if let Some(mtime) = info.mtime {
                println!("Modified: {}", mtime.format("%Y-%m-%dT%H:%M:%SZ"));
            }
            if let Some(sha256) = info.sha256 {
                println!("SHA256: {}", sha256);
            }
        }
        Commands::Delete { target } => {
            let (base_url, dir_id, filepath) = parse_target(&target, true, base_url_opt)?;
            let client = FileBridgeClient::new(&base_url)?;
            let loc = client.location(&dir_id, cli.token);

            loc.delete(&filepath).await?;
        }
    }

    Ok(())
}

/// Parses a target Unix-like path into (base_url, dir_id, filepath)
/// Expected format for path: /{dir_id}[/{filepath}] (requires cli_base_url)
fn parse_target(
    target: &str,
    require_file: bool,
    cli_base_url: Option<&str>,
) -> Result<(String, String, String)> {
    let base_url_str = cli_base_url
        .ok_or_else(|| {
            anyhow::anyhow!(
                "A base URL is required. Provide --base-url or set FILEBRIDGE_BASE_URL env var."
            )
        })?
        .trim_end_matches('/');

    let target = target.trim_start_matches('/');
    let segments: Vec<_> = target.split('/').collect();

    if segments.is_empty() || segments[0].is_empty() {
        anyhow::bail!("Path must at least contain a location (e.g., /location)");
    }

    let dir_id = segments[0].to_string();

    if require_file && segments.len() < 2 {
        anyhow::bail!("Path is missing the file component (e.g., /location/file.txt)");
    }

    let filepath = if segments.len() > 1 {
        segments[1..].join("/")
    } else {
        String::new()
    };

    Ok((base_url_str.to_string(), dir_id, filepath))
}

fn print_tree<'a>(
    loc: &'a filebridge::FileBridgeLocation<'_>,
    current_path: Option<String>,
    prefix: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let path_ref = current_path.as_deref();
        let mut items = loc.list(path_ref).await?;
        items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        let count = items.len();
        for (i, item) in items.into_iter().enumerate() {
            let is_last = i == count - 1;
            let node_prefix = if is_last { "└── " } else { "├── " };

            if item.is_dir {
                println!("{}{}{}/", prefix, node_prefix, item.name);

                let child_prefix = if is_last { "    " } else { "│   " };
                let child_path = if let Some(p) = &current_path {
                    if p.is_empty() {
                        item.name.clone()
                    } else {
                        format!("{}/{}", p, item.name)
                    }
                } else {
                    item.name.clone()
                };

                print_tree(loc, Some(child_path), format!("{}{}", prefix, child_prefix)).await?;
            } else {
                println!("{}{}{}", prefix, node_prefix, item.name);
            }
        }

        Ok(())
    })
}
