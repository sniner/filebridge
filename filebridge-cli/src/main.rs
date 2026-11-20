//! Command-line interface for the Filebridge file access API.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use filebridge::{Error, FileBridgeClient, FileBridgeLocation, Metadata};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    /// Download file(s) from the server (supports glob patterns)
    Get {
        /// Target path(s), supports glob patterns (e.g., /loc/path/*.txt)
        #[arg(required = true)]
        targets: Vec<String>,

        /// Output file or directory (required when multiple files match)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Overwrite existing local files
        #[arg(short, long)]
        force: bool,
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

        /// Include SHA-256 hashes in the output
        #[arg(short, long)]
        extensive: bool,
    },
    /// Check if a file exists (exit code 0 if it exists, 1 if not, 2 if that could not be found out)
    Exists {
        /// Target path (e.g., /loc/path/to/file)
        target: String,
    },
    /// Get detailed information about a file
    Info {
        /// Target path (e.g., /loc/path/to/file)
        target: String,

        /// Include SHA-256 hash
        #[arg(short, long)]
        extensive: bool,
    },
    /// Delete a file from the server
    Delete {
        /// Target path (e.g., /loc/path/to/file)
        target: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let base_url_opt = cli.base_url.as_deref();

    match cli.command {
        Commands::Get {
            targets,
            output,
            force,
        } => {
            cmd_get(
                &targets,
                output.as_deref(),
                force,
                base_url_opt,
                cli.token.as_deref(),
            )
            .await?;
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
        Commands::List {
            target,
            tree,
            extensive,
        } => {
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
                    filepath
                        .split('/')
                        .next_back()
                        .unwrap_or(&filepath)
                        .to_string()
                };
                println!("{}", root_name);
                let path_str = path_opt.map(|s| s.to_string());
                print_tree(&loc, path_str, String::new()).await?;
            } else {
                let items = if extensive {
                    loc.list_extensive(path_opt).await?
                } else {
                    loc.list(path_opt).await?
                };
                print_listing(&items, extensive);
            }
        }
        Commands::Exists { target } => {
            // Exit code 1 is the answer "no". Not getting an answer is 2, so
            // that a script can tell the two apart.
            return Ok(match exists(&target, base_url_opt, cli.token).await {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => {
                    eprintln!("Not found: {target}");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("Error: cannot tell whether {target} exists: {e:#}");
                    ExitCode::from(2)
                }
            });
        }
        Commands::Info { target, extensive } => {
            let (base_url, dir_id, filepath) = parse_target(&target, true, base_url_opt)?;
            let client = FileBridgeClient::new(&base_url)?;
            let loc = client.location(&dir_id, cli.token);

            let info = if extensive {
                loc.info_extensive(&filepath).await?
            } else {
                loc.info(&filepath).await?
            };
            println!("Name: {}", info.name);
            println!("Type: {}", if info.is_dir { "Directory" } else { "File" });
            if let Some(size) = info.size {
                println!("Size: {} bytes", size);
            }
            if let Some(mtime) = info.mtime {
                println!(
                    "Modified: {}",
                    mtime
                        .with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M:%S")
                );
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

    Ok(ExitCode::SUCCESS)
}

async fn exists(target: &str, base_url_opt: Option<&str>, token: Option<String>) -> Result<bool> {
    let (base_url, dir_id, filepath) = parse_target(target, true, base_url_opt)?;
    let client = FileBridgeClient::new(&base_url)?;
    let loc = client.location(&dir_id, token);

    match loc.info(&filepath).await {
        Ok(_) => Ok(true),
        Err(Error::Api(status, _)) if status.as_u16() == 404 => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Downloads `path` to the local file `dest`.
///
/// The content goes to a file next to `dest` that takes its name when the
/// download is complete. A download that fails leaves no partial file behind
/// and does not touch a file that `dest` already names.
async fn download(loc: &FileBridgeLocation<'_>, path: &str, dest: &Path) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // A device or a pipe is written to as it is; a rename would replace it.
    if let Ok(meta) = tokio::fs::metadata(dest).await
        && !meta.is_file()
    {
        let mut file = tokio::fs::OpenOptions::new().write(true).open(dest).await?;
        loc.read_stream(path, &mut file).await?;
        file.flush().await?;
        return Ok(());
    }

    // Fails if the name is taken, so that no file of someone else is
    // overwritten here or removed below.
    let part = part_path(dest);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)
        .await
        .with_context(|| format!("cannot create {}", part.display()))?;
    let result = async {
        loc.read_stream(path, &mut file).await?;
        file.flush().await?;
        drop(file);
        tokio::fs::rename(&part, dest)
            .await
            .with_context(|| format!("cannot rename {} to {}", part.display(), dest.display()))
    }
    .await;

    if result.is_err()
        && let Err(e) = tokio::fs::remove_file(&part).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("Cannot remove the partial download {}: {e}", part.display());
    }
    result
}

/// The file a download to `dest` is written to until it is complete. The
/// process id in the name keeps two downloads to the same destination, each
/// by its own `filebridge` process, apart.
fn part_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.part", std::process::id()));
    dest.with_file_name(name)
}

/// Resolved file entry ready for download.
struct ResolvedFile {
    base_url: String,
    dir_id: String,
    path: String,
    filename: String,
}

async fn cmd_get(
    targets: &[String],
    output: Option<&std::path::Path>,
    force: bool,
    base_url_opt: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    // Phase 1: resolve all targets via glob
    let mut files: Vec<ResolvedFile> = Vec::new();

    for target in targets {
        let (base_url, dir_id, pattern) = parse_target(target, true, base_url_opt)?;
        let client = FileBridgeClient::new(&base_url)?;
        let loc = client.location(&dir_id, token.map(String::from));

        let entries = loc.glob(&pattern).await?;
        if entries.is_empty() {
            anyhow::bail!("No files matched: {}", target);
        }

        for entry in entries {
            if entry.metadata.is_dir {
                continue; // skip directories, only download files
            }
            let filename = entry
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&entry.path)
                .to_string();
            files.push(ResolvedFile {
                base_url: base_url.clone(),
                dir_id: dir_id.clone(),
                path: entry.path,
                filename,
            });
        }
    }

    if files.is_empty() {
        anyhow::bail!("No files matched");
    }

    // Phase 2: dispatch based on count and output mode
    if files.len() == 1 {
        let f = &files[0];
        let client = FileBridgeClient::new(&f.base_url)?;
        let loc = client.location(&f.dir_id, token.map(String::from));

        if let Some(out) = output {
            // -o given: could be a file path or a directory
            let dest = if out.is_dir() {
                out.join(&f.filename)
            } else {
                out.to_path_buf()
            };
            if dest.exists() && !force {
                eprintln!(
                    "Skipping {:?}: file already exists (use --force to overwrite)",
                    dest
                );
            } else {
                download(&loc, &f.path, &dest).await?;
            }
        } else {
            // No -o: write to stdout
            let mut stdout = tokio::io::stdout();
            loc.read_stream(&f.path, &mut stdout).await?;
        }
    } else {
        // Multiple files: -o must be a directory
        let out_dir = output.ok_or_else(|| {
            anyhow::anyhow!(
                "Multiple files matched ({}). Use -o <directory> to specify a destination.",
                files.len()
            )
        })?;

        if !out_dir.is_dir() {
            anyhow::bail!(
                "{:?} is not a directory. When downloading multiple files, -o must be a directory.",
                out_dir
            );
        }

        let mut seen_filenames = std::collections::HashSet::new();
        let mut failed = 0usize;

        for f in &files {
            if !seen_filenames.insert(&f.filename) {
                eprintln!(
                    "Skipping {:?} (from {}): duplicate filename",
                    f.filename, f.path
                );
                continue;
            }

            let dest = out_dir.join(&f.filename);
            if dest.exists() && !force {
                eprintln!(
                    "Skipping {:?}: file already exists (use --force to overwrite)",
                    dest
                );
                continue;
            }

            let client = FileBridgeClient::new(&f.base_url)?;
            let loc = client.location(&f.dir_id, token.map(String::from));
            match download(&loc, &f.path, &dest).await {
                Ok(()) => {
                    eprintln!("{}", f.path);
                }
                Err(e) => {
                    failed += 1;
                    eprintln!("Error downloading {}: {e:#}", f.path);
                }
            }
        }

        if failed > 0 {
            anyhow::bail!("{failed} file(s) could not be downloaded");
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

fn format_size(size: u64) -> String {
    const KI: u64 = 1024;
    const MI: u64 = 1024 * KI;
    const GI: u64 = 1024 * MI;
    const TI: u64 = 1024 * GI;
    if size >= TI {
        format!("{:.1}T", size as f64 / TI as f64)
    } else if size >= GI {
        format!("{:.1}G", size as f64 / GI as f64)
    } else if size >= MI {
        format!("{:.1}M", size as f64 / MI as f64)
    } else if size >= KI {
        format!("{:.1}K", size as f64 / KI as f64)
    } else {
        format!("{size}")
    }
}

fn print_listing(items: &[Metadata], extensive: bool) {
    // Determine column width for size
    let size_width = items
        .iter()
        .filter_map(|m| m.size.map(|s| format_size(s).len()))
        .max()
        .unwrap_or(0);

    for item in items {
        let type_char = if item.is_dir { 'd' } else { '-' };
        let size_str = match item.size {
            Some(s) => format!("{:>width$}", format_size(s), width = size_width),
            None => format!("{:>width$}", "-", width = size_width),
        };
        let mtime_str = match &item.mtime {
            Some(dt) => dt
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string(),
            None => "                ".to_string(),
        };
        if extensive {
            let hash_str = match &item.sha256 {
                Some(h) => h.as_str(),
                None => "",
            };
            // SHA-256 hex is 64 chars; pad/align for directories without hash
            println!(
                "{type_char} {size_str}  {mtime_str}  {hash_str:64}  {}",
                item.name
            );
        } else {
            println!("{type_char} {size_str}  {mtime_str}  {}", item.name);
        }
    }
}

fn print_tree<'a>(
    loc: &'a filebridge::FileBridgeLocation<'_>,
    current_path: Option<String>,
    prefix: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let path_ref = current_path.as_deref();
        let mut items = loc.list(path_ref).await?;
        items.sort_by_key(|a| a.name.to_lowercase());

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Starts a server that answers one request with `response` and closes
    /// the connection. Returns its base URL.
    async fn serve_once(response: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // The request fits into one read; its content does not matter.
            let mut request = [0u8; 4096];
            let received = socket.read(&mut request).await.unwrap();
            assert!(received > 0);
            socket.write_all(response).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        format!("http://{addr}")
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn part_path_is_next_to_the_destination() {
        let pid = std::process::id();
        assert_eq!(
            part_path(Path::new("out/report.pdf")),
            Path::new("out").join(format!("report.pdf.{pid}.part"))
        );
        assert_eq!(
            part_path(Path::new("report")),
            PathBuf::from(format!("report.{pid}.part"))
        );
    }

    #[tokio::test]
    async fn download_replaces_the_destination_when_complete() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("a.bin");
        std::fs::write(&dest, b"old").unwrap();

        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
              Content-Length: 10\r\nConnection: close\r\n\r\n0123456789",
        )
        .await;
        let client = FileBridgeClient::new(&url).unwrap();
        let loc = client.location("loc", None);

        download(&loc, "a.bin", &dest).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"0123456789");
        assert_eq!(names_in(tmp.path()), ["a.bin"]);
    }

    #[tokio::test]
    async fn download_that_breaks_off_leaves_the_destination_as_it_was() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("a.bin");
        std::fs::write(&dest, b"old").unwrap();

        // Announces 100 bytes and closes the connection after 10.
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
              Content-Length: 100\r\nConnection: close\r\n\r\n0123456789",
        )
        .await;
        let client = FileBridgeClient::new(&url).unwrap();
        let loc = client.location("loc", None);

        assert!(download(&loc, "a.bin", &dest).await.is_err());
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert_eq!(names_in(tmp.path()), ["a.bin"]);
    }

    #[tokio::test]
    async fn download_does_not_touch_a_file_that_has_the_name_of_its_part_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("a.bin");
        let taken = part_path(&dest);
        std::fs::write(&taken, b"not a download").unwrap();

        // Fails before anything is requested.
        let client = FileBridgeClient::new("http://127.0.0.1:9").unwrap();
        let loc = client.location("loc", None);

        assert!(download(&loc, "a.bin", &dest).await.is_err());
        assert_eq!(std::fs::read(&taken).unwrap(), b"not a download");
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn exists_tells_a_missing_file_from_a_failed_check() {
        let found = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\
              Content-Length: 31\r\n\r\n{\"name\":\"a.txt\",\"is_dir\":false}",
        )
        .await;
        assert!(exists("/loc/a.txt", Some(&found), None).await.unwrap());

        let missing = serve_once(
            b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 14\r\n\r\npath not found",
        )
        .await;
        assert!(!exists("/loc/a.txt", Some(&missing), None).await.unwrap());

        let broken = serve_once(
            b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(exists("/loc/a.txt", Some(&broken), None).await.is_err());
    }
}
