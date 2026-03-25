use filebridge::{Error, FileBridgeClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = std::env::var("FILEBRIDGE_URL").unwrap_or("http://localhost:8000".into());
    let token = std::env::var("FILEBRIDGE_TOKEN").ok();
    let dir_id = std::env::var("FILEBRIDGE_DIR").unwrap_or("demo".into());

    let client = FileBridgeClient::new(&base_url)?;
    let loc = client.location(&dir_id, token);

    // List directory contents (now includes size and mdate)
    println!("Listing files in '{dir_id}'...");
    let files = loc.list(None).await?;
    for f in &files {
        if f.is_dir {
            println!("  [dir]  {}/", f.name);
        } else {
            let size = f.size.map_or("?".into(), |s| format!("{s}"));
            let mdate = f.mdate.as_deref().unwrap_or("?");
            println!("  [file] {} ({} bytes, {mdate})", f.name, size);
        }
    }

    // Write a file
    println!("\nWriting 'client_test.txt'...");
    loc.write("client_test.txt", b"Hello from Rust Client!", None)
        .await?;

    // Get file info
    println!("Getting info for 'client_test.txt'...");
    let meta = loc.info("client_test.txt").await?;
    println!(
        "  name={}, size={:?}, mdate={:?}",
        meta.name, meta.size, meta.mdate
    );

    // Get file info with SHA-256 hash
    println!("Getting info with hash (extensive=true)...");
    let meta = loc.info_extensive("client_test.txt").await?;
    println!(
        "  sha256={}",
        meta.sha256.as_deref().unwrap_or("none")
    );

    // Read the file
    println!("\nReading 'client_test.txt'...");
    let content = loc.read("client_test.txt", None, None).await?;
    println!("  Content: {}", String::from_utf8_lossy(&content));

    // Read partial content
    println!("Reading partial (offset=6, length=4)...");
    let partial = loc.read("client_test.txt", Some(6), Some(4)).await?;
    println!("  Partial: '{}'", String::from_utf8_lossy(&partial));

    // Error handling: read non-existent file
    println!("\nReading non-existent file...");
    match loc.read("does_not_exist.txt", None, None).await {
        Err(Error::Api(status, msg)) => println!("  Expected error: {status} - {msg}"),
        other => println!("  Unexpected result: {other:?}"),
    }

    // Clean up
    println!("\nDeleting 'client_test.txt'...");
    loc.delete("client_test.txt").await?;

    println!("Done!");
    Ok(())
}
