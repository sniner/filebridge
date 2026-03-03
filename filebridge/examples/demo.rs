use filebridge::FileBridgeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = FileBridgeClient::new("http://localhost:8000")?;
    let loc = client.location("demo", Some("demo-secret-123".to_string()));

    println!("Listing files in 'demo'...");
    let files = loc.list(None).await?;
    for f in files {
        println!(
            " - {} ({} bytes, dir: {})",
            f.name,
            f.sha256.as_deref().unwrap_or("?"),
            f.is_dir
        );
    }

    println!("Writing 'client_test.txt'...");
    loc.write("client_test.txt", b"Hello from Rust Client!", None)
        .await?;

    println!("Reading 'client_test.txt'...");
    let content = loc.read("client_test.txt", None, None).await?;
    println!("Content: {}", String::from_utf8_lossy(&content));

    println!("Reading partial content (offset 6, length 4)...");
    let partial = loc.read("client_test.txt", Some(6), Some(4)).await?;
    println!("Partial Content: '{}'", String::from_utf8_lossy(&partial));

    println!("Deleting 'client_test.txt'...");
    loc.delete("client_test.txt").await?;

    println!("Success!");
    Ok(())
}
