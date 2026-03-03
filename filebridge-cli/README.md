# Filebridge CLI

The CLI uses the `filebridge` library to provide a convenient tool for terminal operations against a `filebridged` server.

## Getting Started

### Configuration

You can set the secret token via an environment variable:

```bash
export FILEBRIDGE_TOKEN="your-secret-key"
```

### Usage Examples

```bash
# Upload from stdin
echo "Hello" | filebridge-cli --base-url http://localhost:8000 put /demo/stdin.txt

# Upload a file
filebridge-cli --base-url http://localhost:8000 put ./local.txt /demo/remote.txt

# Download a file (defaults to stdout)
filebridge-cli --base-url http://localhost:8000 get /demo/remote.txt > downloaded.txt

# Download to a specific file
filebridge-cli --base-url http://localhost:8000 get /demo/remote.txt -o ./save_here.txt

# List files in a location (or tree view)
filebridge-cli --base-url http://localhost:8000 list /demo
filebridge-cli --base-url http://localhost:8000 list -t /demo

# Get detailed information about a file
filebridge-cli --base-url http://localhost:8000 info /demo/remote.txt

# Check if a file exists (exit code 0 if found, 1 if not)
filebridge-cli --base-url http://localhost:8000 exists /demo/nonexistent.txt || echo "Not found"

# Delete a file
filebridge-cli --base-url http://localhost:8000 delete /demo/remote.txt
```
