# filebridge-mcp

MCP server (stdio transport) for [Filebridge](../README.md). Allows Claude Code and other MCP clients to access files through a running `filebridged` server.

## Build

```bash
cargo build -p filebridge-mcp --release
```

The binary is placed at `target/release/filebridge-mcp`.

## Configuration

### Single-Location Mode (Environment Variables)

The simplest setup: configure one Filebridge location via environment variables.

| Variable | Required | Description | Default |
|---|---|---|---|
| `FILEBRIDGE_BASE_URL` | Yes | URL of the `filebridged` server | – |
| `FILEBRIDGE_TOKEN` | No | Authentication token | – |
| `FILEBRIDGE_LOCATION_NAME` | No | Server-side location name | `default` |
| `FILEBRIDGE_LOCATION_ALIAS` | No | MCP-local shortcut used by tools (if different from the server name) | = `FILEBRIDGE_LOCATION_NAME` |
| `FILEBRIDGE_READ_SIZE_LIMIT` | No | Maximum file size for `read_file` (bytes) | `10485760` (10 MiB) |

### Multi-Location Mode (TOML Configuration File)

To use multiple Filebridge servers simultaneously, specify a TOML file:

```bash
FILEBRIDGE_MCP_CONFIG=/path/to/config.toml filebridge-mcp
```

TOML file format:

```toml
[[location]]
name = "demo"
base_url = "http://localhost:8000"
token = "secret-token"

[[location]]
# name is the server-side location identifier (required)
name = "raw-data"
# alias is optional — a MCP-local shortcut if you want to refer to this
# location by a different name in the tools
alias = "archive"
base_url = "http://storage-server:8000"
# token is optional
```

`FILEBRIDGE_MCP_CONFIG` takes precedence — when set, other environment variables are ignored.

## Registering with Claude Code

MCP servers are registered in Claude Code via the CLI, **not** in `settings.json`:

```bash
claude mcp add filebridge --scope user \
  /path/to/filebridge-mcp \
  -e FILEBRIDGE_BASE_URL=http://localhost:8000 \
  -e FILEBRIDGE_TOKEN=secret-token \
  -e FILEBRIDGE_LOCATION_NAME=default
```

`--scope user` registers the server globally for all projects (in `~/.claude.json`).
Use `--scope project` instead for a project-local registration (in `.mcp.json`).

To update an existing entry, remove it first and re-add:

```bash
claude mcp remove filebridge
claude mcp add filebridge --scope user ...
```

### Multi-Location with TOML

```bash
claude mcp add filebridge --scope user \
  /path/to/filebridge-mcp \
  -e FILEBRIDGE_MCP_CONFIG=/home/user/.config/filebridge/locations.toml
```

### Enabling Logging

Since stdout is reserved for MCP frames, all output goes to stderr:

```bash
claude mcp add filebridge --scope user \
  /path/to/filebridge-mcp \
  -e FILEBRIDGE_BASE_URL=http://localhost:8000 \
  -e RUST_LOG=info
```

## Available Tools

All tools take a `location` parameter — either the configured `alias` or, if no alias is set, the `name`.

| Tool | Description |
|---|---|
| `file_exists` | Checks whether a file or directory exists |
| `get_info` | Returns metadata (size, date, SHA-256) |
| `list_directory` | Lists the contents of a directory |
| `glob_files` | Matches files against a glob pattern (`*`, `?`, `[seq]`, `**`) |
| `query_files` | Filters, sorts, and limits entries (size, mtime, kind, glob) |
| `read_file` | Reads a file (encoding: `auto`, `text`, `base64`) |
| `write_file` | Writes a file (encoding: `text`, `base64`) |
| `delete_file` | Deletes a file |

### `query_files` Details

LLM-oriented combined filter/sort/limit. All filters are AND-combined.

- `pattern`: optional glob (e.g. `**/*.csv`); overrides `path` and matches recursively
- `path`: directory to query when no `pattern` is given (default: location root)
- `kind`: `file`, `dir`, or `any` (default)
- `min_size`, `max_size`: byte bounds (inclusive)
- `modified_after`, `modified_before`: ISO 8601 date or RFC 3339 timestamp
- `sort_by`: `name`, `size`, or `mtime`. Missing values sort last
- `order`: `asc` (default) or `desc`
- `limit`: cap on results; the `truncated` flag indicates whether more matched

### `read_file` Details

- `encoding=auto` (default): UTF-8 text if possible, otherwise Base64
- `encoding=text`: Error if the file is not valid UTF-8
- `encoding=base64`: Always Base64, regardless of content
- `offset` / `length`: Read a byte range (bypasses the size limit)
- Without `offset`/`length`: Size is checked against `FILEBRIDGE_READ_SIZE_LIMIT`

### `write_file` Details

- `encoding=text` (default): Content is written directly as UTF-8
- `encoding=base64`: Content is Base64-decoded before writing
- `offset`: Write starting at a specific byte offset

## Manual Testing with MCP Inspector

```bash
FILEBRIDGE_BASE_URL=http://localhost:8000 \
FILEBRIDGE_TOKEN=demo-token \
FILEBRIDGE_LOCATION_NAME=demo \
  npx @modelcontextprotocol/inspector \
  cargo run -p filebridge-mcp
```
