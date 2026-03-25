from filebridge import FileBridgeClient

client = FileBridgeClient("http://localhost:8000")
loc = client.location("demo", token="demo-token")

# Read metadata for a file
info = loc.info("/file.txt")
print(f"File size: {info.size} bytes")

# Read a file
data = loc.read("/file.txt")
print(f"File content: {data}")
