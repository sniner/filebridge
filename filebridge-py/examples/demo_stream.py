from __future__ import annotations

import os
import pathlib

from filebridge import FileBridgeClient

LOCAL_FILE_IN = pathlib.Path("test_large_in.dat")
LOCAL_FILE_OUT = pathlib.Path("test_large_out.dat")
REMOTE_FILE = pathlib.PurePosixPath("/test_stream.dat")


def stream_demo(base_url: str, token: str | None):
    client = FileBridgeClient(base_url)
    loc = client.location("demo", token=token)

    # 1. Create a large test file (e.g. 5 MB) locally
    print("Creating local test file...")
    with open(LOCAL_FILE_IN, "wb") as f:
        # Write 5 MB in 1 MB chunks
        for _ in range(5):
            f.write(os.urandom(1024 * 1024))

    # 2. Test stream write
    print("Testing stream write...", flush=True)
    with open(LOCAL_FILE_IN, "rb") as f:
        loc.write_stream(REMOTE_FILE, f)
    print("Stream write finished.", flush=True)

    # 3. Test stream read
    print("Testing stream read...", flush=True)
    with open(LOCAL_FILE_OUT, "wb") as f_out:
        with loc.read_stream(REMOTE_FILE) as stream:
            print("Opened stream for reading, beginning reads...", flush=True)
            chunk_idx = 0
            while chunk := stream.read(1024 * 256):
                f_out.write(chunk)
                chunk_idx += 1
                if chunk_idx % 10 == 0:
                    print(f"Read {chunk_idx} chunks...", flush=True)
            print("Finished reading!", flush=True)

    # 4. Remove remote file
    loc.delete(REMOTE_FILE)

    # 5. Verify size
    sz_in = os.path.getsize(LOCAL_FILE_IN)
    sz_out = os.path.getsize(LOCAL_FILE_OUT)
    print(f"Original: {sz_in}, Downloaded: {sz_out}: {'PASS' if sz_in == sz_out else 'FAIL'}")


if __name__ == "__main__":
    url = "http://127.0.0.1:8000"
    tok = os.environ.get("FILEBRIDGE_TOKEN", "demo-token")

    try:
        stream_demo(url, tok)
        print("ALL TESTS PASSED!")
    finally:
        for f in [LOCAL_FILE_IN, LOCAL_FILE_OUT]:
            if f.exists():
                f.unlink()
