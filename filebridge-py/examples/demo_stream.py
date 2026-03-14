import asyncio
import os

from filebridge import AsyncFileBridgeClient, FileBridgeClient


def test_sync(base_url, token):
    client = FileBridgeClient(base_url)
    loc = client.location("demo", token=token)

    # 1. Create a large test file (e.g. 5 MB) locally
    print("Creating local test file...")
    local_in = "test_large_in.dat"
    with open(local_in, "wb") as f:
        # Write 5 MB in 1 MB chunks
        for _ in range(5):
            f.write(os.urandom(1024 * 1024))

    # 2. Test stream write
    print("Testing stream write...", flush=True)
    with open(local_in, "rb") as f:
        loc.write_stream("/test_stream.dat", f)
    print("Stream write finished.", flush=True)

    # 3. Test stream read
    print("Testing stream read...", flush=True)
    local_out = "test_large_out.dat"
    with open(local_out, "wb") as f_out:
        with loc.read_stream("/test_stream.dat") as stream:
            print("Opened stream for reading, beginning reads...", flush=True)
            chunk_idx = 0
            while chunk := stream.read(1024 * 256):
                f_out.write(chunk)
                chunk_idx += 1
                if chunk_idx % 10 == 0:
                    print(f"Read {chunk_idx} chunks...", flush=True)
            print("Finished reading!", flush=True)

    # Verify size
    sz_in = os.path.getsize(local_in)
    sz_out = os.path.getsize(local_out)
    print(f"Sync Test Complete! Original: {sz_in}, Downloaded: {sz_out}")
    assert sz_in == sz_out


async def test_async(base_url, token):
    client = AsyncFileBridgeClient(base_url)
    loc = client.location("demo", token=token)

    print("Testing async stream write...")
    local_in = "test_large_in.dat"

    # Async read generator
    async def file_reader(filepath, chunk_size=1024 * 1024):
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                yield chunk

    await loc.write_stream("/test_stream_async.dat", file_reader(local_in))

    print("Testing async stream read...")
    local_out = "test_large_out_async.dat"
    with open(local_out, "wb") as f_out:
        async with loc.read_stream("/test_stream_async.dat") as stream:
            while chunk := await stream.read(1024 * 256):
                f_out.write(chunk)

    # Verify size
    sz_in = os.path.getsize(local_in)
    sz_out = os.path.getsize(local_out)
    print(f"Async Test Complete! Original: {sz_in}, Downloaded: {sz_out}")
    assert sz_in == sz_out


if __name__ == "__main__":
    url = "http://127.0.0.1:8000"
    tok = os.environ.get("FILEBRIDGE_TOKEN", "demo-token")

    try:
        test_sync(url, tok)
        asyncio.run(test_async(url, tok))
        print("ALL TESTS PASSED!")
    finally:
        # Clean up
        for f in ["test_large_in.dat", "test_large_out.dat", "test_large_out_async.dat"]:
            if os.path.exists(f):
                os.remove(f)
