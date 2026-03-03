import asyncio
import os

from filebridge import (
    AsyncFileBridgeClient,
    FileBridgeClient,
    NotFoundError,
)


def run_sync_demo(base_url, dir_id, token):
    print("--- Running Sync Demo ---")
    with FileBridgeClient(base_url) as client:
        loc = client.location(dir_id, token=token)

        # 1. Write a file
        print("Writing sync_test.txt...")
        loc.write("sync_test.txt", b"Hello from Sync Python!")

        # 2. List files
        print("\nListing files:")
        items = loc.list()
        for item in items:
            char = "/" if item.is_dir else " "
            print(f" {char} {item.name} ({item.sha256 or 'no-hash'})")

        # 3. Get Info
        print("\nGetting info for sync_test.txt:")
        info = loc.info("sync_test.txt")
        print(f" - Name: {info.name}, Hash: {info.sha256}")

        # 4. Read the file
        print("\nReading sync_test.txt...")
        content = loc.read("sync_test.txt")
        print(f"Content: {content.decode()}")

        # 5. Delete the test file
        print("\nDeleting sync_test.txt...")
        loc.delete("sync_test.txt")

        print("\nSync demo complete!")


async def run_async_demo(base_url, dir_id, token):
    print("\n--- Running Async Demo ---")
    async with AsyncFileBridgeClient(base_url) as client:
        loc = client.location(dir_id, token=token)

        # 1. Write a file
        print("Writing async_test.txt...")
        await loc.write("async_test.txt", b"Hello from Async Python!")

        # 2. List files
        print("\nListing files:")
        items = await loc.list()
        for item in items:
            char = "/" if item.is_dir else " "
            print(f" {char} {item.name}")

        # 3. Read the file
        print("\nReading async_test.txt...")
        content = await loc.read("async_test.txt")
        print(f"Content: {content.decode()}")

        # 4. Check error handling
        print("\nTesting error handling (non-existent file):")
        try:
            await loc.read("does_not_exist.txt")
        except NotFoundError:
            print("Caught expected NotFoundError")

        # 5. Delete the test file
        print("\nDeleting async_test.txt...")
        await loc.delete("async_test.txt")

        print("\nAsync demo complete!")


def main():
    base_url = os.environ.get("FILEBRIDGE_URL", "http://localhost:8000")
    token = os.environ.get("FILEBRIDGE_TOKEN", "demo-token")
    dir_id = "demo"

    run_sync_demo(base_url, dir_id, token)

    try:
        asyncio.run(run_async_demo(base_url, dir_id, token))
    except Exception as e:
        print(f"Async demo failed: {e}")


if __name__ == "__main__":
    main()
