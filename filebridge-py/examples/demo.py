from __future__ import annotations

import os

from filebridge import FileBridgeClient, NotFoundError

TEST_FILE_NAME = "test.txt"


def run_demo(base_url: str, dir_id: str, token: str | None):
    print("--- Running Demo ---")
    with FileBridgeClient(base_url) as client:
        loc = client.location(dir_id, token=token)

        # 1. Write a file
        print("Writing test file...")
        loc.write(TEST_FILE_NAME, b"Hello from Sync Python!")

        # 2. Show a very simple directory tree
        print("\nListing directory entries:")
        for item in loc.glob("**"):
            depth = len(item.path.parts)
            indent = "  " * depth
            if item.is_dir():
                print(f"{indent}{item.name}/")
            else:
                print(f"{indent}{item.name}: {item.stat().mtime}")

        # 3. Get Info
        print("\nGetting metadata for test file:")
        info = loc.info(TEST_FILE_NAME)
        print(f"  Name: {info.name}\n  Size: {info.size}\n  Hash: {info.sha256}")

        # 4. Read the file
        print("\nReading test file...")
        content = loc.read(TEST_FILE_NAME)
        print(f"Content: {content.decode()}")

        # 5. Delete the test file
        print("\nDeleting test file...")
        loc.delete(TEST_FILE_NAME)

        # 6. This is expected to fail
        print("\nAccessing non-existing file...")
        try:
            _ = loc.info("this-does-not-exist.txt")
        except NotFoundError as e:
            print(f"Expected error: {e}")

        print("\nFileBridgeClient demo complete!")


def main():
    base_url = os.environ.get("FILEBRIDGE_URL", "http://localhost:8000")
    token = os.environ.get("FILEBRIDGE_TOKEN", "demo-token")
    dir_id = "demo"

    run_demo(base_url, dir_id, token)


if __name__ == "__main__":
    main()
