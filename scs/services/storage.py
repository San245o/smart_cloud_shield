"""Storage abstraction: local folder or S3."""
import os
from pathlib import Path

from scs.config import Config


class LocalStorage:
    def __init__(self, dirpath):
        self.dir = Path(dirpath)
        self.dir.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, data: bytes):
        (self.dir / key).write_bytes(data)

    def get(self, key: str) -> bytes:
        return (self.dir / key).read_bytes()

    def delete(self, key: str):
        (self.dir / key).unlink(missing_ok=True)


class S3Storage:
    def __init__(self, bucket: str):
        self.bucket = bucket
        import boto3

        self.s3 = boto3.client("s3")

    def put(self, key: str, data: bytes):
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=data)

    def get(self, key: str) -> bytes:
        return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def delete(self, key: str):
        self.s3.delete_object(Bucket=self.bucket, Key=key)


def get_storage(base=None):
    if os.environ.get("STORAGE_BACKEND", "").lower() == "s3":
        return S3Storage(os.environ["S3_BUCKET"])
    blob_dir = (
        os.environ.get("BLOB_DIR")
        or (Path(base) / "instance" / "blobs" if base else Config.INSTANCE_DIR / "blobs")
    )
    return LocalStorage(blob_dir)
