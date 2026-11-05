import base64
import os
import tarfile
import tempfile
import urllib.request
import urllib.error

from pathlib import Path


DATABASES = {
    "city": {
        "url": (
            "https://download.maxmind.com/"
            "geoip/databases/GeoLite2-City/download?suffix=tar.gz"
        ),
        "filename": "GeoLite2-City.mmdb",
        "env_path": "GEOIP_DB_PATH",
        "default_path": "/tmp/GeoLite2-City.mmdb",
    },
    "asn": {
        "url": (
            "https://download.maxmind.com/"
            "geoip/databases/GeoLite2-ASN/download?suffix=tar.gz"
        ),
        "filename": "GeoLite2-ASN.mmdb",
        "env_path": "GEOIP_ASN_DB_PATH",
        "default_path": "/tmp/GeoLite2-ASN.mmdb",
    },
}


def _download_database(
    database: dict,
    account_id: str,
    license_key: str,
) -> bool:

    db_path = Path(
        os.getenv(
            database["env_path"],
            database["default_path"],
        )
    )

    if db_path.is_file() and db_path.stat().st_size > 0:
        print(f"{database['filename']} already exists.")
        return True

    credentials = f"{account_id}:{license_key}".encode("utf-8")
    auth = base64.b64encode(credentials).decode("ascii")

    request = urllib.request.Request(
        database["url"],
        headers={
            "Authorization": f"Basic {auth}",
            "User-Agent": "Prahari-AI/1.0",
        },
    )

    db_path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = db_path.with_suffix(".mmdb.tmp")

    try:
        # Download archive into a temporary file.
        with tempfile.TemporaryFile() as archive:

            with urllib.request.urlopen(
                request,
                timeout=120,
            ) as response:

                while True:
                    chunk = response.read(1024 * 1024)

                    if not chunk:
                        break

                    archive.write(chunk)

            archive.seek(0)

            # Extract only the required MMDB file.
            with tarfile.open(
                fileobj=archive,
                mode="r:gz",
            ) as tar:

                member = next(
                    (
                        item
                        for item in tar.getmembers()
                        if item.isfile()
                        and Path(item.name).name
                        == database["filename"]
                    ),
                    None,
                )

                if member is None:
                    raise RuntimeError(
                        "Database file not found in archive."
                    )

                source = tar.extractfile(member)

                if source is None:
                    raise RuntimeError(
                        "Could not read database archive."
                    )

                with source, temporary_path.open("wb") as output:

                    while True:
                        chunk = source.read(1024 * 1024)

                        if not chunk:
                            break

                        output.write(chunk)

        if (
            not temporary_path.is_file()
            or temporary_path.stat().st_size == 0
        ):
            raise RuntimeError("Downloaded database is empty.")

        # Atomically replace the destination file.
        temporary_path.replace(db_path)

        print(
            f"{database['filename']} downloaded successfully."
        )

        return True

    except urllib.error.HTTPError as exc:

        print(
            f"{database['filename']} download failed: "
            f"HTTP {exc.code} - {exc.reason}"
        )

        return False

    except urllib.error.URLError as exc:

        print(
            f"{database['filename']} download failed: "
            f"Network error - {exc.reason}"
        )

        return False

    except Exception as exc:

        print(
            f"{database['filename']} download failed: "
            f"{type(exc).__name__}: {exc}"
        )

        return False

    finally:

        temporary_path.unlink(missing_ok=True)


def ensure_geoip_databases() -> dict:
    """Ensure both MaxMind GeoLite databases are available."""

    account_id = os.getenv("MAXMIND_ACCOUNT_ID")
    license_key = os.getenv("MAXMIND_LICENSE_KEY")

    if not account_id or not license_key:
        print(
            "GeoIP unavailable: MaxMind credentials are missing."
        )

        return {
            "city": False,
            "asn": False,
        }

    results = {}

    for name, database in DATABASES.items():

        results[name] = _download_database(
            database,
            account_id,
            license_key,
        )

    return results


def ensure_geoip_database() -> bool:
    """Backwards-compatible City database function."""

    results = ensure_geoip_databases()

    return results["city"]
