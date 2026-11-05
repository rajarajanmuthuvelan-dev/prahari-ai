
import os
import shutil
import subprocess
from pathlib import Path


DATABASES = {
    "city": {
        "filename": "GeoLite2-City.mmdb",
        "env_path": "GEOIP_DB_PATH",
        "default_path": "/tmp/GeoLite2-City.mmdb",
    },
    "asn": {
        "filename": "GeoLite2-ASN.mmdb",
        "env_path": "GEOIP_ASN_DB_PATH",
        "default_path": "/tmp/GeoLite2-ASN.mmdb",
    },
}


def ensure_geoip_databases() -> dict:
    """Download MaxMind GeoLite2 City and ASN databases."""

    account_id = os.getenv("MAXMIND_ACCOUNT_ID")
    license_key = os.getenv("MAXMIND_LICENSE_KEY")

    if not account_id or not license_key:
        print("GeoIP unavailable: MaxMind credentials are missing.")
        return {"city": False, "asn": False}

    paths = {
        name: Path(
            os.getenv(item["env_path"], item["default_path"])
        )
        for name, item in DATABASES.items()
    }

    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update({
        "GEOIPUPDATE_ACCOUNT_ID": account_id,
        "GEOIPUPDATE_LICENSE_KEY": license_key,
        "GEOIPUPDATE_EDITION_IDS": "GeoLite2-City GeoLite2-ASN",
        "GEOIPUPDATE_DB_DIR": "/tmp",
        "GEOIPUPDATE_FREQUENCY": "0",
    })

    try:
        executable = shutil.which("pygeoipupdate")

        if not executable:
            raise RuntimeError(
                "pygeoipupdate executable not found. "
                "Check that pygeoipupdate is in requirements.txt."
            )

        result = subprocess.run(
            [executable, "-v"],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        print("MaxMind updater output:", result.stdout[-4000:])

        if result.returncode != 0:
            print("MaxMind updater error:", result.stderr[-4000:])

    except Exception as exc:
        print(f"MaxMind updater failed: {type(exc).__name__}: {exc}")

    results = {}

    for name, item in DATABASES.items():
        expected_path = Path("/tmp") / item["filename"]
        configured_path = paths[name]

        if expected_path.is_file() and expected_path.stat().st_size > 0:
            if expected_path != configured_path:
                shutil.copy2(expected_path, configured_path)

        results[name] = (
            configured_path.is_file()
            and configured_path.stat().st_size > 0
        )

        print(f"{item['filename']}: {'available' if results[name] else 'missing'}")

    print(f"GeoIP database status: {results}")
    return results


def ensure_geoip_database() -> bool:
    """Backwards-compatible City database function."""
    return ensure_geoip_databases()["city"]
