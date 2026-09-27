"""GeoIP context for valid public infrastructure IPs only."""

import asyncio
import logging
import socket
from datetime import datetime, timezone
from typing import Optional

import httpx

from ..config import settings
from .ioc_normalizer import parse_ip_address

logger = logging.getLogger(__name__)
_reader = None


def _provider_outcome(
    source: str,
    provider: str,
    status: str,
    *,
    checked_at: Optional[str] = None,
    **data,
) -> dict:
    return {
        "source": source,
        "provider": provider,
        "status": status,
        "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
        "confidence": None,
        **data,
    }


def _get_maxmind_reader():
    global _reader
    if _reader is not None:
        return _reader
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(settings.geoip_db_path)
    except Exception:
        logger.info("MaxMind GeoIP database is unavailable", exc_info=True)
        _reader = False
    return _reader


def _maxmind_lookup(ip: str) -> Optional[dict]:
    reader = _get_maxmind_reader()
    if not reader:
        return None
    try:
        response = reader.city(ip)
    except Exception:
        logger.info("MaxMind has no GeoIP record for %s", ip, exc_info=True)
        return None
    return {
        "country": response.country.name,
        "country_code": response.country.iso_code,
        "region": response.subdivisions.most_specific.name,
        "city": response.city.name,
        "asn": None,
        "asn_name": None,
        "isp": None,
        "reverse_dns": None,
        "network": None,
        "network_type": None,
        "infrastructure_type": None,
        "confidence": None,
        "accuracy_radius_km": response.location.accuracy_radius,
        "location_note": "Approximate infrastructure location; city-level data is not precise.",
        "source": "MAXMIND",
        "provider": "MaxMind GeoIP",
        "status": "FOUND",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


async def _ip_api_lookup(ip: str) -> Optional[dict]:
    fields = (
        "status,message,country,countryCode,regionName,city,as,isp,org,"
        "mobile,hosting,proxy,reverse"
    )
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://ip-api.com/json/{ip}?fields={fields}",
            timeout=5,
        )
    response.raise_for_status()
    data = response.json()
    if data.get("status") != "success":
        return None

    asn = data.get("as", "")
    asn_number = asn.split(" ", 1)[0] if asn else None
    if asn_number and not asn_number.upper().startswith("AS"):
        asn_number = f"AS{asn_number}"
    if data.get("proxy"):
        network_type = "VPN / Proxy"
        infrastructure_type = "Proxy"
    elif data.get("hosting"):
        network_type = "Hosting"
        infrastructure_type = "Hosting"
    elif data.get("mobile"):
        network_type = "Mobile"
        infrastructure_type = "Mobile"
    else:
        network_type = None
        infrastructure_type = None
    return {
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "asn": asn_number,
        "asn_name": data.get("org") or (asn.partition(" ")[2] or None),
        "isp": data.get("isp"),
        "reverse_dns": data.get("reverse"),
        "network": None,
        "network_type": network_type,
        "infrastructure_type": infrastructure_type,
        "confidence": None,
        "accuracy_radius_km": None,
        "location_note": "Approximate infrastructure location; city-level data is not precise.",
        "source": "IP_API",
        "provider": "IP-API",
        "status": "FOUND",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "raw": data,
    }


async def _ipwhois_lookup(ip: str) -> Optional[dict]:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://ipwho.is/{ip}", timeout=6)
    response.raise_for_status()
    data = response.json()
    if not data.get("success"):
        return None

    connection = data.get("connection") or {}
    asn = connection.get("asn")
    return {
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "asn": f"AS{asn}" if asn else None,
        "asn_name": connection.get("org"),
        "isp": connection.get("isp"),
        "org": connection.get("org"),
        "reverse_dns": None,
        "network": None,
        "network_type": None,
        "infrastructure_type": None,
        "postal_code": data.get("postal"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "confidence": None,
        "accuracy_radius_km": None,
        "location_note": "Approximate infrastructure location; city-level data is not precise.",
        "source": "IPWHOIS",
        "provider": "ipwho.is",
        "status": "FOUND",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "raw": data,
    }


def _resolve_ptr(ip: str) -> dict:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, TimeoutError):
        return _provider_outcome(
            "DNS_PTR", "System DNS PTR", "NOT_FOUND", hostname=None
        )
    except OSError:
        logger.warning("System DNS PTR lookup failed for %s", ip, exc_info=True)
        return _provider_outcome(
            "DNS_PTR", "System DNS PTR", "ERROR", hostname=None
        )

    return _provider_outcome(
        "DNS_PTR",
        "System DNS PTR",
        "FOUND",
        hostname=hostname.rstrip(".").encode("idna").decode("ascii").lower(),
    )


def _merge_provider_results(results: list[dict]) -> dict:
    def field_status(field: str, value) -> str:
        if value is not None:
            return "AVAILABLE"
        if field == "reverse_dns":
            ptr_result = next(
                (
                    result for result in results
                    if result.get("source") == "DNS_PTR"
                ),
                None,
            )
            if ptr_result:
                return (
                    "LOOKUP_FAILED"
                    if ptr_result.get("status") in ("TIMEOUT", "ERROR")
                    else "NOT_AVAILABLE"
                )
        non_ptr_results = [
            result for result in results if result.get("source") != "DNS_PTR"
        ]
        if any(result.get("status") == "FOUND" for result in non_ptr_results):
            return "NOT_RETURNED_BY_SOURCE"
        if any(result.get("status") in ("TIMEOUT", "ERROR") for result in results):
            return "LOOKUP_FAILED"
        return "NOT_AVAILABLE"

    found = [
        result for result in results
        if result.get("status") == "FOUND" and result.get("source") != "DNS_PTR"
    ]
    if not found:
        ptr_result = next(
            (
                result for result in results
                if result.get("source") == "DNS_PTR"
                and result.get("status") == "FOUND"
                and result.get("hostname")
            ),
            None,
        )
        status = next(
            (result["status"] for result in results if result.get("status") in ("TIMEOUT", "ERROR")),
            "NOT_FOUND" if results else "UNAVAILABLE",
        )
        return {
            "source": " + ".join(result["source"] for result in results) or "UNAVAILABLE",
            "provider": ", ".join(result["provider"] for result in results) or None,
            "status": status,
            "checked_at": max((result["checked_at"] for result in results if result.get("checked_at")), default=None),
            "confidence": None,
            "reverse_dns": ptr_result.get("hostname") if ptr_result else None,
            "domain_hostname": ptr_result.get("hostname") if ptr_result else None,
            "domain_hostname_source": "DNS_PTR" if ptr_result else None,
            "field_status": {
                "reverse_dns": field_status(
                    "reverse_dns", ptr_result.get("hostname") if ptr_result else None
                ),
                "network": field_status("network", None),
                "network_type": field_status("network_type", None),
                "infrastructure_type": field_status("infrastructure_type", None),
            },
            "provider_results": {result["source"]: result for result in results},
            "disagreements": {},
        }
    primary = found[0]
    fields = (
        "country",
        "country_code",
        "region",
        "city",
        "asn",
        "asn_name",
        "isp",
        "reverse_dns",
        "network",
        "network_type",
        "infrastructure_type",
    )
    disagreements = {
        field: {
            result["source"]: result.get(field)
            for result in found
            if result.get(field)
        }
        for field in fields
        if len({result.get(field) for result in found if result.get(field)}) > 1
    }
    merged = dict(primary)
    for field in fields:
        if merged.get(field) is None:
            merged[field] = next(
                (result.get(field) for result in found if result.get(field) is not None),
                None,
            )
    ptr_result = next(
        (
            result for result in results
            if result.get("source") == "DNS_PTR" and result.get("hostname")
        ),
        None,
    )
    intelligence_hostname = next(
        (
            result.get("reverse_dns")
            for result in found
            if result.get("reverse_dns")
        ),
        None,
    )
    hostname_candidates = {
        result["source"]: result.get("hostname") or result.get("reverse_dns")
        for result in results
        if result.get("status") == "FOUND"
        if result.get("hostname") or result.get("reverse_dns")
    }
    if len(set(hostname_candidates.values())) > 1:
        disagreements["domain_hostname"] = hostname_candidates
    domain_hostname = (
        ptr_result.get("hostname") if ptr_result else intelligence_hostname
    )
    if ptr_result and ptr_result.get("hostname"):
        merged["reverse_dns"] = ptr_result["hostname"]
    normalized_fields = {
        "reverse_dns": merged.get("reverse_dns"),
        "network": merged.get("network"),
        "network_type": merged.get("network_type"),
        "infrastructure_type": merged.get("infrastructure_type"),
    }
    return {
        **merged,
        "domain_hostname": domain_hostname,
        "domain_hostname_source": (
            "DNS_PTR" if ptr_result else
            next(
                (
                    result["source"]
                    for result in found
                    if result.get("reverse_dns")
                ),
                None,
            )
        ),
        "source": " + ".join(result["source"] for result in found),
        "provider": ", ".join(result["provider"] for result in found),
        "status": "FOUND",
        "checked_at": max(
            result["checked_at"] for result in results if result.get("checked_at")
        ),
        "confidence": next((result.get("confidence") for result in found if result.get("confidence") is not None), None),
        "field_status": {
            field: field_status(field, value)
            for field, value in normalized_fields.items()
        },
        "provider_results": {
            result["source"]: result
            for result in results
        },
        "disagreements": disagreements,
    }


async def lookup_ip(ip: str) -> Optional[dict]:
    try:
        address = parse_ip_address(ip)
    except ValueError:
        return None
    if not address.is_global:
        return None

    maxmind_result = await asyncio.to_thread(_maxmind_lookup, str(address))
    if maxmind_result is None:
        maxmind_status = "NOT_FOUND" if _reader not in (None, False) else "UNAVAILABLE"
        maxmind_result = _provider_outcome(
            "MAXMIND", "MaxMind GeoIP", maxmind_status
        )

    async def run_provider(source: str, provider: str, lookup) -> dict:
        try:
            result = await lookup(str(address))
            if result is not None:
                return result
            return _provider_outcome(source, provider, "NOT_FOUND")
        except httpx.TimeoutException:
            logger.warning("%s GeoIP lookup timed out for %s", provider, address)
            return _provider_outcome(source, provider, "TIMEOUT")
        except Exception:
            logger.warning("%s GeoIP lookup failed for %s", provider, address, exc_info=True)
            return _provider_outcome(source, provider, "ERROR")

    ip_api_result, ipwhois_result = await asyncio.gather(
        run_provider("IP_API", "IP-API", _ip_api_lookup),
        run_provider("IPWHOIS", "ipwho.is", _ipwhois_lookup),
    )
    ptr_result = await asyncio.to_thread(_resolve_ptr, str(address))
    return _merge_provider_results(
        [maxmind_result, ip_api_result, ipwhois_result, ptr_result]
    )


async def enrich_geo(iocs: list[dict]) -> list[dict]:
    ip_iocs = [
        (index, ioc)
        for index, ioc in enumerate(iocs)
        if ioc.get("type") == "IP" and ioc.get("valid") is True
    ]
    tasks = [lookup_ip(ioc["normalized_value"]) for _, ioc in ip_iocs]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for (index, ioc), geo in zip(ip_iocs, results):
        intel = iocs[index].get("intelligence") or {}
        if isinstance(geo, Exception):
            logger.error(
                "GeoIP lookup failed for %s",
                ioc["normalized_value"],
                exc_info=geo,
            )
            iocs[index]["intelligence"] = {
                **intel,
                "geo_status": "ERROR",
                "geo": {
                    "source": "UNAVAILABLE",
                    "provider": None,
                    "status": "ERROR",
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "confidence": None,
                },
            }
        elif geo:
            iocs[index]["intelligence"] = {
                **intel,
                "domain_hostname": geo.get("domain_hostname"),
                "domain_hostname_source": geo.get("domain_hostname_source"),
                "geo": geo if geo.get("status") == "FOUND" else None,
                "geo_status": geo.get("status", "UNAVAILABLE"),
                "geo_lookup": geo,
            }
            iocs[index]["geo_source"] = (
                geo.get("source") if geo.get("status") == "FOUND" else None
            )
        else:
            iocs[index]["intelligence"] = {**intel, "geo_status": "UNAVAILABLE"}

    return iocs
