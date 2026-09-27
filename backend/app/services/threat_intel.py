"""Server-side IOC lookups with honest cache, provider, and result status."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

import httpx
import redis.asyncio as aioredis

from ..config import settings
from .ioc_reputation import (
    normalize_ioc_reputation,
    reputation_risk_contribution,
    reputation_lookup_source,
    reputation_state,
)
from .ioc_normalizer import is_public_domain, normalize_ioc, parse_ip_address
from .local_ioc_db import lookup as local_lookup

CACHE_TTL = 3600
_redis: Optional[aioredis.Redis] = None
logger = logging.getLogger(__name__)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lookup_result(
    source: str,
    provider: Optional[str],
    status: str,
    *,
    confidence: Optional[int] = None,
    raw: Optional[dict] = None,
    **data,
) -> dict:
    checked_at = data.pop("checked_at") if "checked_at" in data else _timestamp()
    lookup_status = data.pop("lookup_status", status)
    lookup_timestamp = data.pop("lookup_timestamp", checked_at)
    return {
        "source": source,
        "provider": provider,
        "status": status,
        "lookup_status": lookup_status,
        "confidence": confidence,
        "checked_at": checked_at,
        "lookup_timestamp": lookup_timestamp,
        **data,
        "raw": raw,
    }


async def get_redis() -> Optional[aioredis.Redis]:
    global _redis
    if _redis is not None:
        return _redis
    try:
        candidate = aioredis.from_url(settings.redis_url, decode_responses=True)
        await candidate.ping()
        _redis = candidate
    except Exception:
        logger.warning("IOC cache is unavailable", exc_info=True)
    return _redis


async def _cache_get(key: str) -> Optional[dict]:
    try:
        redis_client = await get_redis()
        if redis_client:
            value = await redis_client.get(key)
            if value:
                return json.loads(value)
    except Exception:
        logger.warning("Unable to read IOC cache entry", exc_info=True)
    return None


async def _cache_set(key: str, data: dict) -> None:
    try:
        redis_client = await get_redis()
        if redis_client:
            await redis_client.setex(key, CACHE_TTL, json.dumps(data))
    except Exception:
        logger.warning("Unable to write IOC cache entry", exc_info=True)


def _classify_risk(reputation: Optional[int]) -> str:
    if reputation is None:
        return "UNKNOWN"
    if reputation >= 90:
        return "CRITICAL"
    if reputation >= 70:
        return "HIGH"
    if reputation >= 40:
        return "MEDIUM"
    return "LOW"


def _with_reputation_state(intelligence: dict) -> dict:
    provider_results = intelligence.get("provider_results") or {}
    states = [
        result.get("reputation_status")
        for result in provider_results.values()
        if isinstance(result, dict)
        and result.get("lookup_status", result.get("status")) == "FOUND"
        and result.get("reputation") is not None
    ] if isinstance(provider_results, dict) else []
    states.append(intelligence.get("reputation_status"))
    precedence = {"UNKNOWN": 0, "CLEAN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
    state = max(
        (
            value for value in states
            if value in precedence and value != "UNKNOWN"
        ),
        key=precedence.get,
        default=reputation_state(intelligence),
    )
    normalized = {**intelligence, "reputation_status": state}
    normalized["risk_contribution"] = reputation_risk_contribution(normalized)
    normalized["lookup_source"] = reputation_lookup_source(normalized, state)
    if state == "UNKNOWN":
        normalized.setdefault("reason", "No threat-intelligence result available")
    return normalized


def _from_local(record: dict) -> dict:
    geo = {
        "source": "LOCAL_DB",
        "provider": "Local IOC Database",
        "status": "FOUND",
        "confidence": None,
        "checked_at": _timestamp(),
        "country": record.get("country"),
        "country_code": record.get("country_code"),
        "region": record.get("region"),
        "city": record.get("city"),
        "asn": record.get("asn"),
        "asn_name": record.get("asn_name"),
        "isp": record.get("isp"),
        "organization": record.get("asn_name"),
        "reverse_dns": None,
        "raw": record,
    } if record.get("country") else None
    result = _lookup_result(
        "LOCAL_DB",
        "Local IOC Database",
        "FOUND",
        confidence=None,
        raw=record,
        reputation=record.get("reputation"),
        geo=geo,
        first_seen=record.get("first_seen"),
        last_seen=record.get("last_seen"),
        total_reports=record.get("total_reports"),
        tags=record.get("tags", []),
        whois_registrar=record.get("whois_registrar"),
        whois_created=record.get("whois_created"),
    )
    result["reputation_status"] = reputation_state(
        {
            **result,
            "lookup_status": "FOUND",
        }
    )
    return _with_reputation_state(result)


async def _vt_lookup_ip(ip: str, client: httpx.AsyncClient) -> Optional[dict]:
    response = await client.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": settings.virustotal_api_key},
        timeout=8,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values())
    reputation = min(99, int(malicious * 100 / total)) if total else None
    reputation_status = (
        "MALICIOUS" if stats.get("malicious", 0) > 0
        else "SUSPICIOUS" if stats.get("suspicious", 0) > 0
        else "CLEAN" if stats.get("harmless", 0) > 0
        else "UNKNOWN"
    )
    return _lookup_result(
        "VIRUSTOTAL",
        "VirusTotal",
        "FOUND",
        confidence=None,
        raw=attributes,
        reputation=reputation,
        reputation_status=reputation_status,
        first_seen=attributes.get("first_submission_date"),
        last_seen=attributes.get("last_modification_date"),
        total_reports=malicious,
        tags=sorted(set(attributes.get("tags", []))),
        geo=None,
        whois_registrar=None,
        whois_created=None,
    )


async def _vt_lookup_domain(domain: str, client: httpx.AsyncClient) -> Optional[dict]:
    response = await client.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": settings.virustotal_api_key},
        timeout=8,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values())
    reputation = min(99, int(malicious * 100 / total)) if total else None
    reputation_status = (
        "MALICIOUS" if stats.get("malicious", 0) > 0
        else "SUSPICIOUS" if stats.get("suspicious", 0) > 0
        else "CLEAN" if stats.get("harmless", 0) > 0
        else "UNKNOWN"
    )
    whois = attributes.get("whois", "")
    registrar = None
    created = None
    for line in whois.splitlines():
        if "Registrar:" in line:
            registrar = line.split(":", 1)[1].strip()
        elif "Creation Date:" in line:
            created = line.split(":", 1)[1].strip()[:10]
    return _lookup_result(
        "VIRUSTOTAL",
        "VirusTotal",
        "FOUND",
        confidence=None,
        raw=attributes,
        reputation=reputation,
        reputation_status=reputation_status,
        first_seen=created,
        last_seen=None,
        total_reports=malicious,
        tags=sorted(set(attributes.get("tags", []))),
        geo=None,
        whois_registrar=registrar,
        whois_created=created,
    )


async def _abuseipdb_lookup(ip: str, client: httpx.AsyncClient) -> Optional[dict]:
    response = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
        timeout=8,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    data = response.json().get("data", {})
    abuse_score = data.get("abuseConfidenceScore")
    return _lookup_result(
        "ABUSEIPDB",
        "AbuseIPDB",
        "FOUND",
        confidence=abuse_score,
        raw=data,
        reputation=abuse_score,
        reputation_status=(
            "UNKNOWN" if abuse_score is None
            else "SUSPICIOUS" if abuse_score > 0
            else "CLEAN"
        ),
        first_seen=None,
        last_seen=data.get("lastReportedAt"),
        total_reports=data.get("totalReports"),
        tags=[data["usageType"]] if data.get("usageType") else [],
        geo=None,
        whois_registrar=None,
        whois_created=None,
    )


async def _provider_result(name: str, lookup, *args) -> tuple[Optional[dict], Optional[str]]:
    try:
        return await lookup(*args), None
    except httpx.TimeoutException:
        logger.warning("%s IOC lookup timed out", name, exc_info=True)
        return None, "TIMEOUT"
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return None, "NOT_FOUND"
        logger.warning("%s IOC lookup returned HTTP %s", name, exc.response.status_code)
        return None, "ERROR"
    except Exception:
        logger.warning("%s IOC lookup failed", name, exc_info=True)
        return None, "ERROR"


async def enrich_ioc(
    ioc_type: str,
    value: str,
    allow_local_database: bool = True,
) -> dict:
    normalized = normalize_ioc(ioc_type, value, "IOC Lookup")
    if not normalized["valid"]:
        raise ValueError(f"Invalid {ioc_type.upper()} IOC value.")
    ioc_type = normalized["type"]
    value = normalized["normalized_value"]
    cache_key = f"ioc:v4:{ioc_type}:{value}"
    cached = await _cache_get(cache_key)
    if cached:
        return cached

    local = local_lookup(value) if allow_local_database else None
    intel = _from_local(local) if local else None
    provider_outcomes: dict[str, dict] = {}
    lookups: list[tuple[str, object, str]] = []

    address = None
    if ioc_type == "IP":
        address = parse_ip_address(value)
    elif ioc_type == "URL":
        hostname = urlsplit(value).hostname or ""
        try:
            address = parse_ip_address(hostname)
        except ValueError:
            pass
        else:
            ioc_type = "IP"
            value = str(address)

    if ioc_type == "DOMAIN" and not is_public_domain(value):
        return _with_reputation_state(intel) if intel else _with_reputation_state(_lookup_result(
            "UNAVAILABLE", None, "UNAVAILABLE", tags=[], reputation=None,
            checked_at=None, lookup_timestamp=None,
            reason="Non-public domains are not sent to public intelligence providers.",
        ))

    if ioc_type == "URL":
        hostname = urlsplit(value).hostname or ""
        try:
            parse_ip_address(hostname)
        except ValueError:
            if not is_public_domain(hostname):
                return _with_reputation_state(intel) if intel else _with_reputation_state(_lookup_result(
                    "UNAVAILABLE", None, "UNAVAILABLE", tags=[], reputation=None,
                    checked_at=None, lookup_timestamp=None,
                    reason="URLs with non-public hosts are not sent to public providers.",
                ))

    if ioc_type == "IP" and address and not address.is_global:
        return _with_reputation_state(intel) if intel else _with_reputation_state(_lookup_result(
            "UNAVAILABLE", None, "UNAVAILABLE", tags=[], reputation=None,
            checked_at=None, lookup_timestamp=None,
            reason="Non-public IPs are not sent to public intelligence providers.",
        ))

    if ioc_type == "IP":
        if settings.virustotal_api_key:
            lookups.append(("VIRUSTOTAL", _vt_lookup_ip, value))
        if settings.abuseipdb_api_key:
            lookups.append(("ABUSEIPDB", _abuseipdb_lookup, value))
    elif ioc_type == "DOMAIN":
        if settings.virustotal_api_key:
            lookups.append(("VIRUSTOTAL", _vt_lookup_domain, value))
    elif ioc_type == "URL":
        hostname = urlsplit(value).hostname or ""
        if settings.virustotal_api_key:
            lookups.append(("VIRUSTOTAL", _vt_lookup_domain, hostname))

    if lookups:
        async with httpx.AsyncClient() as client:
            outcomes = await asyncio.gather(
                *(
                    _provider_result(name, lookup, lookup_value, client)
                    for name, lookup, lookup_value in lookups
                )
            )
        for (name, _, _), (result, failure_status) in zip(lookups, outcomes):
            if result is not None:
                provider_outcomes[name] = result
            else:
                status = failure_status or "NOT_FOUND"
                display_name = {
                    "VIRUSTOTAL": "VirusTotal",
                    "ABUSEIPDB": "AbuseIPDB",
                }.get(name, name)
                provider_outcomes[name] = _lookup_result(
                    name, display_name, status,
                    tags=[], reputation=None, raw=None,
                )

    provider_results = [
        result for result in provider_outcomes.values()
        if result.get("status") == "FOUND"
    ]
    if provider_results:
        selected = max(provider_results, key=lambda result: result.get("reputation") or 0)
        combined = dict(intel or {})
        for key, value in selected.items():
            if value is not None or key not in combined:
                combined[key] = value
        combined["tags"] = sorted(set((intel or {}).get("tags", [])) | set(selected.get("tags", [])))
        combined["reputation_status"] = max(
            (
                result.get("reputation_status", "UNKNOWN")
                for result in provider_results
            ),
            key={"UNKNOWN": 0, "CLEAN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}.get,
            default="UNKNOWN",
        )
        intel = combined
        if local:
            intel["source"] = f"LOCAL_DB+{'+'.join(result['source'] for result in provider_results)}"
            intel["provider"] = f"Local IOC Database, {', '.join(result['provider'] for result in provider_results)}"
        else:
            intel["source"] = "+".join(result["source"] for result in provider_results)
            intel["provider"] = ", ".join(result["provider"] for result in provider_results)
        intel = _with_reputation_state({
            **intel,
            "status": "FOUND",
            "checked_at": max(result["checked_at"] for result in provider_outcomes.values()),
            "provider_results": provider_outcomes,
        })

    if intel:
        if provider_outcomes:
            intel["provider_results"] = provider_outcomes
            intel["checked_at"] = max(
                intel.get("checked_at") or "",
                *(result["checked_at"] for result in provider_outcomes.values()),
            ) or None
        intel = {
            **intel,
            "lookup_status": intel.get("status", "FOUND"),
            "lookup_timestamp": intel.get("checked_at"),
        }
        if provider_results:
            await _cache_set(cache_key, intel)
        return _with_reputation_state(intel)

    outcomes = list(provider_outcomes.values())
    lookup_status = (
        "UNAVAILABLE" if not lookups
        else next((result["status"] for result in outcomes if result["status"] == "TIMEOUT"), None)
        or next((result["status"] for result in outcomes if result["status"] == "ERROR"), None)
        or "NOT_FOUND"
    )
    failed_at = max((result["checked_at"] for result in outcomes), default=None)
    return _with_reputation_state(_lookup_result(
        lookup_status, ", ".join(result["provider"] for result in outcomes) or None,
        lookup_status, tags=[], reputation=None, checked_at=failed_at,
        lookup_status=lookup_status,
        lookup_timestamp=failed_at,
        provider_results=provider_outcomes,
    ))


async def enrich_iocs(
    iocs: list[dict],
    allow_local_database: bool = True,
) -> list[dict]:
    for ioc in iocs:
        if not ioc.get("valid"):
            raise ValueError(f"Refusing to enrich invalid IOC: {ioc.get('value')!r}")
    tasks = [
        enrich_ioc(ioc["type"], ioc["normalized_value"], allow_local_database)
        for ioc in iocs
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    enriched = []
    for ioc, result in zip(iocs, results):
        if isinstance(result, Exception):
            logger.error(
                "IOC enrichment failed for %s",
                ioc["normalized_value"],
                exc_info=result,
            )
            result = {
                "source": "UNAVAILABLE",
                "provider": None,
                "status": "ERROR",
                "lookup_status": "ERROR",
                "lookup_timestamp": _timestamp(),
                "checked_at": _timestamp(),
                "tags": [],
                "reputation": None,
            }
        reputation = result.get("reputation")
        result = _with_reputation_state(result)
        status = result["reputation_status"]
        risk = _classify_risk(reputation) if status != "UNKNOWN" else "UNKNOWN"
        enriched.append(
            normalize_ioc_reputation({
                **ioc,
                "intelligence": result,
                "risk": risk,
                "status": status,
                "reputation_status": status,
            })
        )
    return enriched
