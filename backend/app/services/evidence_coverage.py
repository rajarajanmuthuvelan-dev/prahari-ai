import ipaddress
from typing import Any


CATEGORY_LABELS = {
    "email_parsing": "Email parsing",
    "header_extraction": "Header extraction",
    "spf": "SPF",
    "dkim": "DKIM",
    "dmarc": "DMARC",
    "bert": "BERT",
    "roberta": "RoBERTa",
    "ioc_extraction": "IOC extraction",
    "threat_intelligence": "Threat intelligence",
    "geoip": "GeoIP",
    "asn_isp": "ASN/ISP",
    "reverse_dns": "Reverse DNS/PTR",
    "infrastructure": "Infrastructure intelligence",
    "attachments": "Attachment analysis",
    "url_analysis": "URL analysis",
}


def _status(available: int, applicable: int) -> str:
    if applicable == 0:
        return "NOT_APPLICABLE"
    if available == applicable:
        return "AVAILABLE"
    if available > 0:
        return "PARTIAL"
    return "UNAVAILABLE"


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _geo(ioc: dict[str, Any]) -> dict[str, Any]:
    intelligence = ioc.get("intelligence") or {}
    return intelligence.get("geo") or {}


def _ip_iocs(iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        ioc for ioc in iocs
        if ioc.get("valid") is True
        and ioc.get("type") == "IP"
        and _is_public_ip(str(ioc.get("normalized_value") or ioc.get("value") or ""))
    ]


def _model_status(ai_analysis: dict[str, Any], name: str) -> str:
    result = next(
        (
            model for model in (ai_analysis.get("models") or [])
            if str(model.get("name", "")).casefold() == name.casefold()
        ),
        None,
    )
    return str(result.get("status", "UNAVAILABLE")).upper() if result else "UNAVAILABLE"


def _has_geo_context(ioc: dict[str, Any]) -> bool:
    geo = _geo(ioc)
    return any(
        geo.get(key) not in (None, "")
        for key in (
            "country",
            "country_code",
            "region",
            "city",
            "latitude",
            "longitude",
        )
    )


def calculate_evidence_coverage(
    parsed: dict[str, Any] | None,
    auth: dict[str, Any] | None,
    iocs: list[dict[str, Any]] | None,
    ai_analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    parsed = parsed or {}
    auth = auth or {}
    ioc_results_available = iocs is not None
    iocs = iocs or []
    ai_analysis = ai_analysis or {}
    categories: dict[str, dict[str, str]] = {}

    def set_category(key: str, status: str, detail: str) -> None:
        categories[key] = {
            "label": CATEGORY_LABELS[key],
            "status": status,
            "detail": detail,
        }

    parsed_successfully = isinstance(parsed, dict) and all(
        key in parsed for key in ("headers", "body_text", "attachments")
    )
    set_category(
        "email_parsing",
        "AVAILABLE" if parsed_successfully else "UNAVAILABLE",
        "Email parsed into structured message data."
        if parsed_successfully else "Structured email parsing data is unavailable.",
    )
    headers = parsed.get("headers")
    headers_available = isinstance(headers, list) and bool(headers)
    set_category(
        "header_extraction",
        "AVAILABLE" if headers_available else "UNAVAILABLE",
        f"{len(headers)} email header(s) extracted."
        if headers_available else "No email headers were extracted.",
    )

    for key, auth_key, label in (
        ("spf", "spf", "SPF"),
        ("dkim", "dkim", "DKIM"),
        ("dmarc", "dmarc", "DMARC"),
    ):
        value = str(auth.get(auth_key, "NOT_AVAILABLE")).upper()
        status = "AVAILABLE" if value in {"PASS", "FAIL", "NEUTRAL", "NONE"} else "UNAVAILABLE"
        set_category(
            key,
            status,
            f"{label} result: {value}." if status == "AVAILABLE"
            else f"No {label} result was available from the email headers.",
        )

    for key, model_name in (("bert", "BERT"), ("roberta", "RoBERTa")):
        model_status = _model_status(ai_analysis, model_name)
        set_category(
            key,
            "AVAILABLE" if model_status == "AVAILABLE" else "UNAVAILABLE",
            f"{model_name} inference completed."
            if model_status == "AVAILABLE"
            else f"{model_name} inference status: {model_status}.",
        )

    valid_iocs = [ioc for ioc in iocs if ioc.get("valid") is True]
    set_category(
        "ioc_extraction",
        "AVAILABLE" if ioc_results_available else "UNAVAILABLE",
        f"{len(valid_iocs)} valid IOC(s) extracted."
        if ioc_results_available else "IOC extraction result is unavailable.",
    )

    intel_iocs = [
        ioc for ioc in valid_iocs
        if ioc.get("type") in {"IP", "DOMAIN", "URL", "HASH"}
    ]
    if not intel_iocs:
        set_category(
            "threat_intelligence",
            "NOT_APPLICABLE",
            "No supported valid IOC was available for reputation lookup.",
        )
    else:
        found = 0
        attempted = 0
        for ioc in intel_iocs:
            intel = ioc.get("intelligence") or {}
            lookup_status = str(intel.get("lookup_status", intel.get("status", ""))).upper()
            if lookup_status == "FOUND" and intel.get("reputation") is not None:
                found += 1
            if lookup_status not in {"", "UNAVAILABLE", "ERROR", "TIMEOUT"}:
                attempted += 1
        ti_status = (
            "AVAILABLE" if found == len(intel_iocs)
            else "PARTIAL" if found or attempted
            else "UNAVAILABLE"
        )
        set_category(
            "threat_intelligence",
            ti_status,
            f"Usable reputation returned for {found} of {len(intel_iocs)} supported IOC(s)."
            if found else (
                f"Lookups were attempted for {len(intel_iocs)} supported IOC(s), "
                "but no usable reputation result was returned."
                if attempted else "No usable threat-intelligence lookup result is available."
            ),
        )

    public_ips = _ip_iocs(iocs)
    if not public_ips:
        for key in ("geoip", "asn_isp", "reverse_dns", "infrastructure"):
            set_category(
                key,
                "NOT_APPLICABLE",
                "No valid public IP was present for this evidence category.",
            )
    else:
        geo_count = sum(_has_geo_context(ioc) for ioc in public_ips)
        geo_status = _status(geo_count, len(public_ips))
        set_category(
            "geoip",
            geo_status,
            f"GeoIP context available for {geo_count} of {len(public_ips)} public IP(s).",
        )

        asn_isp_count = sum(
            bool(_geo(ioc).get("asn")) and bool(_geo(ioc).get("isp"))
            for ioc in public_ips
        )
        asn_isp_partial = sum(
            bool(_geo(ioc).get("asn")) or bool(_geo(ioc).get("isp"))
            for ioc in public_ips
        )
        asn_isp_status = (
            "AVAILABLE" if asn_isp_count == len(public_ips)
            else "PARTIAL" if asn_isp_partial
            else "UNAVAILABLE"
        )
        set_category(
            "asn_isp",
            asn_isp_status,
            f"Both ASN and ISP available for {asn_isp_count} of {len(public_ips)} public IP(s).",
        )

        ptr_count = sum(bool(_geo(ioc).get("reverse_dns")) for ioc in public_ips)
        ptr_attempted = sum(
            "DNS_PTR" in (_geo(ioc).get("provider_results") or {})
            for ioc in public_ips
        )
        ptr_status = (
            "AVAILABLE" if ptr_count == len(public_ips)
            else "PARTIAL" if ptr_count or ptr_attempted
            else "UNAVAILABLE"
        )
        set_category(
            "reverse_dns",
            ptr_status,
            f"PTR hostname resolved for {ptr_count} of {len(public_ips)} public IP(s).",
        )

    infra_iocs = [
        ioc for ioc in valid_iocs
        if ioc.get("type") in {"IP", "DOMAIN", "URL"}
        and (
            ioc.get("type") != "IP"
            or _is_public_ip(str(ioc.get("normalized_value") or ioc.get("value") or ""))
        )
    ]
    if infra_iocs:
        infrastructure_count = sum(
            bool(
                _geo(ioc).get("network")
                or _geo(ioc).get("network_type")
                or _geo(ioc).get("infrastructure_type")
                or any(
                    (ioc.get("intelligence") or {}).get(key)
                    for key in ("first_seen", "whois_created", "whois_registrar")
                )
            )
            for ioc in infra_iocs
        )
        infra_status = _status(infrastructure_count, len(infra_iocs))
        set_category(
            "infrastructure",
            infra_status,
            f"Specific network or infrastructure intelligence available for "
            f"{infrastructure_count} of {len(infra_iocs)} applicable network indicator(s).",
        )
    else:
        set_category(
            "infrastructure",
            "NOT_APPLICABLE",
            "No public IP, domain, or URL was present for infrastructure enrichment.",
        )

    attachments = parsed.get("attachments")
    if not attachments:
        set_category(
            "attachments",
            "NOT_APPLICABLE",
            "No attachments were present in the email.",
        )
    elif isinstance(attachments, list):
        hashed = sum(
            isinstance(attachment, dict) and bool(attachment.get("sha256"))
            for attachment in attachments
        )
        attachment_status = "PARTIAL"
        set_category(
            "attachments",
            attachment_status,
            f"Metadata extracted for {len(attachments)} attachment(s); "
            f"hashes available for {hashed}; "
            "content/malware scanning was not performed."
        )
    else:
        set_category("attachments", "UNAVAILABLE", "Attachment analysis data is unavailable.")

    urls = parsed.get("urls")
    if not urls:
        set_category("url_analysis", "NOT_APPLICABLE", "No URLs were present in the email.")
    elif isinstance(urls, list):
        extracted_urls = {
            str(ioc.get("normalized_value") or ioc.get("value"))
            for ioc in valid_iocs if ioc.get("type") == "URL"
        }
        covered_urls = sum(str(url) in extracted_urls for url in urls)
        set_category(
            "url_analysis",
            _status(covered_urls, len(urls)),
            f"Extracted and normalized {covered_urls} of {len(urls)} email URL(s).",
        )
    else:
        set_category("url_analysis", "UNAVAILABLE", "URL analysis data is unavailable.")

    applicable = [
        item for item in categories.values()
        if item["status"] != "NOT_APPLICABLE"
    ]
    available_count = sum(item["status"] == "AVAILABLE" for item in applicable)
    partial_count = sum(item["status"] == "PARTIAL" for item in applicable)
    unavailable = [
        item["label"] for item in applicable
        if item["status"] == "UNAVAILABLE"
    ]
    partial = [
        item["label"] for item in applicable
        if item["status"] == "PARTIAL"
    ]
    applicable_count = len(applicable)
    coverage = round(
        100 * (available_count + 0.5 * partial_count) / applicable_count,
        1,
    ) if applicable_count else 100.0
    return {
        "percentage": coverage,
        "available_count": available_count,
        "partial_count": partial_count,
        "unavailable_count": len(unavailable),
        "applicable_count": applicable_count,
        "categories": categories,
        "available": [
            item["label"] for item in applicable if item["status"] == "AVAILABLE"
        ],
        "partial": partial,
        "unavailable": unavailable,
        "not_applicable": [
            item["label"] for item in categories.values()
            if item["status"] == "NOT_APPLICABLE"
        ],
        "summary": (
            f"Evidence coverage: {coverage:.0f}% "
            f"({available_count} available, {partial_count} partial, "
            f"{len(unavailable)} unavailable of {applicable_count} applicable categories; "
            "partial categories count as half)."
        ),
    }
