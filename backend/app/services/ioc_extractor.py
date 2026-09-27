import uuid
from urllib.parse import urlsplit

from .ioc_normalizer import normalize_domain, normalize_ioc, parse_ip_address


def extract_iocs(parsed: dict) -> list[dict]:
    iocs: list[dict] = []
    seen: set[str] = set()

    def add(ioc_type: str, value: str, source: str) -> None:
        normalized = normalize_ioc(ioc_type, value, source)
        if not normalized["valid"]:
            return
        canonical_value = normalized["normalized_value"]
        if normalized["type"] in ("IP", "DOMAIN", "HASH"):
            canonical_value = canonical_value.casefold()
        key = f"{normalized['type']}:{canonical_value}"
        if key in seen:
            return
        seen.add(key)
        iocs.append(
            {
                "id": str(uuid.uuid4()),
                **normalized,
                "risk": "UNKNOWN",
                "status": "UNKNOWN",
            }
        )

    for ip in parsed.get("received_ips", []):
        add("IP", ip, "Received Header")
    for ip in parsed.get("x_originating_ips", []):
        add("IP", ip, "X-Originating-IP Header")
    for ip in parsed.get("body_ips", []):
        add("IP", ip, "Email Body")

    for header in parsed.get("received_headers", []):
        for key in ("from_host", "by_host"):
            host = header.get(key)
            if not host:
                continue
            try:
                parse_ip_address(host)
            except ValueError:
                if normalize_domain(host):
                    add("DOMAIN", host, f"Received Header ({key.replace('_', '-')})")

    for domain in parsed.get("domains", []):
        add("DOMAIN", domain["value"], domain["source"])

    for url in parsed.get("urls", []):
        add("URL", url, "Email Body")
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            hostname = None
        if not hostname:
            continue
        try:
            parse_ip_address(hostname)
        except ValueError:
            if normalize_domain(hostname):
                add("DOMAIN", hostname, "Email Body URL")
        else:
            add("IP", hostname, "Email Body URL")

    for item in parsed.get("email_evidence", []):
        add("EMAIL", item["value"], item["source"])

    for attachment in parsed.get("attachments", []):
        digest = attachment.get("sha256")
        if digest:
            add("HASH", digest, f"Attachment: {attachment.get('filename', 'unknown')}")

    return iocs
