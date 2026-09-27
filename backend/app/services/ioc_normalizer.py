import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
_DOMAIN_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_HASH_LENGTHS = {32, 40, 64}
_IPV4_RE = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}\Z")
_NON_PUBLIC_SUFFIXES = {
    "example",
    "invalid",
    "localhost",
    "local",
    "internal",
    "test",
    "home",
    "lan",
    "arpa",
}


def parse_ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if address.version == 4 and not _IPV4_RE.fullmatch(value):
        raise ValueError("IPv4 addresses must use four dotted-decimal octets.")
    return address


def normalize_domain(value: str) -> str | None:
    domain = value.strip().rstrip(".")
    if not domain or len(domain) > 253:
        return None
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(
        len(label) > 63 or not _DOMAIN_LABEL_RE.fullmatch(label)
        for label in labels
    ):
        return None
    if not re.fullmatch(r"[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59}", labels[-1]):
        return None
    return ascii_domain


def is_public_domain(value: str) -> bool:
    domain = normalize_domain(value)
    return bool(domain and domain.rsplit(".", 1)[1] not in _NON_PUBLIC_SUFFIXES)


def normalize_ioc(
    ioc_type: str,
    value: str,
    source: str,
    confidence: int = 100,
) -> dict:
    original = str(value)
    candidate = original.strip()
    kind = ioc_type.upper()
    normalized_value: str | None = None

    if kind == "IP":
        try:
            normalized_value = str(parse_ip_address(candidate))
        except ValueError:
            pass
    elif kind == "DOMAIN":
        normalized_value = normalize_domain(candidate)
    elif kind == "URL":
        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname
            if parsed.scheme.lower() in ("http", "https") and hostname:
                port = parsed.port
                try:
                    host_ip = parse_ip_address(hostname)
                    normalized_host = (
                        f"[{host_ip.compressed}]"
                        if host_ip.version == 6
                        else host_ip.compressed
                    )
                except ValueError:
                    normalized_host = normalize_domain(hostname)
                if normalized_host:
                    userinfo = (
                        f"{parsed.username}:{parsed.password}@"
                        if parsed.username is not None and parsed.password is not None
                        else f"{parsed.username}@"
                        if parsed.username is not None
                        else ""
                    )
                    normalized_netloc = f"{userinfo}{normalized_host}"
                    if port is not None:
                        normalized_netloc += f":{port}"
                    normalized_value = urlunsplit(
                        (
                            parsed.scheme.lower(),
                            normalized_netloc,
                            parsed.path,
                            parsed.query,
                            parsed.fragment,
                        )
                    )
        except ValueError:
            pass
    elif kind == "EMAIL":
        if _EMAIL_RE.fullmatch(candidate):
            local, domain = candidate.rsplit("@", 1)
            normalized_domain = normalize_domain(domain)
            if normalized_domain:
                normalized_value = f"{local}@{normalized_domain}"
    elif kind == "HASH":
        if len(candidate) in _HASH_LENGTHS and re.fullmatch(
            r"[A-Fa-f0-9]+", candidate
        ):
            normalized_value = candidate.lower()

    valid = normalized_value is not None
    return {
        "type": kind,
        "value": original,
        "source": source,
        "normalized_value": normalized_value or candidate,
        "valid": valid,
        "confidence": max(0, min(100, confidence)) if valid else 0,
    }
