import email.policy
import hashlib
import re
from html.parser import HTMLParser
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

from .ioc_normalizer import normalize_domain, parse_ip_address


URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"
)
DOMAIN_RE = re.compile(
    r"(?<![@A-Za-z0-9-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\.?"
)
IP_CANDIDATE_RE = re.compile(
    r"\[([^\]]+)\]|(?<![A-Za-z0-9:.])([0-9A-Fa-f:.]+)(?![A-Za-z0-9:.])"
)
RECEIVED_HOST_RE = re.compile(
    r"\b(from|by)\s+(\[[^\]]+\]|[^\s(;]+)", re.IGNORECASE
)
HEADER_NAME_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+:")


class _VisibleHTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in ("head", "title", "script", "style", "noscript"):
            self._hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in ("head", "title", "script", "style", "noscript") and self._hidden_depth:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden_depth:
            self.parts.append(data)


def _repair_unfolded_headers(raw_bytes: bytes) -> bytes:
    lines = raw_bytes.splitlines(keepends=True)
    repaired: list[bytes] = []
    current_header = b""
    in_headers = True

    for line in lines:
        if in_headers and line.rstrip(b"\r\n") == b"":
            repaired.append(line)
            in_headers = False
            continue
        if not in_headers:
            repaired.append(line)
            continue

        match = HEADER_NAME_RE.match(line)
        if match:
            current_header = line.split(b":", 1)[0].lower()
            repaired.append(line)
            continue

        if current_header and repaired:
            ending = b"\r\n" if repaired[-1].endswith(b"\r\n") else b"\n"
            previous = repaired[-1]
            previous = previous[:-len(ending)] if previous.endswith(ending) else previous
            continuation = line.rstrip(b"\r\n").lstrip()
            repaired[-1] = previous + b" " + continuation + ending
        else:
            repaired.append(line)

    return b"".join(repaired)


def _decode_header_value(raw: str) -> str:
    parts = decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded)


def _extract_valid_ips(text: str) -> list[str]:
    found: list[str] = []
    for bracketed, unbracketed in IP_CANDIDATE_RE.findall(text):
        candidate = (bracketed or unbracketed).strip()
        try:
            address = parse_ip_address(candidate)
        except ValueError:
            continue
        canonical = str(address)
        if canonical not in found:
            found.append(canonical)
    return found


def _normalize_received_host(host: str) -> str | None:
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(parse_ip_address(candidate))
    except ValueError:
        domain = normalize_domain(candidate)
        if domain:
            return domain
        if "." in candidate or ":" in candidate or all(
            label.isdigit() for label in candidate.rstrip(".").split(".")
        ):
            return None
        try:
            hostname = candidate.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        labels = hostname.split(".")
        if len(hostname) > 253 or any(
            len(label) > 63
            or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label
            )
            for label in labels
        ):
            return None
        return hostname


def _parse_received(value: str) -> dict:
    route, separator, raw_timestamp = value.rpartition(";")
    if not separator:
        route = value
        raw_timestamp = ""

    hosts: dict[str, str | None] = {"from_host": None, "by_host": None}
    for match in RECEIVED_HOST_RE.finditer(route):
        key = f"{match.group(1).lower()}_host"
        hosts[key] = _normalize_received_host(match.group(2))

    timestamp = None
    if raw_timestamp.strip():
        try:
            timestamp = parsedate_to_datetime(raw_timestamp.strip()).isoformat()
        except (TypeError, ValueError, OverflowError):
            pass

    return {
        **hosts,
        "timestamp": timestamp,
        "ips": _extract_valid_ips(route),
    }


def _get_text(msg) -> tuple[str, str]:
    body_text = ""
    body_html = ""
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            raw_payload = part.get_payload()
            if isinstance(raw_payload, str):
                text = raw_payload
            else:
                continue
        else:
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")

        if content_type == "text/plain" and not body_text:
            body_text = text
        elif content_type == "text/html" and not body_html:
            body_html = text
    if not body_text and body_html:
        visible_text = _VisibleHTMLText()
        visible_text.feed(body_html)
        body_text = " ".join(" ".join(visible_text.parts).split())
    return body_text, body_html


def _get_attachments(msg) -> list[dict]:
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() not in ("attachment", "inline"):
            continue
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "filename": _decode_header_value(str(filename)),
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return attachments


def _extract_domains(values: list[tuple[str, str]]) -> list[dict]:
    domains: list[dict] = []
    seen: set[str] = set()
    for text, source in values:
        for candidate in DOMAIN_RE.findall(text):
            normalized = normalize_domain(candidate)
            if normalized and normalized not in seen:
                seen.add(normalized)
                domains.append({"value": candidate.rstrip("."), "source": source})
    return domains


def parse_eml(raw_bytes: bytes) -> dict:
    msg = BytesParser(policy=email.policy.default).parsebytes(
        _repair_unfolded_headers(raw_bytes)
    )
    headers = [
        {"name": name, "value": _decode_header_value(str(value))}
        for name, value in msg.items()
    ]

    from_addr = _decode_header_value(str(msg.get("From", "")))
    to_addr = _decode_header_value(str(msg.get("To", "")))
    subject = _decode_header_value(str(msg.get("Subject", "")))
    date = str(msg.get("Date", ""))
    reply_to = _decode_header_value(str(msg.get("Reply-To", ""))) or None
    message_id = str(msg.get("Message-ID", "")) or None

    received_headers = [
        _parse_received(str(value)) for value in msg.get_all("Received", [])
    ]
    received_ips = list(
        dict.fromkeys(ip for header in received_headers for ip in header["ips"])
    )
    x_originating_ips = list(
        dict.fromkeys(
            ip
            for value in msg.get_all("X-Originating-IP", [])
            for ip in _extract_valid_ips(str(value))
        )
    )

    body_text, body_html = _get_text(msg)
    combined_body = f"{body_text}\n{body_html}"
    urls = list(
        dict.fromkeys(
            match.rstrip(".,;!?)") for match in URL_RE.findall(combined_body)
        )
    )
    header_email_text = f"{from_addr}\n{to_addr}\n{reply_to or ''}"
    email_evidence = []
    for name, value in (
        ("From Header", from_addr),
        ("To Header", to_addr),
        ("Reply-To Header", reply_to or ""),
    ):
        email_evidence.extend(
            {"value": address, "source": name}
            for address in dict.fromkeys(EMAIL_RE.findall(value))
        )
    email_evidence.extend(
        {"value": address, "source": "Email Body"}
        for address in dict.fromkeys(EMAIL_RE.findall(combined_body))
    )
    email_addresses = list(
        dict.fromkeys(item["value"] for item in email_evidence)
    )
    body_ips = _extract_valid_ips(combined_body)
    domain_sources = [
        (header["value"], f"{header['name']} Header")
        for header in headers
        if header["name"].lower() != "received"
    ]
    domain_sources.extend([
        (combined_body, "Email Body"),
        *[(url, "Email Body URL") for url in urls],
    ])
    domains = _extract_domains(domain_sources)
    attachments = _get_attachments(msg)

    return {
        "from_addr": from_addr,
        "to_addr": to_addr,
        "subject": subject,
        "date": date,
        "reply_to": reply_to,
        "message_id": message_id,
        "headers": headers,
        "body_text": body_text,
        "body_html": body_html,
        "received_headers": received_headers,
        "received_ips": received_ips,
        "x_originating_ips": x_originating_ips,
        "body_ips": body_ips,
        "domains": domains,
        "urls": urls,
        "email_addresses": email_addresses,
        "email_evidence": email_evidence,
        "attachments": attachments,
    }
