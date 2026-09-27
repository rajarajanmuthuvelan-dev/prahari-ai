import re
from typing import Any

from .ioc_reputation import reputation_state


THREAT_TYPE_LABELS = {
    "Business Email Compromise",
    "Phishing",
    "Impersonation",
    "Malware / Suspicious Attachment",
    "Suspicious Email",
    "Clean",
}

_PRESSURE_RE = re.compile(
    r"\b(?:urgent|immediately|asap|act now|action required|within\s+\d+\s+hours?|"
    r"expires?|suspended|verify now|final notice)\b",
    re.IGNORECASE,
)
_CREDENTIAL_RE = re.compile(
    r"\b(?:verify|confirm|update|restore|unlock|validate).{0,45}"
    r"(?:password|credentials?|account|sign[ -]?in|log[ -]?in|identity)\b"
    r"|\b(?:password|credentials?|account|sign[ -]?in|log[ -]?in).{0,45}"
    r"(?:verify|confirm|update|restore|unlock|validate)\b",
    re.IGNORECASE,
)
_PAYMENT_RE = re.compile(
    r"\b(?:wire transfer|bank account|bank details|payment details|"
    r"invoice payment|payroll|gift cards?|remittance|funds transfer|"
    r"change.{0,20}payment|update.{0,20}bank|purchase.{0,20}gift card)\b",
    re.IGNORECASE,
)
_BEC_CONTEXT_RE = re.compile(
    r"\b(?:ceo|cfo|chief executive|chief financial|executive|finance team|"
    r"accounts payable|vendor|supplier|payroll|wire transfer)\b",
    re.IGNORECASE,
)
_IMPERSONATION_RE = re.compile(
    r"\b(?:impersonat(?:ion|ing|es)?|look[ -]?alike|typosquat(?:ting)?|"
    r"spoof(?:ed|ing)?|pretending to be|on behalf of)\b",
    re.IGNORECASE,
)
_PHISHING_CONTEXT_RE = re.compile(
    r"\b(?:credential harvest(?:ing)?|password harvest(?:ing)?|"
    r"login page|sign[ -]?in page|account verification|credential theft)\b",
    re.IGNORECASE,
)
_SUSPICIOUS_URL_RE = re.compile(
    r"(?:https?://\d{1,3}(?:\.\d{1,3}){3}(?=[:/])|"
    r"https?://[^/\s]*(?:xn--|bit\.ly|tinyurl\.com|t\.co|rb\.gy)|"
    r"https?://[^/\s]+/(?:login|signin|verify|validate|credential|"
    r"password|account[-_/]?security)(?:[/?#]|$))",
    re.IGNORECASE,
)
_SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".ade", ".adp", ".app", ".bat", ".cab", ".cmd", ".com", ".cpl",
    ".docm", ".exe", ".hta", ".iso", ".js", ".jse", ".lnk", ".msi",
    ".msp", ".ocx", ".pif", ".ps1", ".rar", ".scr", ".sct", ".shb",
    ".sys", ".vbe", ".vbs", ".wsf", ".wsh", ".xll", ".xlsm", ".xltm",
}
_KNOWN_BRANDS = {
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.in"),
    "google": ("google.com", "google.co.uk", "google.co.in"),
    "microsoft": ("microsoft.com", "outlook.com", "office.com"),
    "paypal": ("paypal.com",),
}


def _signals(risk_score: dict[str, Any] | None) -> list[str]:
    return [
        str(signal)
        for component in (risk_score or {}).values()
        if isinstance(component, dict)
        for signal in component.get("signals", [])
    ]


def _sender_impersonation(parsed: dict[str, Any], signals: list[str]) -> bool:
    if any(_IMPERSONATION_RE.search(signal) for signal in signals):
        return True

    sender = str(parsed.get("from_addr") or "")
    display_name = sender.split("<", 1)[0]
    address = re.search(r"<([^>]+)>", sender)
    address_text = address.group(1) if address else sender
    domain_match = re.search(r"@([^>\s,]+)", address_text)
    if not domain_match:
        return False
    domain = domain_match.group(1).casefold().rstrip(".")
    name = display_name.casefold()
    for brand, domains in _KNOWN_BRANDS.items():
        if brand in name and not any(
            domain == known_domain or domain.endswith(f".{known_domain}")
            for known_domain in domains
        ):
            return True
    return False


def _attachment_threat(
    parsed: dict[str, Any],
    iocs: list[dict[str, Any]],
) -> bool:
    for ioc in iocs:
        source = str(ioc.get("source") or "").casefold()
        intel = ioc.get("intelligence") or {}
        if (
            ioc.get("type") == "HASH"
            and "attachment" in source
            and ioc.get("valid") is True
            and reputation_state(intel, ioc.get("status")) in {"MALICIOUS", "SUSPICIOUS"}
        ):
            return True

    for attachment in parsed.get("attachments") or []:
        if not isinstance(attachment, dict):
            continue
        filename = str(attachment.get("filename") or "").casefold()
        suffix = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
        if suffix in _SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            return True
        if re.search(r"\.(?:pdf|docx?|xlsx?|jpg|png)\.(?:exe|js|vbs|scr|bat|ps1)$", filename):
            return True
        content_type = str(attachment.get("content_type") or "").casefold()
        if content_type in {
            "application/x-dosexec",
            "application/x-msdownload",
            "application/x-msi",
            "application/x-sh",
        }:
            return True
    return False


def _ioc_evidence(iocs: list[dict[str, Any]]) -> tuple[bool, bool]:
    malicious = False
    suspicious = False
    for ioc in iocs:
        if ioc.get("valid") is not True:
            continue
        intel = ioc.get("intelligence") or {}
        if intel.get("lookup_status", intel.get("status")) != "FOUND":
            continue
        state = reputation_state(intel, ioc.get("status"))
        if state == "MALICIOUS":
            malicious = True
        elif state == "SUSPICIOUS":
            suspicious = True
    return malicious, suspicious


def _suspicious_url(parsed: dict[str, Any], iocs: list[dict[str, Any]]) -> bool:
    urls = [str(url) for url in parsed.get("urls") or []]
    if any(_SUSPICIOUS_URL_RE.search(url) for url in urls):
        return True
    for ioc in iocs:
        if ioc.get("valid") is not True or ioc.get("type") not in {"URL", "DOMAIN"}:
            continue
        intel = ioc.get("intelligence") or {}
        if (
            intel.get("lookup_status", intel.get("status")) == "FOUND"
            and reputation_state(intel, ioc.get("status")) in {"MALICIOUS", "SUSPICIOUS"}
        ):
            return True
    return False


def _ai_phishing_evidence(ai_analysis: dict[str, Any]) -> bool:
    models = [
        model for model in ai_analysis.get("models") or []
        if str(model.get("status", "")).upper() == "AVAILABLE"
    ]
    model_probabilities = [
        float(model["phishing_probability"])
        for model in models
        if isinstance(model.get("phishing_probability"), (int, float))
    ]
    combined = ai_analysis.get("combined_ai_signal") or {}
    combined_probability = combined.get("phishing_probability")
    if not isinstance(combined_probability, (int, float)):
        combined_probability = ai_analysis.get("aggregate_phishing_probability")
    strong_models = sum(probability >= 0.75 for probability in model_probabilities)
    combined_strong = (
        isinstance(combined_probability, (int, float))
        and combined_probability >= 0.75
    )
    return strong_models >= 2 or (strong_models >= 1 and combined_strong)


def classify_threat_type(
    parsed: dict[str, Any],
    auth: dict[str, Any],
    iocs: list[dict[str, Any]],
    ai_analysis: dict[str, Any] | None,
    risk_score: dict[str, Any] | None,
    mitre_mappings: list[dict[str, Any]] | None = None,
) -> str:
    """Classify threat type from evidence without consulting score totals or verdict."""
    ai_analysis = ai_analysis or {}
    signals = _signals(risk_score)
    text = " ".join(
        (
            str(parsed.get("subject") or ""),
            str(parsed.get("body_text") or ""),
            str(parsed.get("body_html") or ""),
        )
    )
    pressure = bool(_PRESSURE_RE.search(text))
    credential_harvesting = bool(_CREDENTIAL_RE.search(text)) or any(
        _PHISHING_CONTEXT_RE.search(signal) for signal in signals
    )
    payment_request = bool(_PAYMENT_RE.search(text))
    business_context = bool(_BEC_CONTEXT_RE.search(text))
    impersonation = _sender_impersonation(parsed, signals)
    suspicious_url = _suspicious_url(parsed, iocs)
    malicious_ioc, suspicious_ioc = _ioc_evidence(iocs)
    attachment_threat = _attachment_threat(parsed, iocs)
    auth_failure = any(
        str(auth.get(protocol, "")).upper() == "FAIL"
        for protocol in ("spf", "dkim", "dmarc")
    )
    infrastructure_evidence = any(
        re.search(r"\b(?:tor exit node|bulletproof hosting|newly registered|"
                  r"recently registered|lookalike|typosquatting)\b", signal, re.I)
        for signal in signals
    )
    explicit_phishing_indicator = any(
        _PHISHING_CONTEXT_RE.search(signal) for signal in signals
    )
    ai_phishing = _ai_phishing_evidence(ai_analysis)
    email_mappings = mitre_mappings or []
    phishing_evidence = (
        credential_harvesting
        or suspicious_url
        or explicit_phishing_indicator
        or any(
            mapping.get("technique_id") == "T1566.002"
            for mapping in email_mappings
        )
        or (ai_phishing and (pressure or auth_failure or bool(parsed.get("urls"))))
    )
    related_bec_evidence = (
        impersonation or credential_harvesting or pressure or auth_failure
    )

    if payment_request and (business_context or impersonation) and related_bec_evidence:
        return "Business Email Compromise"
    if phishing_evidence:
        return "Phishing"
    if attachment_threat:
        return "Malware / Suspicious Attachment"
    if impersonation:
        return "Impersonation"
    if (
        pressure
        or auth_failure
        or malicious_ioc
        or suspicious_ioc
        or infrastructure_evidence
        or ai_phishing
        or any(mapping.get("technique_id") for mapping in email_mappings)
    ):
        return "Suspicious Email"
    return "Clean"


def normalize_threat_type(value: str | None) -> str | None:
    if value in THREAT_TYPE_LABELS:
        return value
    aliases = {
        "bec": "Business Email Compromise",
        "malware": "Malware / Suspicious Attachment",
        "suspicious": "Suspicious Email",
        "phishing": "Phishing",
        "impersonation": "Impersonation",
        "clean": "Clean",
    }
    return aliases.get(str(value or "").casefold())
