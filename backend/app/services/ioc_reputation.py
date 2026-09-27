from typing import Any


REPUTATION_STATES = {"MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"}


def reputation_lookup_source(intelligence: dict[str, Any], state: str) -> str:
    if state == "UNKNOWN":
        return "No reputation result"
    source = intelligence.get("provider") or intelligence.get("source")
    if source and str(source).upper() not in {"UNKNOWN", "UNAVAILABLE", "NO_DATA"}:
        return str(source)
    return "No reputation result"


def evidence_category(ioc: dict[str, Any]) -> str:
    source = str(ioc.get("source") or "").casefold()
    value = str(ioc.get("normalized_value") or ioc.get("value") or "").casefold()
    ioc_type = str(ioc.get("type") or "").upper()
    if any(token in value for token in ("smtp.mailfrom", "header.from", "header.d", "header.i")) or any(
        token in source
        for token in (
            "authentication-results",
            "arc-authentication",
            "arc-seal",
            "arc-message-signature",
            "dkim-signature",
            "received-spf",
        )
    ):
        return "Authentication artifact"
    if "email body" not in source and (ioc_type == "EMAIL" or any(
        token in source for token in ("from header", "to header", "reply-to header")
    )):
        return "Sender identity"
    if any(token in source for token in ("received header", "x-originating-ip")):
        return "Network/header infrastructure"
    if "attachment" in source:
        return "Attachment evidence"
    if "email body" in source:
        return "URL/domain IOC" if ioc_type in {"URL", "DOMAIN"} else "Email evidence"
    if (ioc.get("reputation_status") or ioc.get("status")) in {"MALICIOUS", "SUSPICIOUS"}:
        return "Threat intelligence"
    return "Email evidence"


def reputation_state(
    intelligence: dict[str, Any] | None,
    fallback_status: str | None = None,
) -> str:
    intel = intelligence or {}
    reputation = intel.get("reputation")
    if intel.get("lookup_status", intel.get("status")) != "FOUND" or reputation is None:
        return "UNKNOWN"

    explicit = str(intel.get("reputation_status") or "").upper()
    if explicit in REPUTATION_STATES:
        return explicit

    tags = " ".join(str(tag) for tag in intel.get("tags", [])).casefold()
    if any(term in tags for term in ("malicious", "phishing", "credential harvesting", "botnet", "c2")):
        return "MALICIOUS"
    if any(term in tags for term in ("suspicious", "watchlist", "proxy", "bulletproof", "spam")):
        return "SUSPICIOUS"

    if reputation >= 90:
        return "MALICIOUS"
    if reputation >= 40:
        return "SUSPICIOUS"
    if reputation >= 0:
        return "CLEAN"
    return fallback_status if fallback_status in REPUTATION_STATES else "UNKNOWN"


def reputation_risk_contribution(intelligence: dict[str, Any] | None) -> int:
    intel = intelligence or {}
    reputation = intel.get("reputation")
    if (
        intel.get("lookup_status", intel.get("status")) != "FOUND"
        or reputation is None
        or reputation_state(intel) in {"UNKNOWN", "CLEAN"}
    ):
        return 0
    if reputation >= 90:
        return 8
    if reputation >= 70:
        return 5
    if reputation >= 40:
        return 2
    return 0


def normalize_ioc_reputation(ioc: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(ioc)
    intelligence = dict(ioc.get("intelligence") or {})
    state = reputation_state(intelligence, ioc.get("status"))
    contribution = reputation_risk_contribution(intelligence)
    intelligence["reputation_status"] = state
    intelligence["risk_contribution"] = contribution
    intelligence["lookup_source"] = reputation_lookup_source(intelligence, state)
    if state == "UNKNOWN":
        intelligence.setdefault("reason", "No threat-intelligence result available")
    normalized["intelligence"] = intelligence
    normalized["reputation_status"] = state
    normalized["risk_contribution"] = contribution
    normalized["status"] = state
    normalized["lookup_status"] = intelligence.get(
        "lookup_status", intelligence.get("status", "UNAVAILABLE")
    )
    normalized["lookup_source"] = reputation_lookup_source(intelligence, state)
    normalized["geo_source"] = (intelligence.get("geo") or {}).get("source")
    normalized["evidence_category"] = evidence_category(normalized)
    return normalized
