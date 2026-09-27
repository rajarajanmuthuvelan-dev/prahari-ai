import re


STATUS_RE = re.compile(
    r"\b{key}\s*=\s*(pass|fail|hardfail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)


def _normalize_status(value: str | None) -> str:
    if value is None:
        return "NOT_AVAILABLE"
    status = value.lower()
    if status == "pass":
        return "PASS"
    if status in ("fail", "hardfail", "softfail", "permerror"):
        return "FAIL"
    if status == "neutral":
        return "NEUTRAL"
    if status == "none":
        return "NONE"
    return "NOT_AVAILABLE"


def _status_from_results(value: str, key: str) -> str:
    match = re.search(
        STATUS_RE.pattern.format(key=re.escape(key)),
        value,
        re.IGNORECASE,
    )
    return _normalize_status(match.group(1) if match else None)


def _status_from_received_spf(values: list[str]) -> str:
    if not values:
        return "NOT_AVAILABLE"
    first_token = re.match(r"\s*([A-Za-z]+)\b", values[0])
    return _normalize_status(first_token.group(1) if first_token else None)


def _detail(value: str, key: str) -> str | None:
    match = re.search(
        rf"\b{re.escape(key)}\s*=\s*[^;\s]+([^;]*)",
        value,
        re.IGNORECASE,
    )
    return match.group(1).strip() or None if match else None


def analyze_auth(headers: list[dict]) -> dict:
    auth_values = [
        header["value"]
        for header in headers
        if header["name"].lower() == "authentication-results"
    ]
    auth_results = "; ".join(auth_values)
    received_spf = [
        header["value"]
        for header in headers
        if header["name"].lower() == "received-spf"
    ]

    spf_from_auth_results = _status_from_results(auth_results, "spf")
    spf = spf_from_auth_results
    if spf_from_auth_results == "NOT_AVAILABLE":
        spf = _status_from_received_spf(received_spf)
    dkim = _status_from_results(auth_results, "dkim")
    dmarc = _status_from_results(auth_results, "dmarc")

    failures = sum(status == "FAIL" for status in (spf, dkim, dmarc))
    if failures:
        summary = (
            f"{failures} authentication mechanism(s) failed based on parsed headers."
        )
    elif (spf, dkim, dmarc) == ("PASS", "PASS", "PASS"):
        summary = "All authentication checks pass based on parsed headers."
    elif all(
        status == "NOT_AVAILABLE" for status in (spf, dkim, dmarc)
    ):
        summary = "Authentication results are not available in the email headers."
    else:
        summary = "Authentication results are mixed or incomplete."

    return {
        "spf": spf,
        "spf_detail": (
            auth_results[:120]
            if spf_from_auth_results != "NOT_AVAILABLE"
            else received_spf[0][:120]
            if received_spf
            else None
        ),
        "dkim": dkim,
        "dkim_detail": _detail(auth_results, "dkim"),
        "dmarc": dmarc,
        "dmarc_detail": _detail(auth_results, "dmarc"),
        "summary": summary,
    }
