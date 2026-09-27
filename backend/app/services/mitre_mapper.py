import re


def _phishing_link_evidence(
    parsed: dict,
    iocs: list[dict],
) -> list[str]:
    evidence: list[str] = []

    body = f"{parsed.get('subject', '')}\n{parsed.get('body_text', '')}"
    action = re.search(
        r"\b(click|open|visit|follow|review|secure|verify|confirm|update|reset|"
        r"sign\s*in|log\s*in|submit)\b",
        body,
        re.IGNORECASE,
    )
    target = re.search(
        r"\b(account|password|credential|bank(?:ing)?|payment|card|invoice|mailbox)\b",
        body,
        re.IGNORECASE,
    )
    pressure = re.search(
        r"\b(urgent|immediately|within\s+\d+\s+hours?|suspend(?:ed)?|"
        r"block(?:ed)?|close(?:d)?|expire(?:s|d)?|unauthorized)\b",
        body,
        re.IGNORECASE,
    )
    if action and target and pressure:
        evidence.append(
            "Email requests an account/payment action under urgency or threat"
        )

    malicious_link_iocs = [
        ioc for ioc in iocs
        if ioc.get("type") in ("URL", "DOMAIN")
        and ioc.get("valid") is True
        and (ioc.get("intelligence") or {}).get("lookup_status") == "FOUND"
        and (
            (ioc.get("intelligence") or {}).get("reputation") is not None
            and (ioc.get("intelligence") or {}).get("reputation") >= 70
        )
    ]
    if malicious_link_iocs:
        evidence.append(
            "Threat intelligence reports a linked URL/domain as high risk: "
            + ", ".join(ioc["value"][:80] for ioc in malicious_link_iocs[:2])
        )
    return evidence


def map_mitre(
    parsed: dict,
    auth: dict,
    iocs: list[dict],
    risk_score: dict | None = None,
) -> list[dict]:
    mappings: list[dict] = []

    if parsed.get("urls"):
        evidence = _phishing_link_evidence(parsed, iocs)
        if evidence:
            evidence.extend(
                f"URL: {ioc['value'][:80]}"
                for ioc in iocs
                if ioc.get("type") == "URL" and ioc.get("valid") is True
            )
            evidence = evidence[:4]
            mappings.append({
                "technique_id": "T1566.002",
                "technique_name": "Phishing: Spearphishing Link",
                "tactic": "Initial Access",
                "tactic_id": "TA0001",
                "description": "Email links are accompanied by phishing indicators or corroborating malicious link intelligence.",
                "evidence": evidence,
            })

    if auth.get("spf") == "FAIL" or auth.get("dkim") == "FAIL":
        evidence = [e for e in [
            "SPF FAIL — sender IP not authorized" if auth.get("spf") == "FAIL" else "",
            "DKIM FAIL — signature invalid" if auth.get("dkim") == "FAIL" else "",
            "DMARC FAIL — policy enforcement failure" if auth.get("dmarc") == "FAIL" else "",
        ] if e]
        mappings.append({
            "technique_id": "T1036.005",
            "technique_name": "Masquerading: Match Legitimate Name",
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "description": "Email authentication failures indicate sender identity spoofing or unauthorized sending infrastructure.",
            "evidence": evidence,
        })

    reply_to = parsed.get("reply_to", "")
    from_addr = parsed.get("from_addr", "")
    if reply_to:
        fd = re.search(r'@([^>@\s,]+)', from_addr)
        rd = re.search(r'@([^>@\s,]+)', reply_to)
        if fd and rd and fd.group(1) != rd.group(1):
            mappings.append({
                "technique_id": "T1598.003",
                "technique_name": "Phishing for Information: Spearphishing Link",
                "tactic": "Reconnaissance",
                "tactic_id": "TA0043",
                "description": "Reply-To address routes victim responses to an attacker-controlled mailbox.",
                "evidence": [f"Reply-To ({rd.group(1)}) differs from From domain ({fd.group(1)})"],
            })

    return mappings
