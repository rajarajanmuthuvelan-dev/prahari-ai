import re
from .nlp_service import analyze_content
from .ioc_reputation import reputation_state
from .evidence_coverage import calculate_evidence_coverage


def _score_auth(auth: dict) -> dict:
    signals: list[str] = []
    score = 0

    def check(status: str, name: str, fail_pts: int, neutral_pts: int):
        nonlocal score
        if status == "FAIL":
            score += fail_pts
            signals.append(f"{name}: FAIL (+{fail_pts} points)")
        elif status == "PASS":
            signals.append(f"{name}: PASS (+0 points)")
        elif status in ("NEUTRAL", "NONE"):
            score += neutral_pts
            signals.append(f"{name}: {status} (+{neutral_pts} points)")
        else:
            signals.append(f"{name}: Not available (+0 points)")

    check(auth.get("spf", "NOT_AVAILABLE"), "SPF", 7, 2)
    check(auth.get("dkim", "NOT_AVAILABLE"), "DKIM", 7, 2)
    check(auth.get("dmarc", "NOT_AVAILABLE"), "DMARC", 6, 1)

    return {"score": min(20, score), "max": 20, "signals": signals}


def _score_reputation(iocs: list[dict]) -> dict:
    signals: list[str] = []
    score = 0
    unavailable = 0

    for ioc in iocs:
        if not ioc.get("valid"):
            continue
        intelligence = ioc.get("intelligence") or {}
        rep = intelligence.get("reputation")
        state = reputation_state(intelligence)
        if (
            intelligence.get("lookup_status") != "FOUND"
            or rep is None
            or state == "UNKNOWN"
        ):
            unavailable += 1
            continue
        if state == "CLEAN":
            continue
        label = ioc["value"][:50] + ("…" if len(ioc["value"]) > 50 else "")
        if rep >= 90:
            score += 8
            signals.append(
                f"{ioc['type']} {label} — {state} ({rep}% threat score, +8 risk points)"
            )
        elif rep >= 70:
            score += 5
            signals.append(f"{ioc['type']} {label} — {state} ({rep}%, +5 risk points)")
        elif rep >= 40:
            score += 2
            signals.append(f"{ioc['type']} {label} — {state} ({rep}%, +2 risk points)")
    if unavailable:
        signals.append(
            f"Reputation unavailable for {unavailable} valid IOC(s); no reputation risk points were assigned."
        )

    return {"score": min(25, score), "max": 25, "signals": signals}


def _score_infrastructure(parsed: dict, iocs: list[dict]) -> dict:
    signals: list[str] = []
    score = 0

    for ioc in iocs:
        if not ioc.get("valid"):
            continue
        tags = (ioc.get("intelligence") or {}).get("tags", [])
        if ioc["type"] == "IP":
            if any(re.search(r'tor', t, re.IGNORECASE) for t in tags):
                score += 6
                signals.append(f"Tor exit node in sending path: {ioc['value']} (+6 points)")
            elif any(re.search(r'bulletproof', t, re.IGNORECASE) for t in tags):
                score += 4
                signals.append(f"Bulletproof hosting detected: {ioc['value']} (+4 points)")
        if ioc["type"] == "DOMAIN":
            first_seen = (ioc.get("intelligence") or {}).get("first_seen")
            if first_seen:
                try:
                    from datetime import datetime
                    days = (datetime.utcnow() - datetime.fromisoformat(first_seen)).days
                    if days < 7:
                        score += 5
                        signals.append(
                            f'Domain "{ioc["value"]}" newly registered ({days}d old, +5 points)'
                        )
                    elif days < 30:
                        score += 2
                        signals.append(
                            f'Domain "{ioc["value"]}" recently registered ({days}d old, +2 points)'
                        )
                except Exception:
                    pass

    from_addr = parsed.get("from_addr", "")
    from_domain = re.search(r'@([^>@\s,]+)', from_addr)
    fd = from_domain.group(1).lower() if from_domain else ""
    brands = [
        ("paypal", "paypa"),
        ("microsoft", "microsof"),
        ("apple", "app1e"),
        ("google", "g00gle"),
        ("amazon", "arnazon"),
    ]
    for brand, fake in brands:
        if fake in fd and not fd.endswith(f"{brand}.com"):
            score += 5
            signals.append(
                f'Lookalike/typosquatting domain: "{fd}" impersonating "{brand}" (+5 points)'
            )
            break

    x_mailer = next((h["value"] for h in parsed.get("headers", []) if h["name"].lower() == "x-mailer"), "")
    if re.search(r'bulk|mass|blast|spam', x_mailer, re.IGNORECASE):
        score += 3
        signals.append(f"X-Mailer indicates bulk sending tool: {x_mailer} (+3 points)")

    reply_to = parsed.get("reply_to", "")
    if reply_to and fd:
        rt_domain = re.search(r'@([^>@\s,]+)', reply_to)
        if rt_domain and rt_domain.group(1).lower() != fd:
            score += 3
            signals.append(
                f"Reply-To domain ({rt_domain.group(1)}) differs from From domain ({fd}) (+3 points)"
            )

    return {"score": min(30, score), "max": 30, "signals": signals}


def compute_risk_score(parsed: dict, auth: dict, iocs: list[dict]) -> dict:
    nlp = analyze_content(parsed.get("subject", ""), parsed.get("body_text", ""))
    content = {
        "score": nlp["score_contribution"],
        "max": 25,
        "signals": nlp["signals"],
        "model_used": nlp["model_used"],
        "is_rule_based": nlp["is_rule_based"],
        "rule_score": nlp["rule_score"],
        "ai_score": nlp["ai_score"],
    }
    authentication = _score_auth(auth)
    reputation = _score_reputation(iocs)
    infrastructure = _score_infrastructure(parsed, iocs)

    total = content["score"] + authentication["score"] + reputation["score"] + infrastructure["score"]

    if total >= 80:
        level = "CRITICAL"
    elif total >= 60:
        level = "HIGH"
    elif total >= 40:
        level = "MEDIUM"
    elif total >= 20:
        level = "LOW"
    else:
        level = "CLEAN"

    drivers = []
    if reputation["score"] >= 15:
        drivers.append("malicious IOC reputation")
    if authentication["score"] >= 12:
        drivers.append("authentication failure")
    if infrastructure["score"] >= 12:
        drivers.append("suspicious infrastructure")
    if content["score"] >= 12:
        drivers.append("high-risk content patterns")

    explanation = (
        f"{level} risk driven primarily by: {', '.join(drivers)}."
        if drivers
        else f"Risk score {total}/100 from multi-signal weighted analysis."
    )
    evidence_coverage = calculate_evidence_coverage(
        parsed,
        auth,
        iocs,
        nlp.get("ai_analysis"),
    )
    confidence = evidence_coverage["percentage"]
    explanation = f"{explanation} {evidence_coverage['summary']}"

    return {
        "total": total,
        "level": level,
        "confidence": confidence,
        "evidence_coverage": evidence_coverage,
        "content": content,
        "authentication": authentication,
        "reputation": reputation,
        "infrastructure": infrastructure,
        "ai_analysis": nlp["ai_analysis"],
        "explanation": explanation,
    }
