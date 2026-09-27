from typing import Any


RISK_FLOW = [
    "AI Content",
    "Authentication",
    "IOC Reputation",
    "Infrastructure",
    "Multi-Signal Risk Engine",
    "Risk Score + Verdict",
]
RISK_FLOW_TEXT = (
    "AI Content + Authentication + IOC Reputation + Infrastructure "
    "↓ Multi-Signal Risk Engine ↓ Risk Score + Verdict"
)
AI_INTERPRETATION = (
    "AI is one evidence source. Final risk is determined by multi-signal analysis."
)


def format_investigation_explanation(risk_score: dict[str, Any]) -> str:
    categories = (
        ("authentication", "authentication"),
        ("content", "content"),
        ("reputation", "IOC reputation"),
        ("infrastructure", "infrastructure"),
    )
    reasons = []
    for key, label in categories:
        component = risk_score.get(key) or {}
        if not component.get("score"):
            continue
        signals = [str(signal).casefold() for signal in component.get("signals", [])]
        if key == "authentication" and any("fail" in signal for signal in signals):
            label = "authentication failures"
        elif key == "content":
            label = "high-risk content patterns"
        elif key == "reputation":
            label = "IOC reputation evidence"
        elif key == "infrastructure":
            label = "infrastructure evidence"
        reasons.append(label)

    if not reasons:
        return "No scored evidence triggered additional risk points."
    if len(reasons) == 1:
        reason_text = reasons[0]
    elif len(reasons) == 2:
        reason_text = f"{reasons[0]} and {reasons[1]}"
    else:
        reason_text = f"{', '.join(reasons[:-1])}, and {reasons[-1]}"
    return f"Investigation triggered by: {reason_text}."


def build_risk_presentation(
    risk_score: dict[str, Any],
    verdict: str,
    evidence_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    coverage = evidence_coverage or risk_score.get("evidence_coverage") or {}
    total = risk_score.get("total", 0)
    return {
        "verdict": verdict,
        "risk_score": f"{total} / 100",
        "risk_band": risk_score.get("level", "Not available"),
        "evidence_coverage": (
            f"{coverage['percentage']:.0f}%"
            if isinstance(coverage.get("percentage"), (int, float))
            else "Not available"
        ),
        "explanation": format_investigation_explanation(risk_score),
        "risk_flow": RISK_FLOW,
        "risk_flow_display": RISK_FLOW_TEXT,
        "ai_interpretation": AI_INTERPRETATION,
    }
