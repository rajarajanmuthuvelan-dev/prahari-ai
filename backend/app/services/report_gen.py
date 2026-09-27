import json
from datetime import datetime
from .ioc_reputation import normalize_ioc_reputation
from .risk_presentation import AI_INTERPRETATION, build_risk_presentation


def _ai_evidence(case: dict) -> dict:
    risk = case["risk_score"]
    ai_analysis = case.get("ai_analysis") or risk.get("ai_analysis") or {}
    auth = case.get("auth") or {}
    iocs = case.get("iocs") or []
    return {
        "models": [
            {
                "name": model.get("name"),
                "model_id": model.get("model_id"),
                "status": model.get("status"),
                "class_mapping": model.get("class_mapping", {}),
                "benign_probability": model.get("benign_probability"),
                "phishing_probability": model.get("phishing_probability"),
                "predicted_label": model.get("predicted_label"),
                "predicted_class": model.get("predicted_class"),
                "error": model.get("error"),
            }
            for model in ai_analysis.get("models", [])
        ],
        "combined_ai_signal": ai_analysis.get("combined_ai_signal"),
        "interpretation": AI_INTERPRETATION,
        "authentication": {
            "spf": auth.get("spf"),
            "dkim": auth.get("dkim"),
            "dmarc": auth.get("dmarc"),
            "summary": auth.get("summary"),
            "evidence": [
                value for value in (
                    auth.get("spf_detail"),
                    auth.get("dkim_detail"),
                    auth.get("dmarc_detail"),
                ) if value
            ],
            "risk_score": risk.get("authentication", {}).get("score"),
            "signals": risk.get("authentication", {}).get("signals", []),
        },
        "ioc_reputation": {
            "risk_score": risk.get("reputation", {}).get("score"),
            "signals": risk.get("reputation", {}).get("signals", []),
            "lookups": [
                {
                    "type": ioc.get("type"),
                    "value": ioc.get("value"),
                    "status": ioc.get("lookup_status")
                    or (ioc.get("intelligence") or {}).get("lookup_status"),
                    "reputation_status": ioc.get("reputation_status", "UNKNOWN"),
                    "risk_contribution": ioc.get("risk_contribution", 0),
                    "reputation": (ioc.get("intelligence") or {}).get("reputation"),
                    "provider": (ioc.get("intelligence") or {}).get("provider"),
                    "lookup_source": ioc.get("lookup_source", "No reputation result"),
                    "geo_source": ioc.get("geo_source"),
                }
                for ioc in iocs if ioc.get("valid")
            ],
        },
        "infrastructure": {
            "risk_score": risk.get("infrastructure", {}).get("score"),
            "signals": risk.get("infrastructure", {}).get("signals", []),
        },
        "final_risk": {
            "total": risk.get("total"),
            "level": risk.get("level"),
            "verdict": case.get("verdict"),
            "explanation": risk.get("explanation"),
        },
    }


def generate_json_report(case: dict) -> bytes:
    ai_analysis = case.get("ai_analysis") or case["risk_score"].get("ai_analysis")
    iocs = [normalize_ioc_reputation(ioc) for ioc in case.get("iocs", [])]
    normalized_case = {**case, "iocs": iocs}
    risk_presentation = build_risk_presentation(
        case["risk_score"],
        case["verdict"],
        case["risk_score"].get("evidence_coverage"),
    )
    risk_score = {
        **case["risk_score"],
        "explanation": risk_presentation["explanation"],
        "presentation": risk_presentation,
    }
    normalized_case["risk_score"] = risk_score
    report = {
        "report_type": "PRAHARI AI Forensic Investigation Report",
        "report_version": "1.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "disclaimer": "This report is generated for analytical and investigative purposes only. It does not constitute legal evidence or certification.",
        "is_demo": case.get("is_demo", False),
        "case": {
            "id": case["id"],
            "threat_type": case.get("threat_type"),
            "created_at": case["created_at"],
            "severity": case["severity"],
            "verdict": case["verdict"],
            "evidence_coverage": case["risk_score"].get("evidence_coverage"),
        },
        "threat_type": case.get("threat_type"),
        "threat_type_interpretation": (
            "Investigative classification based on available evidence; not a certainty."
        ),
        "risk_score": risk_score,
        "risk_presentation": risk_presentation,
        "evidence_coverage": risk_score.get("evidence_coverage"),
        "ai_analysis": ai_analysis,
        "ai_evidence": _ai_evidence(normalized_case),
        "authentication": case["auth"],
        "iocs": iocs,
        "mitre_mappings": case["mitre_mappings"],
        "timeline": case["timeline"],
        "why_flagged": case["why_flagged"],
        "summary": case["summary"],
    }
    return json.dumps(report, indent=2, default=str).encode("utf-8")


def generate_html_report(case: dict) -> str:
    rs = case["risk_score"]
    auth = case["auth"]
    risk_color = "#dc2626" if rs["level"] in ("CRITICAL", "HIGH") else ("#d97706" if rs["level"] == "MEDIUM" else "#059669")

    def badge(s: str) -> str:
        color = "#059669" if s == "PASS" else ("#dc2626" if s == "FAIL" else "#94a3b8")
        return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">{s}</span>'

    ioc_rows = "".join(
        f"<tr><td>{i['type']}</td><td>{i['value'][:80]}</td><td>{i['source']}</td><td>{i['risk']}</td><td>{i['status']}</td></tr>"
        for i in case["iocs"]
    )
    mitre_html = "".join(
        f'<div class="mit"><div style="display:flex;gap:8px;align-items:center;margin-bottom:4px"><span class="mit-id">{m["technique_id"]}</span><span style="font-size:11px;font-weight:600">{m["technique_name"]}</span><span style="font-size:9px;background:#e0e7ff;color:#3730a3;padding:1px 6px;border-radius:4px">{m["tactic"]}</span></div><div style="font-size:10px;color:#374151">{m["description"]}</div><div style="font-size:9px;color:#64748b;margin-top:4px">Evidence: {" | ".join(m["evidence"])}</div></div>'
        for m in case["mitre_mappings"]
    )
    timeline_html = "".join(
        f'<div class="tl"><div class="ts">{e["timestamp"]}</div><div style="font-weight:600;font-size:11px">{e["event"]}</div><div style="color:#64748b;font-size:10px">{e["detail"]}</div></div>'
        for e in case["timeline"]
    )
    why_flagged_html = "".join(f"<div>• {r}</div>" for r in case["why_flagged"])

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>PRAHARI AI — {case['id']}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:Inter,sans-serif;color:#0f172a;font-size:11px;line-height:1.6}}
.hd{{background:#0f172a;color:white;padding:40px}}.hd h1{{font-size:22px;font-weight:700}}
.sec{{padding:20px 40px;border-bottom:1px solid #e2e8f0}}.sec h2{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:12px}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}.f label{{font-size:9px;text-transform:uppercase;letter-spacing:.5px;color:#94a3b8;font-weight:600;display:block}}.f span{{font-family:'JetBrains Mono',monospace;font-size:10px}}
.score-box{{text-align:center;padding:20px;background:#fef2f2;border-radius:8px;margin-bottom:12px}}.score-box .n{{font-size:40px;font-weight:700;color:{risk_color}}}.score-box .l{{font-size:14px;font-weight:600;color:{risk_color}}}
table{{width:100%;border-collapse:collapse;font-size:10px}}th{{background:#f8fafc;font-weight:600;text-transform:uppercase;font-size:9px;padding:6px 10px;text-align:left;border:1px solid #e2e8f0}}td{{padding:6px 10px;border:1px solid #e2e8f0;font-family:'JetBrains Mono',monospace;word-break:break-all}}
.mit{{margin-bottom:12px;padding:10px;background:#f8fafc;border-radius:4px;border-left:3px solid #3b82f6}}.mit-id{{font-family:'JetBrains Mono',monospace;color:#3b82f6;font-size:10px}}
.tl{{padding:6px 0;border-bottom:1px solid #f1f5f9}}.ts{{font-family:'JetBrains Mono',monospace;font-size:9px;color:#94a3b8}}
.ft{{padding:16px 40px;text-align:center;color:#94a3b8;font-size:9px}}
</style></head><body>
<div class="hd">
<div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#3b82f6;margin-bottom:6px">PRAHARI AI</div>
<h1>Forensic Investigation Report</h1>
<div style="color:#94a3b8;margin-top:4px;font-size:11px">Email Threat Detection &amp; Forensic Intelligence Platform</div>
<div style="font-family:'JetBrains Mono',monospace;color:#60a5fa;font-size:14px;margin-top:20px">CASE ID: {case['id']}</div>
<div style="font-family:'JetBrains Mono',monospace;color:#94a3b8;font-size:11px;margin-top:6px">THREAT TYPE: {case.get('threat_type') or 'Suspicious'}</div>
<div style="margin-top:12px;color:#94a3b8;font-size:11px">Generated: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S UTC')} &nbsp;|&nbsp; Verdict: <span style="color:{risk_color};font-weight:700">{case['verdict']}</span> &nbsp;|&nbsp; Risk: <span style="color:{risk_color};font-weight:700">{rs['total']}/100</span> &nbsp;|&nbsp; Evidence coverage: {rs['confidence']:.0f}%</div>
<div style="margin-top:4px;color:#94a3b8;font-size:10px">{(rs.get('evidence_coverage') or {}).get('summary', 'Evidence coverage details unavailable.')}</div>
<div style="color:#64748b;font-size:9px;margin-top:16px;padding-top:16px;border-top:1px solid #1e293b">FORENSIC INVESTIGATION REPORT — For analytical purposes only. Does not constitute legal evidence or certification.</div>
</div>
<div class="sec"><h2>Email Summary</h2>
<div class="g2">
<div><div class="f"><label>From</label><span>{case.get('from_addr','')}</span></div><div class="f"><label>To</label><span>{case.get('to_addr','')}</span></div><div class="f"><label>Subject</label><span style="font-family:Inter,sans-serif">{case.get('subject','')}</span></div></div>
<div><div class="f"><label>Date</label><span>{case.get('date','')}</span></div><div class="f"><label>Reply-To</label><span>{case.get('reply_to') or 'Not set'}</span></div></div>
</div></div>
<div class="sec"><h2>Risk Assessment</h2>
<div class="score-box"><div class="n">{rs['total']}</div><div style="font-size:10px;color:#64748b">out of 100</div><div class="l">{rs['level']} RISK</div></div>
<div style="font-size:11px;color:#374151;background:#f8fafc;padding:10px;border-radius:4px;margin-bottom:12px">{rs['explanation']}</div>
<table><tr><th>Category</th><th>Score</th><th>Max</th><th>Top Signal</th></tr>
<tr><td>Content</td><td>{rs['content']['score']}</td><td>25</td><td style="font-family:Inter,sans-serif">{rs['content']['signals'][0] if rs['content']['signals'] else '—'}</td></tr>
<tr><td>Authentication</td><td>{rs['authentication']['score']}</td><td>20</td><td style="font-family:Inter,sans-serif">{rs['authentication']['signals'][0] if rs['authentication']['signals'] else '—'}</td></tr>
<tr><td>Reputation</td><td>{rs['reputation']['score']}</td><td>25</td><td style="font-family:Inter,sans-serif">{rs['reputation']['signals'][0] if rs['reputation']['signals'] else '—'}</td></tr>
<tr><td>Infrastructure</td><td>{rs['infrastructure']['score']}</td><td>30</td><td style="font-family:Inter,sans-serif">{rs['infrastructure']['signals'][0] if rs['infrastructure']['signals'] else '—'}</td></tr>
</table></div>
<div class="sec"><h2>Authentication</h2>
<div style="display:flex;gap:16px;margin-bottom:10px">
<div style="text-align:center"><div style="font-size:9px;color:#94a3b8">SPF</div><div style="margin-top:4px">{badge(auth['spf'])}</div></div>
<div style="text-align:center"><div style="font-size:9px;color:#94a3b8">DKIM</div><div style="margin-top:4px">{badge(auth['dkim'])}</div></div>
<div style="text-align:center"><div style="font-size:9px;color:#94a3b8">DMARC</div><div style="margin-top:4px">{badge(auth['dmarc'])}</div></div>
</div><div style="font-size:11px;color:#374151">{auth['summary']}</div></div>
<div class="sec"><h2>IOCs ({len(case['iocs'])})</h2>
<table><tr><th>Type</th><th>Indicator</th><th>Source</th><th>Risk</th><th>Status</th></tr>{ioc_rows}</table></div>
<div class="sec"><h2>MITRE ATT&amp;CK</h2>{mitre_html}</div>
<div class="sec"><h2>Timeline</h2>{timeline_html}</div>
<div class="sec"><h2>Why Flagged</h2>{why_flagged_html}</div>
<div class="ft"><strong>PRAHARI AI</strong> — Email Threat Detection &amp; Forensic Intelligence Platform<br>Not legally certified · For analytical use only</div>
</body></html>"""
