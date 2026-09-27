import re
from datetime import datetime, timezone
from .threat_classifier import classify_threat_type


def _graph_layout(iocs: list[dict], subject: str) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    nodes.append({"id": "email", "type": "EMAIL", "label": "Email", "detail": subject[:50], "x": 420, "y": 90})

    ip_idx = dom_idx = url_idx = email_idx = 0
    valid_iocs = [ioc for ioc in iocs if ioc.get("valid") is True]
    displayed_iocs = valid_iocs[:9]
    for ioc in displayed_iocs:
        nid = f"n-{ioc['id']}"
        if ioc["type"] == "IP":
            x, y = 580 + ip_idx * 60, 240 + ip_idx * 80
            geo = (ioc.get("intelligence") or {}).get("geo") or {}
            nodes.append({"id": nid, "type": "IP", "label": ioc["value"], "detail": geo.get("network_type") or "IP Address", "risk": ioc.get("risk"), "x": x, "y": y})
            source = ioc.get("source", "")
            edge_label = (
                "received via"
                if "received" in source.lower()
                else "originating IP"
                if "originating" in source.lower()
                else "contains IP"
            )
            edges.append({"id": f"e-em-{nid}", "source": "email", "target": nid, "label": edge_label})
            geo = (ioc.get("intelligence") or {}).get("geo")
            if geo:
                gid = f"geo-{ioc['id']}"
                nodes.append({"id": gid, "type": "GEO", "label": geo.get("country", ""), "detail": geo.get("asn_name", ""), "risk": "LOW", "x": x + 130, "y": y + 70})
                edges.append({"id": f"e-{nid}-{gid}", "source": nid, "target": gid, "label": "geo"})
            ip_idx += 1
        elif ioc["type"] == "DOMAIN":
            x, y = 200 + dom_idx * 30, 240 + dom_idx * 80
            label = ioc["value"][:28] + ("…" if len(ioc["value"]) > 28 else "")
            nodes.append({"id": nid, "type": "DOMAIN", "label": label, "detail": ioc.get("source", ""), "risk": ioc.get("risk"), "x": x, "y": y})
            source = ioc.get("source", "")
            edge_label = source.replace(" Header", "").replace("Email Body", "contains")
            edges.append({"id": f"e-em-{nid}", "source": "email", "target": nid, "label": edge_label or "domain"})
            dom_idx += 1
        elif ioc["type"] == "URL" and url_idx < 2:
            x, y = 410, 240 + url_idx * 90
            label = ioc["value"][:36] + ("…" if len(ioc["value"]) > 36 else "")
            nodes.append({"id": nid, "type": "URL", "label": label, "detail": "Email Body URL", "risk": ioc.get("risk"), "x": x, "y": y})
            edges.append({"id": f"e-em-{nid}", "source": "email", "target": nid, "label": "contains"})
            url_idx += 1
        elif ioc["type"] == "EMAIL":
            x, y = 650 + email_idx * 30, 240 + email_idx * 80
            nodes.append({"id": nid, "type": "EMAIL", "label": ioc["value"], "detail": ioc.get("source", ""), "risk": ioc.get("risk"), "x": x, "y": y})
            source = ioc.get("source", "").lower()
            edge_label = (
                "reply-to"
                if "reply-to" in source
                else "recipient"
                if "to header" in source
                else "sender"
                if "from header" in source
                else "contains"
            )
            edges.append({"id": f"e-em-{nid}", "source": "email", "target": nid, "label": edge_label})
            email_idx += 1

    malicious_iocs = [
        ioc for ioc in displayed_iocs
        if ioc.get("status") == "MALICIOUS"
        and (ioc.get("intelligence") or {}).get("lookup_status") == "FOUND"
    ]
    if malicious_iocs:
        nodes.append({"id": "rep", "type": "REPUTATION", "label": "MALICIOUS", "detail": "Threat Intelligence", "risk": "CRITICAL", "x": 580, "y": 500})
        for ioc in malicious_iocs:
            node_id = f"n-{ioc['id']}"
            if any(node["id"] == node_id for node in nodes):
                edges.append({"id": f"e-rep-{ioc['id']}", "source": node_id, "target": "rep", "label": "reputation"})

    return nodes, edges


def build_case(case_id: str, parsed: dict, auth: dict, iocs: list[dict], risk_score: dict, mitre_mappings: list[dict]) -> dict:
    now = datetime.now(timezone.utc).isoformat()

    total = risk_score["total"]
    if total >= 80:
        verdict = "MALICIOUS"
    elif total >= 55:
        verdict = "SUSPICIOUS"
    elif total >= 35:
        verdict = "INVESTIGATING"
    elif total >= 15:
        verdict = "LIKELY_CLEAN"
    else:
        verdict = "CLEAN"

    threat_type = classify_threat_type(
        parsed,
        auth,
        iocs,
        risk_score.get("ai_analysis"),
        risk_score,
        mitre_mappings,
    )

    timeline = [
        {"id": "tl-submit", "timestamp": now, "event": "Email Submitted to PRAHARI AI", "detail": f"EML file uploaded. From: {parsed['from_addr'][:60]}", "type": "info"},
        {"id": "tl-parse", "timestamp": now, "event": "Email Parsed", "detail": f"{len(parsed['headers'])} headers, {len(parsed['received_ips'])} IP(s), {len(parsed['urls'])} URL(s), {len(parsed['attachments'])} attachment(s).", "type": "success"},
        {"id": "tl-auth", "timestamp": now, "event": "Authentication Analysis", "detail": f"SPF: {auth['spf']} | DKIM: {auth['dkim']} | DMARC: {auth['dmarc']}", "type": "critical" if auth["spf"] == "FAIL" or auth["dkim"] == "FAIL" else "info" if all(auth[key] == "NOT_AVAILABLE" for key in ("spf", "dkim", "dmarc")) else "success"},
        {"id": "tl-ioc", "timestamp": now, "event": "IOC Extraction & Enrichment", "detail": f"{len(iocs)} IOC(s) extracted. {sum(1 for i in iocs if i.get('status') == 'MALICIOUS')} confirmed malicious.", "type": "critical" if any(i.get("risk") == "CRITICAL" for i in iocs) else "warning"},
        {"id": "tl-geo", "timestamp": now, "event": "Geographic & Network Context", "detail": next((f"Geo context: {i['intelligence']['geo']['country']} / {i['intelligence']['geo']['asn_name']} [Source: {i['intelligence']['geo']['source']}]" for i in iocs if (i.get("intelligence") or {}).get("geo")), "No geo context available for observed IPs"), "type": "info"},
        {"id": "tl-score", "timestamp": now, "event": "Risk Assessment Complete", "detail": f"Score: {total}/100 ({risk_score['level']}). {risk_score['evidence_coverage']['summary']} {len(mitre_mappings)} MITRE technique(s). Verdict: {verdict}.", "type": "critical" if total >= 60 else "info"},
    ]

    graph_nodes, graph_edges = _graph_layout(iocs, parsed.get("subject", ""))

    why_flagged = (
        risk_score["content"]["signals"][:2]
        + [s for s in risk_score["authentication"]["signals"] if "FAIL" in s][:2]
        + (risk_score["reputation"]["signals"][:2] if risk_score["reputation"]["score"] > 0 else [])
        + risk_score["infrastructure"]["signals"][:2]
    )

    return {
        "id": case_id,
        "threat_type": threat_type,
        "created_at": now,
        "severity": risk_score["level"],
        "verdict": verdict,
        "is_demo": False,
        "risk_score": risk_score,
        "ai_analysis": risk_score.get("ai_analysis"),
        "auth": auth,
        "email": {
            "from_addr": parsed["from_addr"],
            "to_addr": parsed["to_addr"],
            "subject": parsed["subject"],
            "date": parsed["date"],
            "reply_to": parsed.get("reply_to"),
            "message_id": parsed.get("message_id"),
            "received_ips": parsed["received_ips"],
            "received_path": parsed.get("received_headers", []),
            "urls": parsed["urls"],
            "email_addresses": parsed["email_addresses"],
            "headers": parsed["headers"],
            "attachments": parsed["attachments"],
            "body_text": parsed["body_text"][:50000],
        },
        "iocs": iocs,
        "mitre_mappings": mitre_mappings,
        "timeline": timeline,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "why_flagged": [r for r in why_flagged if r],
        "summary": f"{case_id}: {verdict} email. Threat type: {threat_type} (investigative classification based on available evidence). Risk score {total}/100 ({risk_score['level']}). {len(iocs)} IOC(s), {len(mitre_mappings)} MITRE technique(s). {risk_score['evidence_coverage']['summary']}",
        "evidence_count": len(iocs) + len(mitre_mappings),
    }
