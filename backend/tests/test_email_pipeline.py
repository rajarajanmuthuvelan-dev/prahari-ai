import ipaddress
import asyncio
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from app.services.auth_checker import analyze_auth
from app.services.email_parser import parse_eml
from app.services.ioc_extractor import extract_iocs
from app.services.ioc_normalizer import normalize_ioc
from app.services.ioc_reputation import normalize_ioc_reputation
from app.services.evidence_coverage import calculate_evidence_coverage
from app.services.risk_presentation import build_risk_presentation
from app.services.threat_classifier import classify_threat_type
from app.services.risk_engine import (
    _score_auth,
    _score_infrastructure,
    _score_reputation,
    compute_risk_score,
)
from app.services.geo_service import (
    _ipwhois_lookup,
    _merge_provider_results,
    enrich_geo,
    lookup_ip,
)
from app.services.threat_intel import enrich_ioc
from app.services.mitre_mapper import map_mitre
from app.routers.cases import _normalize_geo_context
from app.schemas import CaseOut, IOCIntelligence as IOCIntelligenceSchema
from app.services.case_builder import build_case
from app.services.nlp_service import (
    AIAnalysisService,
    RuleBasedClassifier,
    TransformerRunner,
    analyze_content,
    _token_chunks,
)
from app.config import settings
from app.services.report_gen import generate_json_report
from app.services.threat_intel import enrich_iocs


EML = b"""From: Sender <sender@example.com>
To: Recipient <recipient@example.net>
Subject: Header and IOC validation
Date: Sat, 26 Sep 2026 08:30:00 +0000
Reply-To: reply@different.example
Message-ID: <message-1@example.com>
Received: from relay.example.net ([2001:4860:4860::8888]) by mx.example.net with ESMTP; Sat, 26 Sep 2026 08:29:00 +0000
Received: from source.example.net (203.0.113.25) by relay.example.net with ESMTP; Sat, 26 Sep 2026 08:28:00 +0000
Received: from clock.example (12:04:13) by mx.example.net with ESMTP; Sat, 26 Sep 2026 08:27:00 +0000
X-Originating-IP: [8.8.8.8]
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=sender@example.com; dkim=pass header.d=example.com; dmarc=fail header.from=example.com
Content-Type: text/plain; charset=utf-8

Visit https://EXAMPLE.com/path?Token=CaseSensitive.
Other tokens: 12:04:13 09.04.12.04 2026.08.30 999.2.3.4 8.8.8.8
"""

CLEAN_EML = (Path(__file__).parent / "fixtures" / "controlled-clean.eml").read_bytes()
CONTROLLED_PHISHING_EML = (
    Path(__file__).parent / "fixtures" / "controlled-phishing-bec.eml"
).read_bytes()


class EmailPipelineTests(unittest.TestCase):
    @staticmethod
    def classify_test_email(
        subject="",
        body="",
        sender="",
        attachments=None,
        urls=None,
        auth=None,
        iocs=None,
        ai=None,
        signals=None,
    ):
        parsed = {
            "subject": subject,
            "body_text": body,
            "body_html": "",
            "from_addr": sender,
            "urls": urls or [],
            "attachments": attachments or [],
        }
        risk_signals = {
            "content": {"signals": signals or []},
            "authentication": {"signals": []},
            "reputation": {"signals": []},
            "infrastructure": {"signals": []},
        }
        return classify_threat_type(
            parsed,
            auth or {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"},
            iocs or [],
            ai or {},
            risk_signals,
            [],
        )

    def test_threat_type_classifies_phishing_email_from_content_and_ai(self):
        result = self.classify_test_email(
            subject="Verify your account immediately",
            body="Confirm your password and sign in now to restore account access.",
            urls=["https://example.org/login"],
            ai={
                "models": [
                    {"name": "BERT", "status": "AVAILABLE", "phishing_probability": 0.91},
                    {"name": "RoBERTa", "status": "AVAILABLE", "phishing_probability": 0.88},
                ],
                "combined_ai_signal": {"phishing_probability": 0.895},
            },
        )
        self.assertEqual(result, "Phishing")

    def test_threat_type_classifies_bec_from_payment_and_impersonation_evidence(self):
        result = self.classify_test_email(
            subject="Urgent wire transfer",
            body="I am the CFO. Please send the wire transfer to the new bank account immediately.",
            sender="Finance Executive <executive@external-mail.example>",
            signals=["Sender impersonation indicator"],
        )
        self.assertEqual(result, "Business Email Compromise")

    def test_threat_type_classifies_dominant_sender_impersonation(self):
        result = self.classify_test_email(
            subject="Microsoft account notice",
            body="A monthly update is available for your organization.",
            sender="Microsoft Support <support@gmail.com>",
        )
        self.assertEqual(result, "Impersonation")

    def test_threat_type_classifies_suspicious_attachment(self):
        result = self.classify_test_email(
            subject="Requested document",
            body="Please review the attached file.",
            attachments=[{
                "filename": "invoice.docm",
                "content_type": "application/vnd.ms-word.document.macroEnabled.12",
            }],
        )
        self.assertEqual(result, "Malware / Suspicious Attachment")

    def test_threat_type_classifies_ordinary_legitimate_email_as_clean(self):
        result = self.classify_test_email(
            subject="Meeting agenda",
            body="Hello, the meeting is scheduled for tomorrow at 10 AM.",
            sender="Colleague <colleague@example.org>",
        )
        self.assertEqual(result, "Clean")

    def test_case_builder_preserves_canonical_id_and_sets_threat_type(self):
        parsed = {
            "from_addr": "sender@example.com",
            "to_addr": "recipient@example.net",
            "subject": "Account notice",
            "date": "",
            "received_ips": [],
            "received_headers": [],
            "urls": [],
            "email_addresses": [],
            "headers": [],
            "attachments": [],
            "body_text": "",
        }
        auth = {"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"}
        risk_score = {
            "total": 36,
            "level": "LOW",
            "confidence": 80,
            "evidence_coverage": {"summary": "Evidence coverage: 80%."},
            "content": {"score": 16, "signals": ["Credential harvesting language"]},
            "authentication": {"score": 20, "signals": ["SPF FAIL"]},
            "reputation": {"score": 0, "signals": []},
            "infrastructure": {"score": 0, "signals": []},
        }
        case_id = "PRH-2026-EML-0927-0003"

        case = build_case(
            case_id,
            parsed,
            auth,
            [],
            risk_score,
            [{"technique_id": "T1566.002"}],
        )

        self.assertEqual(case["id"], case_id)
        self.assertEqual(case["threat_type"], "Phishing")
        self.assertEqual(case["risk_score"]["total"], 36)

    def test_risk_presentation_changes_wording_without_changing_score(self):
        risk_score = {
            "total": 36,
            "level": "LOW",
            "content": {"score": 16, "signals": ["Credential harvesting patterns"]},
            "authentication": {"score": 20, "signals": ["SPF FAIL", "DKIM FAIL"]},
            "reputation": {"score": 0, "signals": []},
            "infrastructure": {"score": 0, "signals": []},
            "evidence_coverage": {"percentage": 81.8},
        }

        presentation = build_risk_presentation(
            risk_score,
            "INVESTIGATING",
        )

        self.assertEqual(risk_score["total"], 36)
        self.assertEqual(presentation["verdict"], "INVESTIGATING")
        self.assertEqual(presentation["risk_score"], "36 / 100")
        self.assertEqual(presentation["risk_band"], "LOW")
        self.assertEqual(presentation["evidence_coverage"], "82%")
        self.assertEqual(
            presentation["explanation"],
            "Investigation triggered by: authentication failures and high-risk content patterns.",
        )
        report_case = {
            "id": "PRH-PRESENTATION",
            "created_at": "2026-09-27T00:00:00Z",
            "severity": "LOW",
            "verdict": "INVESTIGATING",
            "risk_score": risk_score,
            "auth": {},
            "iocs": [],
            "mitre_mappings": [],
            "timeline": [],
            "why_flagged": [],
            "summary": "",
        }
        report = json.loads(generate_json_report(report_case))
        self.assertEqual(report["risk_score"]["total"], 36)
        self.assertEqual(
            report["risk_presentation"]["explanation"],
            presentation["explanation"],
        )
        self.assertEqual(report["risk_presentation"]["evidence_coverage"], "82%")
        self.assertEqual(
            report["risk_presentation"]["risk_flow"],
            ["AI Content", "Authentication", "IOC Reputation", "Infrastructure",
             "Multi-Signal Risk Engine", "Risk Score + Verdict"],
        )

    def test_evidence_coverage_uses_applicable_pipeline_categories(self):
        parsed = {
            "headers": [{"name": "From", "value": "a@example.com"}],
            "body_text": "Message",
            "attachments": [],
            "urls": ["https://example.org/path"],
        }
        auth = {"spf": "PASS", "dkim": "NOT_AVAILABLE", "dmarc": "FAIL"}
        iocs = [
            {
                "type": "IP",
                "value": "69.169.232.61",
                "normalized_value": "69.169.232.61",
                "valid": True,
                "intelligence": {
                    "lookup_status": "FOUND",
                    "reputation": 0,
                    "geo": {
                        "country": "United States",
                        "asn": "AS16509",
                        "isp": "Amazon",
                        "reverse_dns": "mail.example.net",
                        "provider_results": {"DNS_PTR": {"status": "FOUND"}},
                    },
                },
            },
            {
                "type": "URL",
                "value": "https://example.org/path",
                "normalized_value": "https://example.org/path",
                "valid": True,
                "intelligence": {"lookup_status": "UNAVAILABLE"},
            },
        ]
        ai = {
            "models": [
                {"name": "BERT", "status": "AVAILABLE"},
                {"name": "RoBERTa", "status": "UNAVAILABLE"},
            ]
        }

        coverage = calculate_evidence_coverage(parsed, auth, iocs, ai)
        self.assertEqual(coverage["categories"]["email_parsing"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["header_extraction"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["spf"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["dkim"]["status"], "UNAVAILABLE")
        self.assertEqual(coverage["categories"]["dmarc"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["bert"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["roberta"]["status"], "UNAVAILABLE")
        self.assertEqual(coverage["categories"]["ioc_extraction"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["threat_intelligence"]["status"], "PARTIAL")
        self.assertEqual(coverage["categories"]["geoip"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["asn_isp"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["reverse_dns"]["status"], "AVAILABLE")
        self.assertEqual(coverage["categories"]["infrastructure"]["status"], "UNAVAILABLE")
        self.assertEqual(coverage["categories"]["attachments"]["status"], "NOT_APPLICABLE")
        self.assertEqual(coverage["categories"]["url_analysis"]["status"], "AVAILABLE")
        self.assertEqual(
            coverage["percentage"],
            round(100 * (coverage["available_count"] + coverage["partial_count"] / 2)
                  / coverage["applicable_count"], 1),
        )

    def test_evidence_coverage_varies_with_pipeline_availability_not_risk(self):
        parsed = {
            "headers": [{"name": "Subject", "value": "Urgent action required"}],
            "body_text": "Urgent action required",
            "attachments": [],
            "urls": [],
        }
        auth = {"spf": "NOT_AVAILABLE", "dkim": "NOT_AVAILABLE", "dmarc": "NOT_AVAILABLE"}
        unavailable_ai = {
            "models": [
                {"name": "BERT", "status": "UNAVAILABLE"},
                {"name": "RoBERTa", "status": "UNAVAILABLE"},
            ]
        }
        clean_ai = {
            "models": [
                {"name": "BERT", "status": "AVAILABLE"},
                {"name": "RoBERTa", "status": "AVAILABLE"},
            ]
        }

        low_coverage = calculate_evidence_coverage(parsed, auth, [], unavailable_ai)
        high_coverage = calculate_evidence_coverage(parsed, auth, [], clean_ai)

        self.assertLess(low_coverage["percentage"], high_coverage["percentage"])
        self.assertEqual(
            low_coverage["percentage"],
            calculate_evidence_coverage(parsed, auth, [], unavailable_ai)["percentage"],
        )
        self.assertEqual(
            low_coverage["categories"]["threat_intelligence"]["status"],
            "NOT_APPLICABLE",
        )
        self.assertEqual(low_coverage["categories"]["geoip"]["status"], "NOT_APPLICABLE")

    def test_evidence_coverage_keeps_asn_separate_from_geolocation(self):
        parsed = {
            "headers": [{"name": "From", "value": "a@example.com"}],
            "body_text": "",
            "attachments": [],
            "urls": [],
        }
        iocs = [{
            "type": "IP",
            "value": "69.169.232.61",
            "normalized_value": "69.169.232.61",
            "valid": True,
            "intelligence": {"geo": {"asn": "AS16509", "isp": "Amazon"}},
        }]

        coverage = calculate_evidence_coverage(
            parsed,
            {"spf": "NOT_AVAILABLE", "dkim": "NOT_AVAILABLE", "dmarc": "NOT_AVAILABLE"},
            iocs,
            {},
        )

        self.assertEqual(coverage["categories"]["geoip"]["status"], "UNAVAILABLE")
        self.assertEqual(coverage["categories"]["asn_isp"]["status"], "AVAILABLE")

    def test_attachment_metadata_without_scanning_is_partial_coverage(self):
        parsed = {
            "headers": [{"name": "From", "value": "a@example.com"}],
            "body_text": "",
            "attachments": [{"filename": "document.pdf"}],
            "urls": [],
        }

        coverage = calculate_evidence_coverage(
            parsed,
            {"spf": "NOT_AVAILABLE", "dkim": "NOT_AVAILABLE", "dmarc": "NOT_AVAILABLE"},
            [],
            {},
        )

        self.assertEqual(coverage["categories"]["attachments"]["status"], "PARTIAL")

    def test_parser_extracts_metadata_and_received_route_without_dates_as_ips(self):
        parsed = parse_eml(EML)

        self.assertEqual(parsed["from_addr"], "Sender <sender@example.com>")
        self.assertEqual(parsed["to_addr"], "Recipient <recipient@example.net>")
        self.assertEqual(parsed["subject"], "Header and IOC validation")
        self.assertTrue(parsed["date"])
        self.assertEqual(parsed["reply_to"], "reply@different.example")
        self.assertEqual(parsed["message_id"], "<message-1@example.com>")
        self.assertTrue(
            any(h["name"] == "Authentication-Results" for h in parsed["headers"])
        )
        self.assertEqual(parsed["received_headers"][0]["from_host"], "relay.example.net")
        self.assertEqual(parsed["received_headers"][0]["by_host"], "mx.example.net")
        self.assertEqual(
            parsed["received_headers"][0]["timestamp"],
            "2026-09-26T08:29:00+00:00",
        )
        self.assertIn("2001:4860:4860::8888", parsed["received_ips"])
        self.assertIn("203.0.113.25", parsed["received_ips"])
        self.assertNotIn("12:04:13", parsed["received_ips"])
        self.assertNotIn("09.04.12.04", parsed["received_ips"])
        self.assertNotIn("2026.08.30", parsed["received_ips"])
        self.assertEqual(parsed["urls"], ["https://EXAMPLE.com/path?Token=CaseSensitive"])
        self.assertIn("example.com", [d["value"].lower() for d in parsed["domains"]])

    def test_unfolded_received_header_does_not_hide_later_microsoft_headers(self):
        eml_path = (
            Path(__file__).parents[1]
            / "phish_mail"
            / "Microsoft Team.eml"
        )
        parsed = parse_eml(eml_path.read_bytes())
        auth = analyze_auth(parsed["headers"])

        self.assertIn("microsoftonline-verify.com", parsed["from_addr"])
        self.assertIn("Unusual sign-in activity", parsed["subject"])
        self.assertEqual((auth["spf"], auth["dkim"], auth["dmarc"]), ("FAIL", "FAIL", "FAIL"))
        self.assertIn("178.238.225.91", parsed["received_ips"])
        self.assertIn("secure your account immediately", parsed["body_text"].lower())
        mappings = map_mitre(parsed, auth, extract_iocs(parsed))
        self.assertIn("T1566.002", [item["technique_id"] for item in mappings])
        self.assertIn("T1036.005", [item["technique_id"] for item in mappings])

    def test_html_only_bhashini_message_provides_visible_text_for_analysis(self):
        eml_path = (
            Path(__file__).parents[1]
            / "phish_mail"
            / "One-Time Password (OTP) for Account Verification - BHASHINI.eml"
        )
        parsed = parse_eml(eml_path.read_bytes())

        self.assertIn("onboarding@bhashini.co.in", parsed["from_addr"])
        self.assertIn("One-Time Password", parsed["subject"])
        self.assertTrue(parsed["body_html"])
        self.assertTrue(parsed["body_text"])
        self.assertNotIn("<html", parsed["body_text"].lower())
        self.assertNotIn("OTP Email Template", parsed["body_text"])

    def test_all_ip_iocs_are_valid_and_deduplicated(self):
        parsed = parse_eml(EML)
        iocs = extract_iocs(parsed)
        ip_iocs = [ioc for ioc in iocs if ioc["type"] == "IP"]

        self.assertTrue(ip_iocs)
        for ioc in ip_iocs:
            self.assertTrue(ioc["valid"])
            self.assertEqual(str(ipaddress.ip_address(ioc["normalized_value"])), ioc["normalized_value"])
        self.assertEqual(
            len({ioc["normalized_value"] for ioc in ip_iocs}),
            len(ip_iocs),
        )
        self.assertFalse(
            any(value in ("12:04:13", "09.04.12.04", "2026.08.30") for value in (
                ioc["value"] for ioc in ip_iocs
            ))
        )

    def test_ioc_normalization_preserves_url_evidence(self):
        url = "HTTPS://Example.COM/A?Token=CaseSensitive"
        normalized = normalize_ioc("URL", url, "Email Body")

        self.assertTrue(normalized["valid"])
        self.assertEqual(normalized["value"], url)
        self.assertEqual(
            normalized["normalized_value"],
            "https://example.com/A?Token=CaseSensitive",
        )
        for invalid_ip in (
            "12:04:13",
            "09.04.12.04",
            "2026.08.30",
            "256.1.1.1",
            "1234",
        ):
            self.assertFalse(normalize_ioc("IP", invalid_ip, "Received Header")["valid"])

    def test_authentication_uses_header_results_and_reports_missing_as_unavailable(self):
        parsed = parse_eml(EML)
        auth = analyze_auth(parsed["headers"])
        missing = analyze_auth([])

        self.assertEqual((auth["spf"], auth["dkim"], auth["dmarc"]), ("PASS", "PASS", "FAIL"))
        self.assertNotIn("All authentication checks pass", auth["summary"])
        self.assertEqual(
            (missing["spf"], missing["dkim"], missing["dmarc"]),
            ("NOT_AVAILABLE", "NOT_AVAILABLE", "NOT_AVAILABLE"),
        )
        self.assertNotIn("pass", missing["summary"].lower())

    def test_unavailable_reputation_does_not_add_risk(self):
        component = _score_reputation(
            [
                {
                    "type": "IP",
                    "value": "8.8.8.8",
                    "valid": True,
                    "intelligence": {
                        "reputation": 98,
                        "lookup_status": "UNAVAILABLE",
                    },
                }
            ]
        )

        self.assertEqual(component["score"], 0)
        self.assertIn("no reputation risk points were assigned", component["signals"][0])

    def test_ioc_reputation_states_and_contributions_are_separate_from_lookup_status(self):
        cases = [
            (
                {
                    "lookup_status": "UNAVAILABLE",
                    "reputation": 98,
                    "provider": None,
                },
                "UNKNOWN",
                0,
                0,
            ),
            (
                {
                    "lookup_status": "FOUND",
                    "reputation": 97,
                    "reputation_status": "MALICIOUS",
                    "tags": ["Known malicious", "Phishing"],
                    "provider": "Local IOC Database",
                    "geo": {"country": "United States", "city": "Seattle", "source": "IPWHOIS"},
                },
                "MALICIOUS",
                8,
                8,
            ),
            (
                {
                    "lookup_status": "FOUND",
                    "reputation": 75,
                    "reputation_status": "SUSPICIOUS",
                    "tags": ["suspicious"],
                    "provider": "VirusTotal",
                },
                "SUSPICIOUS",
                5,
                5,
            ),
            (
                {
                    "lookup_status": "FOUND",
                    "reputation": 98,
                    "reputation_status": "CLEAN",
                    "provider": "AbuseIPDB",
                },
                "CLEAN",
                0,
                0,
            ),
            (
                {
                    "lookup_status": "FOUND",
                    "reputation": 98,
                    "reputation_status": "UNKNOWN",
                    "provider": "VirusTotal",
                },
                "UNKNOWN",
                0,
                0,
            ),
        ]

        for intelligence, expected_state, expected_contribution, expected_score in cases:
            with self.subTest(state=expected_state, intelligence=intelligence):
                normalized = normalize_ioc_reputation({
                    "type": "IP",
                    "value": "69.169.232.61",
                    "status": "UNKNOWN",
                    "risk": "UNKNOWN",
                    "intelligence": intelligence,
                })
                self.assertEqual(normalized["reputation_status"], expected_state)
                self.assertEqual(normalized["status"], expected_state)
                self.assertEqual(normalized["risk_contribution"], expected_contribution)
                self.assertEqual(
                    _score_reputation([{
                        "type": "IP",
                        "value": "69.169.232.61",
                        "valid": True,
                        "intelligence": intelligence,
                    }])["score"],
                    expected_score,
                )

        geo_preserved = normalize_ioc_reputation({
            "type": "IP",
            "value": "69.169.232.61",
            "intelligence": cases[1][0],
        })
        self.assertEqual(geo_preserved["intelligence"]["geo"]["source"], "IPWHOIS")
        self.assertEqual(geo_preserved["intelligence"]["geo"]["city"], "Seattle")
        self.assertEqual(geo_preserved["lookup_source"], "Local IOC Database")
        self.assertEqual(geo_preserved["geo_source"], "IPWHOIS")

        report = json.loads(generate_json_report({
            "id": "PRH-IOC-STATUS",
            "created_at": "2026-09-27T00:00:00Z",
            "severity": "CLEAN",
            "verdict": "CLEAN",
            "risk_score": {"confidence": 75, "total": 0, "level": "CLEAN"},
            "auth": {},
            "iocs": [
                {
                    "id": f"ioc-{index}",
                    "type": "IP",
                    "value": "69.169.232.61",
                    "valid": True,
                    **normalize_ioc_reputation({
                        "status": "UNKNOWN",
                        "risk": "UNKNOWN",
                        "intelligence": intelligence,
                    }),
                }
                for index, (intelligence, _, _, _) in enumerate(cases)
            ],
            "mitre_mappings": [],
            "timeline": [],
            "why_flagged": [],
            "summary": "",
        }))
        self.assertEqual(
            [ioc["reputation_status"] for ioc in report["iocs"]],
            [case[1] for case in cases],
        )
        self.assertEqual(
            [ioc["risk_contribution"] for ioc in report["iocs"]],
            [case[2] for case in cases],
        )
        self.assertEqual(
            normalize_ioc_reputation({
                "type": "DOMAIN",
                "value": "mx.google.com",
                "source": "Received Header (by-host)",
                "intelligence": {},
            })["evidence_category"],
            "Network/header infrastructure",
        )
        self.assertEqual(
            normalize_ioc_reputation({
                "type": "DOMAIN",
                "value": "header.from",
                "source": "ARC-Authentication-Results Header",
                "intelligence": {},
            })["evidence_category"],
            "Authentication artifact",
        )

    def test_url_presence_alone_does_not_add_infrastructure_risk(self):
        parsed = {"urls": ["https://example.com/news"]}
        iocs = [{
            "type": "URL",
            "value": "https://example.com/news",
            "valid": True,
            "intelligence": {"lookup_status": "UNAVAILABLE", "tags": []},
        }]

        component = _score_infrastructure(parsed, iocs)

        self.assertEqual(component["score"], 0)
        self.assertEqual(component["signals"], [])

    def test_authentication_breakdown_shows_points_per_mechanism(self):
        component = _score_auth({"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"})

        self.assertEqual(component["score"], 20)
        self.assertEqual(
            component["signals"],
            ["SPF: FAIL (+7 points)", "DKIM: FAIL (+7 points)", "DMARC: FAIL (+6 points)"],
        )

    def test_invalid_and_private_ips_are_rejected_before_enrichment(self):
        with self.assertRaises(ValueError):
            asyncio.run(enrich_ioc("IP", "12:04:13", allow_local_database=False))

        with (
            patch("app.services.threat_intel._cache_get", new_callable=AsyncMock, return_value=None),
            patch("app.services.threat_intel.httpx.AsyncClient") as client,
        ):
            result = asyncio.run(
                enrich_ioc("IP", "192.168.1.10", allow_local_database=False)
            )
        client.assert_not_called()
        self.assertEqual(result["lookup_status"], "UNAVAILABLE")
        self.assertIsNone(result["reputation"])

    def test_geoip_rejects_invalid_ip_without_provider_calls(self):
        with (
            patch("app.services.geo_service._maxmind_lookup") as maxmind,
            patch("app.services.geo_service._ip_api_lookup", new_callable=AsyncMock) as provider,
            patch("app.services.geo_service._ipwhois_lookup", new_callable=AsyncMock) as ipwhois,
            patch("app.services.geo_service._resolve_ptr") as ptr,
        ):
            result = asyncio.run(lookup_ip("09.04.12.04"))
        self.assertIsNone(result)
        maxmind.assert_not_called()
        provider.assert_not_called()
        ipwhois.assert_not_called()
        ptr.assert_not_called()

    def test_geoip_attempts_only_valid_public_ip_iocs(self):
        iocs = [
            {"type": "IP", "value": "8.8.8.8", "normalized_value": "8.8.8.8", "valid": True},
            {"type": "IP", "value": "192.168.1.10", "normalized_value": "192.168.1.10", "valid": True},
            {"type": "IP", "value": "12:04:13", "normalized_value": "12:04:13", "valid": False},
        ]
        with (
            patch("app.services.geo_service._maxmind_lookup", return_value=None) as maxmind,
            patch("app.services.geo_service._ip_api_lookup", new_callable=AsyncMock, return_value=None) as provider,
            patch("app.services.geo_service._ipwhois_lookup", new_callable=AsyncMock, return_value=None) as ipwhois,
            patch("app.services.geo_service._resolve_ptr", return_value={
                "source": "DNS_PTR", "provider": "System DNS PTR", "status": "NOT_FOUND",
                "checked_at": "2026-09-26T08:30:00+00:00", "hostname": None,
            }) as ptr,
        ):
            result = asyncio.run(enrich_geo(iocs))

        maxmind.assert_called_once_with("8.8.8.8")
        provider.assert_awaited_once_with("8.8.8.8")
        ipwhois.assert_awaited_once_with("8.8.8.8")
        ptr.assert_called_once_with("8.8.8.8")
        self.assertEqual(result[0]["intelligence"]["geo_status"], "NOT_FOUND")
        self.assertEqual(result[1]["intelligence"]["geo_status"], "UNAVAILABLE")
        self.assertNotIn("intelligence", result[2])

    def test_non_public_domains_are_not_sent_to_public_intelligence(self):
        with (
            patch("app.services.threat_intel._cache_get", new_callable=AsyncMock, return_value=None),
            patch("app.services.threat_intel.httpx.AsyncClient") as client,
        ):
            result = asyncio.run(
                enrich_ioc("DOMAIN", "mail.example", allow_local_database=False)
            )
        client.assert_not_called()
        self.assertEqual(result["lookup_status"], "UNAVAILABLE")
        self.assertIsNone(result["reputation"])
        self.assertIsNone(result["checked_at"])

    def test_reputation_provider_results_keep_status_confidence_and_time(self):
        found = {
            "source": "VIRUSTOTAL",
            "provider": "VirusTotal",
            "status": "FOUND",
            "checked_at": "2026-09-26T08:30:00+00:00",
            "confidence": 64,
            "reputation": 42,
            "tags": ["phishing"],
        }
        with (
            patch("app.services.threat_intel._cache_get", new_callable=AsyncMock, return_value=None),
            patch("app.services.threat_intel._cache_set", new_callable=AsyncMock),
            patch("app.services.threat_intel.local_lookup", return_value=None),
            patch("app.services.threat_intel.settings.virustotal_api_key", "configured"),
            patch("app.services.threat_intel.settings.abuseipdb_api_key", "configured"),
            patch(
                "app.services.threat_intel._provider_result",
                new_callable=AsyncMock,
                side_effect=[(found, None), (None, "TIMEOUT")],
            ),
        ):
            result = asyncio.run(
                enrich_ioc("IP", "8.8.8.8", allow_local_database=False)
            )

        self.assertEqual(result["status"], "FOUND")
        self.assertEqual(result["confidence"], 64)
        self.assertEqual(result["provider_results"]["VIRUSTOTAL"]["reputation"], 42)
        self.assertEqual(result["provider_results"]["ABUSEIPDB"]["status"], "TIMEOUT")
        self.assertEqual(
            result["provider_results"]["VIRUSTOTAL"]["checked_at"],
            found["checked_at"],
        )
        self.assertGreaterEqual(result["checked_at"], found["checked_at"])

    def test_not_found_and_unavailable_are_distinguished_without_fake_lookup_time(self):
        with (
            patch("app.services.threat_intel._cache_get", new_callable=AsyncMock, return_value=None),
            patch("app.services.threat_intel.local_lookup", return_value=None),
            patch("app.services.threat_intel.settings.virustotal_api_key", "configured"),
            patch("app.services.threat_intel.settings.abuseipdb_api_key", ""),
            patch(
                "app.services.threat_intel._provider_result",
                new_callable=AsyncMock,
                return_value=(None, None),
            ),
        ):
            not_found = asyncio.run(
                enrich_ioc("DOMAIN", "example.com", allow_local_database=False)
            )
        self.assertEqual(not_found["status"], "NOT_FOUND")
        self.assertEqual(not_found["provider_results"]["VIRUSTOTAL"]["status"], "NOT_FOUND")
        self.assertIsNotNone(not_found["checked_at"])

        with (
            patch("app.services.threat_intel._cache_get", new_callable=AsyncMock, return_value=None),
            patch("app.services.threat_intel.local_lookup", return_value=None),
            patch("app.services.threat_intel.settings.virustotal_api_key", ""),
            patch("app.services.threat_intel.settings.abuseipdb_api_key", ""),
        ):
            unavailable = asyncio.run(
                enrich_ioc("DOMAIN", "example.com", allow_local_database=False)
            )
        self.assertEqual(unavailable["status"], "UNAVAILABLE")
        self.assertIsNone(unavailable["checked_at"])

        with (
            patch("app.services.threat_intel._cache_get", new_callable=AsyncMock, return_value=None),
            patch("app.services.threat_intel.local_lookup", return_value=None),
            patch("app.services.threat_intel.settings.virustotal_api_key", "configured"),
            patch("app.services.threat_intel.settings.abuseipdb_api_key", ""),
            patch(
                "app.services.threat_intel._provider_result",
                new_callable=AsyncMock,
                return_value=(None, "ERROR"),
            ),
        ):
            errored = asyncio.run(
                enrich_ioc("DOMAIN", "example.com", allow_local_database=False)
            )
        self.assertEqual(errored["status"], "ERROR")
        self.assertEqual(errored["provider_results"]["VIRUSTOTAL"]["status"], "ERROR")

    def test_geoip_retains_provider_disagreement_and_checked_times(self):
        maxmind = {
            "country": "United States",
            "city": "Mountain View",
            "source": "MAXMIND",
            "provider": "MaxMind GeoIP",
            "status": "FOUND",
            "checked_at": "2026-09-26T08:30:00+00:00",
            "confidence": None,
        }
        ip_api = {
            "country": "United States",
            "city": "Chicago",
            "reverse_dns": "dns.google",
            "source": "IP_API",
            "provider": "IP-API",
            "status": "FOUND",
            "checked_at": "2026-09-26T08:30:01+00:00",
            "confidence": None,
        }
        with (
            patch("app.services.geo_service._maxmind_lookup", return_value=maxmind),
            patch("app.services.geo_service._ip_api_lookup", new_callable=AsyncMock, return_value=ip_api),
            patch("app.services.geo_service._ipwhois_lookup", new_callable=AsyncMock, return_value=None),
            patch("app.services.geo_service._resolve_ptr", return_value={
                "source": "DNS_PTR", "provider": "System DNS PTR", "status": "NOT_FOUND",
                "checked_at": "2026-09-26T08:30:02+00:00", "hostname": None,
            }),
        ):
            result = asyncio.run(lookup_ip("8.8.8.8"))

        self.assertEqual(result["status"], "FOUND")
        self.assertEqual(result["provider"], "MaxMind GeoIP, IP-API")
        self.assertGreaterEqual(result["checked_at"], ip_api["checked_at"])
        self.assertEqual(result["domain_hostname"], "dns.google")
        self.assertEqual(result["domain_hostname_source"], "IP_API")
        self.assertEqual(
            result["disagreements"]["city"],
            {"MAXMIND": "Mountain View", "IP_API": "Chicago"},
        )

    def test_ipwhois_geoip_result_exposes_actual_geo_and_network_data(self):
        provider = {
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "city": "San Francisco",
            "asn": "AS15169",
            "asn_name": "Google LLC",
            "isp": "Google LLC",
            "org": "Google LLC",
            "postal_code": "94119",
            "timezone": "America/Los_Angeles",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "source": "IPWHOIS",
            "provider": "ipwho.is",
            "status": "FOUND",
            "checked_at": "2026-09-26T08:30:00+00:00",
            "confidence": None,
        }
        with (
            patch("app.services.geo_service._maxmind_lookup", return_value=None),
            patch(
                "app.services.geo_service._ip_api_lookup",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "app.services.geo_service._ipwhois_lookup",
                new_callable=AsyncMock,
                return_value=provider,
            ),
            patch("app.services.geo_service._resolve_ptr", return_value={
                "source": "DNS_PTR", "provider": "System DNS PTR", "status": "NOT_FOUND",
                "checked_at": "2026-09-26T08:30:02+00:00", "hostname": None,
            }),
        ):
            result = asyncio.run(lookup_ip("209.85.220.41"))

        self.assertEqual(result["status"], "FOUND")
        self.assertEqual(result["country"], "United States")
        self.assertEqual(result["city"], "San Francisco")
        self.assertEqual(result["asn"], "AS15169")
        self.assertEqual(result["provider"], "ipwho.is")
        self.assertEqual(result["latitude"], 37.7749)
        self.assertEqual(result["longitude"], -122.4194)
        self.assertEqual(result["provider_results"]["IPWHOIS"]["status"], "FOUND")

    def test_current_ipwhois_response_has_no_network_range_or_type(self):
        raw = {
            "ip": "69.169.232.61",
            "success": True,
            "type": "IPv4",
            "country": "United States",
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "latitude": 47.6062073,
            "longitude": -122.3320666,
            "postal": "98190",
            "connection": {
                "asn": 16509,
                "org": "Amazon Web Services, Inc.",
                "isp": "Amazon.com, Inc.",
                "domain": "amazon.com",
            },
            "timezone": {
                "id": "America/Los_Angeles",
                "abbr": "PDT",
                "is_dst": True,
                "offset": -25200,
                "utc": "-07:00",
            },
            "readme": "https://ipwhois.io/docs",
        }

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return raw

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, *args, **kwargs):
                return Response()

        with patch("app.services.geo_service.httpx.AsyncClient", return_value=Client()):
            ipwhois = asyncio.run(_ipwhois_lookup("69.169.232.61"))

        self.assertEqual(ipwhois["raw"], raw)
        self.assertEqual(ipwhois["asn"], "AS16509")
        self.assertEqual(ipwhois["asn_name"], "Amazon Web Services, Inc.")
        self.assertEqual(ipwhois["isp"], "Amazon.com, Inc.")
        self.assertEqual(ipwhois["raw"]["connection"]["domain"], "amazon.com")
        self.assertIsNone(ipwhois["network"])
        self.assertIsNone(ipwhois["network_type"])
        self.assertIsNone(ipwhois["infrastructure_type"])
        self.assertNotIn("network", ipwhois["raw"])
        self.assertNotIn("cidr", ipwhois["raw"])
        self.assertNotIn("route", ipwhois["raw"])
        self.assertNotIn("reverse", ipwhois["raw"])

    def test_ptr_hostname_is_normalized_as_reverse_dns_and_kept_distinct_from_ipwhois(self):
        ipwhois = {
            "country": "United States",
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "asn": "AS16509",
            "asn_name": "Amazon Web Services, Inc.",
            "isp": "Amazon.com, Inc.",
            "reverse_dns": None,
            "network": None,
            "network_type": None,
            "infrastructure_type": None,
            "source": "IPWHOIS",
            "provider": "ipwho.is",
            "status": "FOUND",
            "checked_at": "2026-09-26T21:19:16+00:00",
            "raw": {
                "ip": "69.169.232.61",
                "connection": {
                    "asn": 16509,
                    "org": "Amazon Web Services, Inc.",
                    "isp": "Amazon.com, Inc.",
                    "domain": "amazon.com",
                },
            },
        }
        ptr = {
            "source": "DNS_PTR",
            "provider": "System DNS PTR",
            "status": "FOUND",
            "checked_at": "2026-09-26T21:19:16+00:00",
            "hostname": "b232-61.smtp-out.ap-southeast-2.amazonses.com",
        }
        merged = _merge_provider_results([
            {"source": "MAXMIND", "provider": "MaxMind GeoIP", "status": "UNAVAILABLE"},
            {"source": "IP_API", "provider": "IP-API", "status": "ERROR"},
            ipwhois,
            ptr,
        ])

        self.assertEqual(merged["reverse_dns"], ptr["hostname"])
        self.assertEqual(merged["domain_hostname"], ptr["hostname"])
        self.assertEqual(merged["domain_hostname_source"], "DNS_PTR")
        self.assertIsNone(merged["network"])
        self.assertIsNone(merged["network_type"])
        self.assertIsNone(merged["infrastructure_type"])
        self.assertEqual(merged["field_status"]["reverse_dns"], "AVAILABLE")
        self.assertEqual(merged["field_status"]["network"], "NOT_RETURNED_BY_SOURCE")
        self.assertEqual(merged["field_status"]["network_type"], "NOT_RETURNED_BY_SOURCE")
        self.assertEqual(merged["field_status"]["infrastructure_type"], "NOT_RETURNED_BY_SOURCE")

        intelligence = IOCIntelligenceSchema.model_validate({
            "source": "UNKNOWN",
            "geo_status": "FOUND",
            "geo": merged,
        })
        self.assertEqual(
            intelligence.geo.reverse_dns,
            "b232-61.smtp-out.ap-southeast-2.amazonses.com",
        )
        self.assertEqual(
            intelligence.geo.field_status["network"],
            "NOT_RETURNED_BY_SOURCE",
        )

        persisted_intelligence = {
            "domain_hostname": ptr["hostname"],
            "domain_hostname_source": "DNS_PTR",
            "geo": {
                "reverse_dns": None,
                "network": None,
                "network_type": None,
                "infrastructure_type": None,
                "provider_results": {
                    "IPWHOIS": ipwhois,
                    "DNS_PTR": ptr,
                },
            },
        }
        _normalize_geo_context(persisted_intelligence)
        self.assertEqual(
            persisted_intelligence["geo"]["reverse_dns"],
            ptr["hostname"],
        )
        self.assertEqual(
            persisted_intelligence["geo"]["field_status"]["network"],
            "NOT_RETURNED_BY_SOURCE",
        )

        report_case = {
            "id": "PRH-GEO-TEST",
            "created_at": "2026-09-27T00:00:00Z",
            "severity": "CLEAN",
            "verdict": "CLEAN",
            "risk_score": {"confidence": 75, "total": 0, "level": "CLEAN"},
            "auth": {},
            "iocs": [{
                "type": "IP",
                "value": "69.169.232.61",
                "valid": True,
                "intelligence": persisted_intelligence,
            }],
            "mitre_mappings": [],
            "timeline": [],
            "why_flagged": [],
            "summary": "",
        }
        report = json.loads(generate_json_report(report_case))
        self.assertEqual(
            report["iocs"][0]["intelligence"]["geo"]["reverse_dns"],
            merged["reverse_dns"],
        )
        self.assertEqual(
            report["iocs"][0]["intelligence"]["geo"]["field_status"],
            merged["field_status"],
        )

    def test_ptr_hostname_is_resolved_and_available_without_geo_provider_result(self):
        ptr = {
            "source": "DNS_PTR",
            "provider": "System DNS PTR",
            "status": "FOUND",
            "checked_at": "2026-09-26T08:30:00+00:00",
            "hostname": "mail.example.net",
        }
        with (
            patch("app.services.geo_service._maxmind_lookup", return_value=None),
            patch(
                "app.services.geo_service._ip_api_lookup",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "app.services.geo_service._ipwhois_lookup",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch("app.services.geo_service._resolve_ptr", return_value=ptr),
        ):
            result = asyncio.run(lookup_ip("8.8.8.8"))

        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["domain_hostname"], "mail.example.net")
        self.assertEqual(result["domain_hostname_source"], "DNS_PTR")
        self.assertEqual(result["provider_results"]["DNS_PTR"]["status"], "FOUND")

    def test_lookup_metadata_survives_fastapi_response_schema(self):
        result = IOCIntelligenceSchema.model_validate(
            {
                "source": "VIRUSTOTAL",
                "provider": "VirusTotal",
                "status": "FOUND",
                "lookup_status": "FOUND",
                "checked_at": "2026-09-26T08:30:00+00:00",
                "confidence": 64,
                "provider_results": {
                    "VIRUSTOTAL": {
                        "status": "FOUND",
                        "checked_at": "2026-09-26T08:30:00+00:00",
                        "reputation": 42,
                    }
                },
                "geo_lookup": {
                    "status": "TIMEOUT",
                    "checked_at": "2026-09-26T08:31:00+00:00",
                },
                "geo": {
                    "country": "India",
                    "domain_hostname": "sender-g1-27.zohomail360.in",
                    "domain_hostname_source": "DNS_PTR",
                },
                "domain_hostname": "mail.example.net",
                "domain_hostname_source": "DNS_PTR",
            }
        )

        serialized = result.model_dump()
        self.assertEqual(serialized["status"], "FOUND")
        self.assertEqual(serialized["confidence"], 64)
        self.assertEqual(serialized["provider_results"]["VIRUSTOTAL"]["status"], "FOUND")
        self.assertEqual(serialized["geo_lookup"]["status"], "TIMEOUT")
        self.assertEqual(serialized["domain_hostname"], "mail.example.net")
        self.assertEqual(
            serialized["geo"]["domain_hostname"],
            "sender-g1-27.zohomail360.in",
        )

    def test_case_builder_handles_ioc_with_unavailable_geo_context(self):
        parsed = parse_eml(EML)
        iocs = [
            {
                "id": "ioc-ip",
                "type": "IP",
                "value": "8.8.8.8",
                "source": "Received Header",
                "normalized_value": "8.8.8.8",
                "valid": True,
                "confidence": 100,
                "risk": "UNKNOWN",
                "status": "UNKNOWN",
                "intelligence": {
                    "geo": None,
                    "geo_status": "UNAVAILABLE",
                },
            }
        ]
        auth = analyze_auth(parsed["headers"])
        risk = compute_risk_score(parsed, auth, iocs)

        case = build_case("PRH-2026-TEST", parsed, auth, iocs, risk, [])

        ip_node = next(node for node in case["graph_nodes"] if node["type"] == "IP")
        self.assertEqual(ip_node["detail"], "IP Address")


class TransformerAnalysisTests(unittest.TestCase):
    def test_one_checkpoint_load_failure_does_not_disable_the_other(self):
        class FakeModel:
            config = SimpleNamespace(
                num_labels=2,
                id2label={0: "LABEL_0", 1: "LABEL_1"},
                max_position_embeddings=512,
            )

            def to(self, device):
                return self

        service = AIAnalysisService()
        with (
            patch("transformers.AutoTokenizer.from_pretrained",
                  side_effect=[RuntimeError("BERT weights unavailable"), object()]),
            patch("transformers.AutoModelForSequenceClassification.from_pretrained",
                  return_value=FakeModel()),
            patch("app.services.nlp_service.settings.ai_device", "cpu"),
            patch("app.services.nlp_service.logger.exception"),
        ):
            service.load_models()

        self.assertEqual(service.model_states["BERT"]["status"], "UNAVAILABLE")
        self.assertEqual(service.model_states["RoBERTa"]["status"], "AVAILABLE")

    def test_token_chunking_preserves_subject_and_overlaps_long_body(self):
        chunks = _token_chunks([99], list(range(12)), max_tokens=10, overlap=2)

        self.assertEqual(chunks, [
            [99, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            [99, 7, 8, 9, 10, 11],
        ])
        self.assertTrue(all(len(chunk) <= 10 for chunk in chunks))

    def test_analysis_aggregates_only_phishing_labeled_models(self):
        class FakeRunner:
            def __init__(self, model_id, probability):
                self.model_id = model_id
                self.probability = probability

            def predict(self, subject, body):
                return {
                    "model_id": self.model_id,
                    "status": "AVAILABLE",
                    "benign_probability": 1 - self.probability,
                    "phishing_probability": self.probability,
                    "labels": [{"label": "phishing", "probability": self.probability}],
                }

        service = AIAnalysisService()
        service.runners = {
            "BERT": FakeRunner("bert-test", 0.8),
            "RoBERTa": FakeRunner("roberta-test", 0.6),
        }

        result = service.analyze("subject", "body")

        self.assertEqual(result["status"], "AVAILABLE")
        self.assertEqual(result["aggregate_phishing_probability"], 0.7)
        self.assertEqual(result["risk_contribution"], 3)
        self.assertEqual([model["name"] for model in result["models"]], ["BERT", "RoBERTa"])
        self.assertAlmostEqual(result["aggregate_benign_probability"], 0.3)
        self.assertAlmostEqual(
            result["combined_ai_signal"]["benign_probability"]
            + result["combined_ai_signal"]["phishing_probability"],
            1.0,
            places=6,
        )

    def test_near_threshold_ai_contribution_explains_integer_rounding(self):
        class FakeRunner:
            def __init__(self, model_id, probability):
                self.model_id = model_id
                self.probability = probability

            def predict(self, subject, body):
                return {
                    "model_id": self.model_id,
                    "status": "AVAILABLE",
                    "benign_probability": 1 - self.probability,
                    "phishing_probability": self.probability,
                }

        service = AIAnalysisService()
        service.runners = {
            "BERT": FakeRunner("bert-test", 0.4977),
            "RoBERTa": FakeRunner("roberta-test", 0.5173),
        }

        with patch("app.services.nlp_service._ai_analysis_service", service), patch(
            "app.services.nlp_service._classifier", RuleBasedClassifier()
        ):
            result = analyze_content("subject", "body")

        self.assertAlmostEqual(
            result["ai_analysis"]["aggregate_phishing_probability"], 0.5075
        )
        self.assertEqual(result["ai_score"], 0)
        self.assertTrue(any("0.12/8 raw point(s) rounded to 0" in s for s in result["signals"]))

    def test_one_model_failure_keeps_other_model_result(self):
        class AvailableRunner:
            model_id = "bert-test"

            def predict(self, subject, body):
                return {
                    "status": "AVAILABLE",
                    "benign_probability": 0.1,
                    "phishing_probability": 0.9,
                    "labels": [{"label": "phishing", "probability": 0.9}],
                }

        class FailedRunner:
            model_id = "roberta-test"

            def predict(self, subject, body):
                raise RuntimeError("model inference failed")

        service = AIAnalysisService()
        service.runners = {"BERT": AvailableRunner(), "RoBERTa": FailedRunner()}
        service.model_states = {
            "BERT": {"model_id": "bert-test", "status": "AVAILABLE"},
            "RoBERTa": {"model_id": "roberta-test", "status": "AVAILABLE"},
        }

        with patch("app.services.nlp_service.logger.exception"):
            result = service.analyze("subject", "body")

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["models"][1]["error"], "model inference failed")
        self.assertEqual(result["aggregate_phishing_probability"], 0.9)
        self.assertGreater(result["risk_contribution"], 0)

    def test_ai_input_cap_is_reported_and_applied_to_each_model(self):
        class FakeRunner:
            model_id = "bert-test"

            def __init__(self):
                self.body = None

            def predict(self, subject, body):
                self.body = body
                return {"status": "AVAILABLE", "phishing_probability": 0.4}

        runner = FakeRunner()
        service = AIAnalysisService()
        service.runners = {"BERT": runner}
        service.model_states = {
            "BERT": {"model_id": "bert-test", "status": "AVAILABLE"},
            "RoBERTa": {"model_id": "roberta-test", "status": "UNAVAILABLE"},
        }

        with patch("app.services.nlp_service.settings.ai_max_input_characters", 5):
            result = service.analyze("", "long body")

        self.assertEqual(runner.body, "long ")
        self.assertTrue(result["input_truncated"])
        self.assertEqual(result["input_characters"], 5)

    def test_ai_input_character_count_includes_subject_body_separator(self):
        class FakeRunner:
            model_id = "bert-test"

            def predict(self, subject, body):
                return {
                    "status": "AVAILABLE",
                    "benign_probability": 0.9,
                    "phishing_probability": 0.1,
                }

        service = AIAnalysisService()
        service.runners = {"BERT": FakeRunner()}
        service.model_states = {
            "BERT": {"model_id": "bert-test", "status": "AVAILABLE"},
            "RoBERTa": {"model_id": "roberta-test", "status": "UNAVAILABLE"},
        }

        result = service.analyze("sub", "body")

        self.assertEqual(result["input_characters"], len("sub body"))

    def test_generic_model_labels_are_not_assumed_to_mean_phishing(self):
        class FakeConfig:
            id2label = {0: "LABEL_0", 1: "LABEL_1"}
            num_labels = 2

        class FakeModel:
            config = FakeConfig()

        runner = TransformerRunner("model-test", FakeModel(), None, None, "cpu")

        self.assertIsNone(runner.phishing_index)
        self.assertIsNone(runner.benign_index)

    def test_configured_roberta_checkpoint_maps_both_generic_labels(self):
        class FakeConfig:
            id2label = {0: "LABEL_0", 1: "LABEL_1"}
            num_labels = 2

        class FakeModel:
            config = FakeConfig()

        runner = TransformerRunner(
            "eduardocastellon/roberta-phishing-email-detector",
            FakeModel(),
            None,
            None,
            "cpu",
        )

        self.assertEqual(runner.class_mapping, {
            "LABEL_0": "benign",
            "LABEL_1": "phishing",
        })
        self.assertEqual(runner.benign_index, 0)
        self.assertEqual(runner.phishing_index, 1)

    def test_configured_bert_checkpoint_uses_its_own_named_labels(self):
        class FakeConfig:
            id2label = {0: "benign", 1: "phishing"}
            num_labels = 2

        class FakeModel:
            config = FakeConfig()

        runner = TransformerRunner(
            "ealvaradob/bert-finetuned-phishing",
            FakeModel(),
            None,
            None,
            "cpu",
        )

        self.assertEqual(runner.class_mapping, {
            "benign": "benign",
            "phishing": "phishing",
        })
        self.assertEqual(runner.benign_index, 0)
        self.assertEqual(runner.phishing_index, 1)


@unittest.skipUnless(
    os.environ.get("PRAHARI_RUN_MODEL_REGRESSION") == "1",
    "Set PRAHARI_RUN_MODEL_REGRESSION=1 to run cached real-checkpoint inference.",
)
class RealCheckpointRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import gc
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        torch.set_num_threads(1)
        root = Path(__file__).parents[1]
        cls.emails = {
            "BHASHINI": parse_eml(
                (root / "phish_mail" / "One-Time Password (OTP) for Account Verification - BHASHINI.eml").read_bytes()
            ),
            "Microsoft Team": parse_eml(
                (root / "phish_mail" / "Microsoft Team.eml").read_bytes()
            ),
        }
        cls.outputs = {}
        cls.mappings = {}
        cls.direct_outputs = {}
        model_ids = {
            "BERT": settings.ai_bert_model_id,
            "RoBERTa": settings.ai_roberta_model_id,
        }
        label_maps = {
            "BERT": settings.ai_bert_label_map,
            "RoBERTa": settings.ai_roberta_label_map,
        }
        for model_name, model_id in model_ids.items():
            tokenizer = AutoTokenizer.from_pretrained(model_id, local_files_only=True)
            model = AutoModelForSequenceClassification.from_pretrained(
                model_id, local_files_only=True
            ).to("cpu")
            runner = TransformerRunner(model_id, model, tokenizer, torch, "cpu")
            cls.mappings[model_name] = runner.class_mapping
            if runner.class_mapping != label_maps[model_name]:
                raise AssertionError(
                    f"{model_name} mapping differs from its configured checkpoint mapping"
                )
            for email_name, parsed in cls.emails.items():
                cls.outputs.setdefault(email_name, {})
                cls.direct_outputs.setdefault(email_name, {})
                cls.outputs[email_name][model_name] = [
                    runner.predict(parsed["subject"], parsed["body_text"])
                    for _ in range(3)
                ]
                normalized_text = f"{parsed['subject']} {parsed['body_text']}".strip()
                encoded = tokenizer(
                    normalized_text,
                    return_tensors="pt",
                    truncation=True,
                    max_length=min(
                        settings.ai_max_sequence_length,
                        getattr(model.config, "max_position_embeddings", settings.ai_max_sequence_length),
                    ),
                )
                with torch.inference_mode():
                    logits = model(**encoded).logits[0]
                    softmax = torch.softmax(logits, dim=-1)
                labels = runner.labels
                cls.direct_outputs[email_name][model_name] = {
                    "logits": logits.tolist(),
                    "probabilities": {
                        labels[index]: float(softmax[index])
                        for index in range(len(labels))
                    },
                }
            del runner, model, tokenizer
            gc.collect()

    def _assert_stable_and_normalized(self, email_name: str) -> None:
        for model_name, runs in self.outputs[email_name].items():
            self.assertEqual(len(runs), 3)
            first = runs[0]
            self.assertEqual(first["status"], "AVAILABLE")
            self.assertEqual(first["class_mapping"], self.mappings[model_name])
            for current in runs[1:]:
                self.assertEqual(current["predicted_label"], first["predicted_label"])
                self.assertEqual(current["predicted_class"], first["predicted_class"])
                self.assertAlmostEqual(
                    current["benign_probability"], first["benign_probability"], places=12
                )
                self.assertAlmostEqual(
                    current["phishing_probability"], first["phishing_probability"], places=12
                )
            self.assertAlmostEqual(
                first["benign_probability"] + first["phishing_probability"],
                1.0,
                delta=1e-7,
            )

    def test_bhashini_outputs_are_repeatable_without_forcing_a_verdict(self):
        self._assert_stable_and_normalized("BHASHINI")

    def test_microsoft_team_outputs_are_repeatable_and_phishing_directed(self):
        self._assert_stable_and_normalized("Microsoft Team")
        means = {
            class_name: sum(
                runs[0][f"{class_name}_probability"]
                for runs in self.outputs["Microsoft Team"].values()
            ) / len(self.outputs["Microsoft Team"])
            for class_name in ("benign", "phishing")
        }
        self.assertGreater(means["phishing"], means["benign"])

    def test_short_real_email_sequences_match_direct_transformers(self):
        for email_name in self.emails:
            for model_name, runs in self.outputs[email_name].items():
                self.assertEqual(runs[0]["chunks"], 1)
                direct = self.direct_outputs[email_name][model_name]["probabilities"]
                actual = {
                    item["label"]: item["probability"]
                    for item in runs[0]["labels"]
                }
                self.assertEqual(actual.keys(), direct.keys())
                for label in direct:
                    self.assertAlmostEqual(actual[label], direct[label], delta=1e-7)


class TransformerReportTests(unittest.TestCase):
    def test_model_outputs_are_included_in_json_report(self):
        analysis = {
            "status": "AVAILABLE",
            "aggregate_phishing_probability": 0.92,
            "risk_contribution": 7,
            "models": [{
                "name": "BERT",
                "model_id": "bert-test",
                "status": "AVAILABLE",
                "predicted_label": "phishing",
                "phishing_probability": 0.92,
                "labels": [{"label": "phishing", "probability": 0.92}],
            }],
        }
        report = generate_json_report({
            "id": "PRH-TEST",
            "created_at": "2026-01-01T00:00:00Z",
            "severity": "HIGH",
            "verdict": "SUSPICIOUS",
            "risk_score": {"confidence": 50, "ai_analysis": analysis},
            "ai_analysis": analysis,
            "auth": {},
            "iocs": [],
            "mitre_mappings": [],
            "timeline": [],
            "why_flagged": [],
            "summary": "",
        })
        self.assertEqual(json.loads(report)["ai_analysis"], analysis)

    def test_model_result_flows_into_risk_score_and_case(self):
        class FakeRunner:
            model_id = "bert-test"

            def predict(self, subject, body):
                return {
                    "model_id": self.model_id,
                    "status": "AVAILABLE",
                    "benign_probability": 0.01,
                    "phishing_probability": 0.99,
                    "labels": [{"label": "phishing", "probability": 0.99}],
                }

        service = AIAnalysisService()
        service.runners = {"BERT": FakeRunner()}
        service.model_states = {
            "BERT": {"model_id": "bert-test", "status": "AVAILABLE"},
            "RoBERTa": {"model_id": "roberta-test", "status": "UNAVAILABLE"},
        }
        parsed = {
            "subject": "Schedule update",
            "body_text": "The meeting is moved to tomorrow.",
            "from_addr": "sender@example.com",
            "to_addr": "recipient@example.com",
            "date": "Sat, 26 Sep 2026 08:30:00 +0000",
            "email_addresses": ["sender@example.com", "recipient@example.com"],
            "received_ips": [],
            "urls": [],
            "attachments": [],
            "headers": [],
        }
        auth = {
            "spf": "NOT_AVAILABLE",
            "dkim": "NOT_AVAILABLE",
            "dmarc": "NOT_AVAILABLE",
            "summary": "No authentication results available.",
        }

        with patch("app.services.nlp_service._ai_analysis_service", service), patch(
            "app.services.nlp_service._classifier", RuleBasedClassifier()
        ):
            risk = compute_risk_score(parsed, auth, [])
        case = build_case("PRH-TEST", parsed, auth, [], risk, [])
        response_case = CaseOut.model_validate(case)

        self.assertEqual(risk["content"]["rule_score"], 0)
        self.assertEqual(risk["content"]["ai_score"], 8)
        self.assertEqual(risk["content"]["score"], 8)
        self.assertEqual(case["ai_analysis"], risk["ai_analysis"])
        self.assertEqual(response_case.ai_analysis.risk_contribution, 8)


class ControlledEmailPipelineTests(unittest.TestCase):
    @staticmethod
    async def _run_pipeline(eml: bytes, phishing_probability: float) -> dict:
        class FixedModelRunner:
            def __init__(self, model_id):
                self.model_id = model_id

            def predict(self, subject, body):
                return {
                    "model_id": self.model_id,
                    "status": "AVAILABLE",
                    "labels": [
                        {"label": "benign", "probability": 1 - phishing_probability},
                        {"label": "phishing", "probability": phishing_probability},
                    ],
                    "class_mapping": {"benign": "benign", "phishing": "phishing"},
                    "predicted_label": "phishing" if phishing_probability > 0.5 else "benign",
                    "predicted_class": "phishing" if phishing_probability > 0.5 else "benign",
                    "benign_probability": 1 - phishing_probability,
                    "phishing_probability": phishing_probability,
                    "chunks": 1,
                    "aggregation": "Arithmetic mean of per-chunk class probabilities",
                }

        parsed = parse_eml(eml)
        auth = analyze_auth(parsed["headers"])
        raw_iocs = extract_iocs(parsed)
        intelligence_error = httpx.ConnectError("controlled provider outage")
        with (
            patch("app.services.threat_intel._cache_get", new_callable=AsyncMock, return_value=None),
            patch("app.services.threat_intel.local_lookup", return_value=None),
            patch("app.services.threat_intel.settings.virustotal_api_key", "test-key"),
            patch("app.services.threat_intel.settings.abuseipdb_api_key", "test-key"),
            patch("app.services.threat_intel.logger.warning"),
            patch("app.services.threat_intel._vt_lookup_ip", new_callable=AsyncMock, side_effect=intelligence_error),
            patch("app.services.threat_intel._vt_lookup_domain", new_callable=AsyncMock, side_effect=intelligence_error),
            patch("app.services.threat_intel._abuseipdb_lookup", new_callable=AsyncMock, side_effect=intelligence_error),
        ):
            iocs = await enrich_iocs(raw_iocs, allow_local_database=False)
        with patch("app.services.geo_service.lookup_ip", new_callable=AsyncMock, return_value=None):
            iocs = await enrich_geo(iocs)

        service = AIAnalysisService()
        service.runners = {
            "BERT": FixedModelRunner("ealvaradob/bert-finetuned-phishing"),
            "RoBERTa": FixedModelRunner("eduardocastellon/roberta-phishing-email-detector"),
        }
        service.model_states = {
            "BERT": {"model_id": "ealvaradob/bert-finetuned-phishing", "status": "AVAILABLE"},
            "RoBERTa": {
                "model_id": "eduardocastellon/roberta-phishing-email-detector",
                "status": "AVAILABLE",
            },
        }
        with (
            patch("app.services.nlp_service._ai_analysis_service", service),
            patch("app.services.nlp_service._classifier", RuleBasedClassifier()),
        ):
            risk = compute_risk_score(parsed, auth, iocs)
        mappings = map_mitre(parsed, auth, iocs, risk)
        case = build_case("PRH-CONTROLLED", parsed, auth, iocs, risk, mappings)
        report = json.loads(generate_json_report(case))
        return {
            "case": case,
            "report": report,
            "iocs": iocs,
            "auth": auth,
            "risk": risk,
            "mappings": mappings,
        }

    def test_clean_email_pipeline_stays_clean_without_invented_intelligence(self):
        result = asyncio.run(self._run_pipeline(CLEAN_EML, 0.01))
        case = result["case"]

        self.assertEqual(result["auth"]["spf"], "PASS")
        self.assertEqual(result["auth"]["dkim"], "PASS")
        self.assertEqual(result["auth"]["dmarc"], "PASS")
        self.assertEqual(case["risk_score"]["total"], 0)
        self.assertEqual(case["verdict"], "CLEAN")
        self.assertEqual(
            case["ai_analysis"]["combined_ai_signal"]["phishing_probability"],
            0.01,
        )
        self.assertEqual(
            case["ai_analysis"]["combined_ai_signal"]["benign_probability"],
            0.99,
        )
        self.assertFalse(any(item["technique_id"] == "T1566.002" for item in result["mappings"]))
        self.assertTrue(all(
            ioc.get("status") != "MALICIOUS"
            and (ioc.get("intelligence") or {}).get("reputation") is None
            for ioc in result["iocs"]
        ))
        self.assertEqual(result["report"]["ai_evidence"]["final_risk"]["level"], "CLEAN")

    def test_controlled_phishing_email_runs_all_stages_and_reports_evidence(self):
        result = asyncio.run(self._run_pipeline(CONTROLLED_PHISHING_EML, 0.99))
        case = result["case"]
        ai = case["ai_analysis"]

        self.assertEqual(result["auth"]["spf"], "FAIL")
        self.assertEqual(result["auth"]["dkim"], "FAIL")
        self.assertEqual(result["auth"]["dmarc"], "FAIL")
        self.assertEqual(ai["models"][0]["phishing_probability"], 0.99)
        self.assertEqual(ai["models"][1]["phishing_probability"], 0.99)
        self.assertEqual(ai["combined_ai_signal"]["phishing_probability"], 0.99)
        self.assertAlmostEqual(ai["combined_ai_signal"]["benign_probability"], 0.01)
        self.assertGreater(case["risk_score"]["total"], 0)
        self.assertNotEqual(case["verdict"], "CLEAN")
        self.assertTrue(any(item["technique_id"] == "T1566.002" for item in result["mappings"]))
        self.assertTrue(all(
            (ioc.get("intelligence") or {}).get("lookup_status") in ("ERROR", "UNAVAILABLE")
            for ioc in result["iocs"]
            if ioc.get("type") in ("IP", "URL", "DOMAIN")
        ))
        evidence = result["report"]["ai_evidence"]
        self.assertEqual(evidence["authentication"]["risk_score"], 20)
        self.assertIn("final_risk", evidence)
        self.assertIn("explanation", evidence["final_risk"])

    def test_ordinary_url_alone_does_not_create_spearphishing_mapping(self):
        parsed = {"urls": ["https://www.example.net/news"], "subject": "Newsletter", "body_text": "Read our newsletter."}
        auth = {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
        iocs = [{
            "type": "URL",
            "value": "https://www.example.net/news",
            "valid": True,
            "risk": "UNKNOWN",
            "intelligence": {"lookup_status": "UNAVAILABLE"},
        }]

        mappings = map_mitre(parsed, auth, iocs, {
            "ai_analysis": {
                "combined_ai_signal": {"phishing_probability": 0.5075},
                "phishing_threshold": 0.5,
            }
        })

        self.assertFalse(any(item["technique_id"] == "T1566.002" for item in mappings))

    def test_contextual_account_review_link_maps_spearphishing(self):
        parsed = {
            "urls": ["https://bit.ly/example"],
            "subject": "Unusual sign-in activity",
            "body_text": "Please secure your account immediately. Review recent activity.",
        }

        mappings = map_mitre(parsed, {}, [])

        self.assertIn("T1566.002", [item["technique_id"] for item in mappings])


if __name__ == "__main__":
    unittest.main()
