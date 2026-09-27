Create the complete technical architecture and implementation plan for:

PRAHARI AI
AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Use ONLY the following technology stack unless a supporting library is genuinely required.

==================================================
FRONTEND
==================================================

• React.js
• Tailwind CSS

Purpose:
Build the analyst dashboard, email upload interface, investigation view,
IOC tables, evidence graph, risk visualization, timeline and forensic report UI.

Required UI modules:

1. Dashboard
2. Email Upload
3. Email Analysis
4. IOC Intelligence
5. Geo / Network Context
6. Evidence Correlation Graph
7. Risk Score
8. MITRE ATT&CK Mapping
9. Investigation Case
10. Forensic Report


==================================================
BACKEND
==================================================

• Python
• FastAPI

Purpose:

Create REST APIs for:

• Email upload
• Email parsing
• Content analysis
• Header analysis
• IOC extraction
• Threat intelligence enrichment
• GeoIP lookup
• Evidence correlation
• Risk scoring
• MITRE mapping
• Case management
• Report generation


==================================================
EMAIL PROCESSING
==================================================

Use:

• Python email / MIME parser

Capabilities:

• Parse .EML files
• Extract headers
• Extract sender / recipient
• Extract subject
• Extract body
• Extract URLs
• Extract IP addresses
• Extract domains
• Extract email addresses
• Extract attachment metadata
• Calculate attachment hashes

Do NOT execute email attachments.


==================================================
AI / NLP
==================================================

Use:

• BERT / RoBERTa-compatible NLP architecture

Purpose:

Analyze email content for phishing/BEC-related signals.

The AI component should produce interpretable signals rather than
only returning a binary classification.

Example signals:

• Suspicious language
• Urgency
• Credential request
• Impersonation indicators
• Suspicious links
• Social engineering patterns

IMPORTANT:

If a trained BERT/RoBERTa model is not available,
do not pretend that a rule-based classifier is an actual trained model.

Create a modular model interface so a trained model can be plugged in later.


==================================================
EMAIL AUTHENTICATION
==================================================

Analyze:

• SPF
• DKIM
• DMARC

Return:

PASS
FAIL
NEUTRAL
NOT AVAILABLE

Use these results as authentication signals in the risk engine.


==================================================
THREAT INTELLIGENCE
==================================================

Integrate where API credentials are available:

• VirusTotal
• AbuseIPDB
• WHOIS / DNS

Use the backend for all API calls.

Never expose API keys in React/frontend.

Store credentials using environment variables.

Example:

VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY


==================================================
GEOLOCATION & NETWORK INTELLIGENCE
==================================================

Use:

• MaxMind GeoIP
• ASN lookup
• ISP lookup
• Network context

Purpose:

Identify the geographic and network context associated with
the observed IP infrastructure.

Display:

• Country
• Region
• City
• ASN
• ISP
• Network

IMPORTANT:

Do NOT claim that GeoIP identifies the attacker's exact physical location.

Use the wording:

"Geographic & Network Context of Observed IP Infrastructure."


==================================================
DATABASE
==================================================

Use:

• PostgreSQL

Store:

• Users
• Cases
• Emails
• Headers
• Attachments
• IOCs
• Threat intelligence
• Geo/network information
• Risk scores
• MITRE mappings
• Reports


==================================================
GRAPH DATABASE
==================================================

Use:

• Neo4j

Purpose:

Create the connected evidence graph.

Nodes:

Email
Domain
URL
IP
ASN
Geo
Reputation

Example relationship:

Email
 ↓
URL
 ↓
Domain
 ↓
IP
 ↓
ASN
 ↓
Geo

Use Neo4j to demonstrate PRAHARI's core capability:

"Connecting scattered indicators into one threat case."


==================================================
CACHE
==================================================

Use:

• Redis

Purpose:

• Cache threat-intelligence responses
• Reduce repeated API calls
• Improve response time
• Support temporary investigation data

Cache external intelligence using sensible expiration times.


==================================================
LOCAL IOC FALLBACK
==================================================

Implement a local IOC database using PostgreSQL.

Purpose:

If:

• VirusTotal is unavailable
• AbuseIPDB is unavailable
• API key is missing
• API rate limit is reached
• Network connection fails

then PRAHARI should use:

Cached Intelligence
        ↓
Local IOC Database

Clearly display:

"Source: Local IOC Database"

Do not pretend the information came from an external API.


==================================================
RISK ENGINE
==================================================

Implement a transparent multi-signal weighted scoring engine.

Inputs:

• Content Score
• Authentication Score
• Reputation Score
• Infrastructure Context Score

Example:

Content Score: 22/25
Authentication Score: 18/20
Reputation Score: 25/25
Infrastructure Score: 26/30

Total:

91/100

The system must explain why the score was generated.

Example:

"High risk due to suspicious URL reputation,
authentication anomalies and suspicious infrastructure context."

Do not use a mysterious black-box score.


==================================================
MITRE ATT&CK
==================================================

Use:

• MITRE ATT&CK

Map supported findings to relevant techniques.

Example:

T1566.002 — Spearphishing Link

Show:

Technique
Evidence
Reason for Mapping

Only create a mapping when evidence supports it.


==================================================
REPORTING
==================================================

Generate:

• PDF
• JSON

Report contents:

• Case ID
• Email summary
• Risk score
• Verdict
• Authentication findings
• IOC list
• Threat intelligence
• Geo/network context
• Evidence relationships
• MITRE ATT&CK mapping
• Timeline
• Analyst summary


==================================================
SECURITY
==================================================

Implement:

• JWT / OAuth-compatible authentication
• Input validation
• File type validation
• File size limits
• Sanitized email parsing
• Secure API handling
• Environment variables
• No API secrets in frontend

Never execute uploaded attachments.


==================================================
DEPLOYMENT
==================================================

Use:

• Docker
• Docker Compose

Containerize:

• React frontend
• FastAPI backend
• PostgreSQL
• Neo4j
• Redis

Design deployment so the prototype can run:

• Locally
• Cloud
• On-premise


==================================================
ARCHITECTURE
==================================================

Use this architecture:

                    PRAHARI AI
                         |
                 React + Tailwind
                         |
                    FastAPI API
                         |
       ┌─────────────────┼─────────────────┐
       ↓                 ↓                 ↓
 Email Processing    AI/NLP           Risk Engine
       |                 |                 |
       └────────────┬────┴─────────────────┘
                    ↓
               IOC Extraction
                    ↓
        Threat Intelligence Layer
          /        |         \
    VirusTotal  AbuseIPDB  WHOIS/DNS
                    |
                    ↓
          Geo / Network Intelligence
                    |
              MaxMind / ASN / ISP
                    ↓
             Evidence Correlation
                    ↓
                  Neo4j
                    ↓
             Risk Assessment
                    ↓
           MITRE ATT&CK Mapping
                    ↓
             Forensic Case
                    ↓
             PDF / JSON Report

Supporting infrastructure:

PostgreSQL → Persistent Storage
Redis → Cache
Local IOC DB → Offline Intelligence Fallback
Docker → Deployment


==================================================
FINAL TECH STACK DISPLAY
==================================================

For the actual PPT, represent the stack as:

Frontend:
React + Tailwind CSS

Backend:
Python + FastAPI

AI:
BERT / RoBERTa

Email:
Python MIME

Database:
PostgreSQL

Graph:
Neo4j

Cache:
Redis

Threat Intelligence:
VirusTotal + AbuseIPDB + WHOIS/DNS

Geo Intelligence:
MaxMind + ASN / ISP

Security:
JWT / OAuth

Deployment:
Docker + Docker Compose

Reporting:
HTML → PDF / JSON


==================================================
IMPLEMENTATION PRIORITY
==================================================

Build in this order:

1. .EML upload
2. Email parsing
3. IOC extraction
4. SPF/DKIM/DMARC analysis
5. Risk scoring
6. Local IOC fallback
7. Threat-intelligence integrations
8. Geo/network context
9. Neo4j evidence graph
10. MITRE mapping
11. Forensic report
12. UI polish
13. Docker deployment

PRIORITIZE A WORKING END-TO-END INVESTIGATION OVER EXTRA FEATURES.

The final prototype must demonstrate:

EMAIL
→ ANALYSIS
→ IOC EXTRACTION
→ THREAT INTELLIGENCE
→ GEO/NETWORK CONTEXT
→ EVIDENCE CORRELATION
→ EXPLAINABLE RISK SCORE
→ MITRE ATT&CK
→ FORENSIC REPORT

This is the core PRAHARI AI technical architecture.