FIX PRAHARI AI REAL-WORLD EMAIL ANALYSIS

The current PRAHARI AI prototype has a critical problem:

When I upload a real-world .EML email, Threat Intelligence / GeoIP
often shows no data or asks for the IOC to exist in the Local IOC Database.

THIS IS WRONG.

The Local IOC Database must NOT be the primary requirement for analysing
a real uploaded email.

The system must dynamically extract IOCs from ANY uploaded .EML file and
attempt real-world enrichment for those IOCs.

==================================================
CORE REQUIREMENT
==================================================

For ANY uploaded .EML:

UPLOAD
 ↓
PARSE EMAIL
 ↓
EXTRACT REAL IOCs
 ↓
QUERY LIVE INTELLIGENCE
 ↓
GEO / NETWORK LOOKUP
 ↓
CORRELATE EVIDENCE
 ↓
CALCULATE RISK
 ↓
GENERATE FORENSIC RESULTS

The system must NOT require the IOC to already exist in a local database.

==================================================
1. REAL IOC EXTRACTION
==================================================

From every uploaded email automatically extract:

• IPv4 addresses
• IPv6 addresses
• Domains
• URLs
• Email addresses
• Attachment hashes
• Sender
• Reply-To
• Return-Path
• Received headers

Extract IOCs from:

• From
• To
• Reply-To
• Return-Path
• Received
• Authentication-Results
• Message-ID
• Subject
• Plain-text body
• HTML body
• Attachments / attachment metadata

Deduplicate all indicators.

Store the extracted indicators for the current investigation.


==================================================
2. LIVE IP GEOLOCATION
==================================================

For every PUBLIC IP extracted from the email:

Perform a live GeoIP lookup.

The system should obtain, when available:

• Country
• Region
• City
• Latitude / Longitude
• ASN
• ISP
• Organization
• Network

Do NOT require the IP to exist in the local IOC database.

Use a real GeoIP provider/service configured through the backend.

IMPORTANT:

Never expose API keys in the frontend.

Use environment variables.

Example:

GEOIP_API_KEY

If MaxMind is configured, use MaxMind.

If another configured GeoIP provider is available, use that provider.

==================================================
3. PRIVATE IP HANDLING
==================================================

Do not send private/local IP addresses to public GeoIP services.

Detect:

10.x.x.x
172.16.x.x – 172.31.x.x
192.168.x.x
127.x.x.x
169.254.x.x

Display:

PRIVATE / LOCAL IP

"Not publicly geolocatable."

Do not treat this as an API failure.


==================================================
4. THREAT INTELLIGENCE
==================================================

For every extracted public IP, domain and URL:

Attempt live enrichment.

IP:

• VirusTotal
• AbuseIPDB
• GeoIP
• ASN
• ISP

Domain / URL:

• VirusTotal
• WHOIS
• DNS
• Reputation

Use backend API integrations.

API credentials must be stored in:

.env

Never in React.


==================================================
5. INTELLIGENCE SOURCE PRIORITY
==================================================

Use this exact priority:

LIVE API
   ↓
CACHED RESULT
   ↓
LOCAL IOC DATABASE
   ↓
NO DATA AVAILABLE

The Local IOC Database is ONLY a fallback.

It must NOT prevent live investigation.

Example:

Uploaded IP:
8.8.8.8

If 8.8.8.8 is not in local IOC database:

DO NOT return:

"No IOC found in local database."

Instead:

1. Query GeoIP
2. Query threat intelligence
3. Query reputation
4. Cache the result
5. Save the result to the investigation

==================================================
6. API FAILURE HANDLING
==================================================

If an external API fails:

Do NOT fail the entire investigation.

For example:

VirusTotal unavailable
↓
Continue GeoIP

AbuseIPDB unavailable
↓
Continue WHOIS/DNS

GeoIP unavailable
↓
Show:

"GeoIP unavailable for this indicator."

Then continue the rest of the investigation.

Each intelligence source must fail independently.

==================================================
7. DISPLAY DATA SOURCE
==================================================

For every intelligence result show its source.

Examples:

Source: VirusTotal
Source: AbuseIPDB
Source: MaxMind GeoIP
Source: WHOIS
Source: DNS
Source: Cached Intelligence
Source: Local IOC Database

Never claim a result came from an API if it did not.

==================================================
8. GEO / NETWORK PAGE
==================================================

When I upload an email containing public IP addresses,
automatically populate:

GEOGRAPHIC & NETWORK CONTEXT

Observed IP:
<real extracted IP>

Country:
<live result>

Region:
<live result>

City:
<live result>

ASN:
<live result>

ISP:
<live result>

Organization:
<live result>

Network:
<live result>

Source:
<provider>

Add this note:

"GeoIP identifies the geographic and network context associated
with the observed IP infrastructure. It does not identify the
attacker's exact physical location."


==================================================
9. THREAT INTELLIGENCE PAGE
==================================================

Never show an empty page if real IOCs were extracted.

For each IOC show:

IOC
Type
Reputation
Confidence
Geo / Network
Source

Example:

185.x.x.x
IP
Suspicious
High
Germany / AS12345
AbuseIPDB + GeoIP

example.com
Domain
Suspicious
Medium
WHOIS / DNS
VirusTotal

==================================================
10. REAL EMAIL WITH NO MALICIOUS IOC
==================================================

IMPORTANT:

Do NOT force every email to become malicious.

If the uploaded email is legitimate:

Show:

LOW RISK

and explain why.

Example:

"No strong malicious indicators detected."

But still show:

• extracted IPs
• domains
• URLs
• authentication results
• Geo/network information where available
• reputation information where available

This makes PRAHARI credible.

==================================================
11. RISK ENGINE
==================================================

Risk score must be calculated from the actual uploaded email.

Use:

Content signals
+
Authentication signals
+
IOC reputation
+
URL/domain signals
+
Infrastructure context

Example:

Authentication anomaly
+20

Suspicious URL
+25

Malicious IP reputation
+25

Look-alike domain
+15

Suspicious content
+10

Final:
95 / 100

Do NOT use a fixed 91/100 score for every email.

The 91/100 score should exist ONLY for the demo investigation.


==================================================
12. EVIDENCE GRAPH
==================================================

Automatically generate the graph from the actual uploaded email.

Example:

EMAIL
 ↓
DOMAIN
 ↓
URL
 ↓
IP
 ↓
ASN
 ↓
GEO

Add reputation relationships where available.

The graph must change depending on the uploaded email.

Do NOT use the same hardcoded graph for every investigation.


==================================================
13. INVESTIGATION RESULT
==================================================

After analysis, create a dynamic investigation case.

Show:

Case ID
Risk Score
Verdict
IOC Count
Threat Signals
Authentication
Geo Context
Evidence Relationships

Example:

PRH-2026-014

Risk:
78 / 100

Verdict:
SUSPICIOUS

IOCs:
14

Public IPs:
3

Domains:
4

URLs:
5

Attachments:
2


==================================================
14. MULTIPLE IOCs
==================================================

If an email contains:

5 IPs
4 domains
8 URLs

analyse ALL of them.

Do not analyse only the first IOC.

Create a background processing queue or asynchronous requests.

Show:

Analyzing 17 indicators...

Then:

17 indicators analyzed


==================================================
15. PERFORMANCE
==================================================

Do not make the user wait for every API sequentially.

Use asynchronous backend processing where possible.

Run independent lookups concurrently.

Example:

IP 1 ─┐
IP 2 ─┤
IP 3 ─┤ → Parallel enrichment
Domain 1 ─┤
URL 1 ─┘

Then combine results into the investigation.


==================================================
16. API CONFIGURATION PAGE
==================================================

Add an Admin / Settings section:

THREAT INTELLIGENCE CONFIGURATION

VirusTotal
[Configured / Not Configured]

AbuseIPDB
[Configured / Not Configured]

GeoIP
[Configured / Not Configured]

WHOIS/DNS
[Configured / Not Configured]

Do NOT expose secret values.

Only show:

Configured
Not Configured


==================================================
17. IMPORTANT DEMO + REAL MODE
==================================================

PRAHARI must support TWO modes:

A. DEMO MODE

Uses deterministic demo investigation:

PRH-2026-001
91/100
HIGH RISK

B. REAL ANALYSIS MODE

Uses the actual uploaded email and dynamically retrieves
real intelligence.

Clearly label the current mode:

DEMO MODE

or

LIVE ANALYSIS


==================================================
18. NO FALSE DATA
==================================================

This is extremely important.

Never invent:

• IP reputation
• Geo location
• ASN
• ISP
• WHOIS
• DNS
• VirusTotal results
• AbuseIPDB results

If unavailable, show:

"Data unavailable from configured sources."

Do not replace missing live data with fake data.

Local IOC fallback can only be used when the indicator exists
in the local database.

==================================================
19. FINAL USER EXPERIENCE
==================================================

The user should be able to:

1. Upload ANY .EML.
2. Click Analyze.
3. Wait for processing.
4. See extracted IOCs.
5. See authentication results.
6. See live threat intelligence where available.
7. See GeoIP for public IPs.
8. See ASN / ISP / network context.
9. See reputation.
10. See evidence graph.
11. See dynamic risk score.
12. See MITRE mapping where supported.
13. Generate the forensic report.

No manual IOC entry should be required.

No requirement that the IOC already exists in the local database.

The user uploads the email.

PRAHARI does the investigation.

==================================================
FINAL ACCEPTANCE TEST
==================================================

Test at least three different .EML files:

TEST 1:
Email containing public IP + URL + domain.

Expected:
IOC extraction + GeoIP + threat intelligence + risk analysis.

TEST 2:
Legitimate email.

Expected:
LOW RISK / CLEAN with extracted indicators and available context.

TEST 3:
Suspicious phishing email.

Expected:
Suspicious / HIGH RISK with evidence-backed reasoning.

The system must work dynamically for all three.

FINAL PRINCIPLE:

"LOCAL IOC DATABASE IS A FALLBACK,
NOT A REQUIREMENT."

PRAHARI should investigate the email,
not ask the user to manually provide intelligence.