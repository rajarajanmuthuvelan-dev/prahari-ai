CRITICAL ENHANCEMENT — IMPROVE PRAHARI AI GEO / NETWORK INTELLIGENCE

IMPORTANT:
The existing PRAHARI AI investigation process is working correctly.

DO NOT change:
• Email parsing
• IOC extraction
• Threat intelligence workflow
• Risk engine
• Evidence correlation
• MITRE ATT&CK
• Timeline
• Reports
• Demo investigation
• Real-email investigation
• Existing UI structure

ONLY enhance the GEO / NETWORK INTELLIGENCE MODULE.

==================================================
GOAL
==================================================

Make GeoIP intelligence more accurate, useful and evidence-based.

The system must identify:

"Geographic and network context associated with the observed
IP infrastructure."

It must NEVER claim:

"The attacker is located here."

==================================================
1. PUBLIC IP VALIDATION
==================================================

Before performing GeoIP lookup:

• Validate the IP format.
• Detect IPv4 / IPv6.
• Detect private IP.
• Detect loopback IP.
• Detect reserved/documentation IP.
• Detect multicast IP.
• Detect bogon/non-routable IP where possible.

Only perform public GeoIP enrichment for valid publicly routable IPs.

==================================================
2. GEOIP PROVIDER
==================================================

Use a reliable GeoIP provider/database configured on the backend.

Prefer:

MaxMind GeoIP2 / GeoLite2

Use the most specific available record.

Retrieve:

• Country
• Country code
• Region
• City
• Postal code when available
• Latitude
• Longitude
• Timezone

Do NOT invent missing fields.

If a field is unavailable:

"Not available"

==================================================
3. NETWORK INTELLIGENCE
==================================================

For every public IP, enrich network information independently.

Retrieve when available:

• ASN
• ASN organization
• ISP
• Organization
• Network / CIDR
• Hosting provider
• Connection type
• Autonomous system name

Display this separately from geographic information.

==================================================
4. REVERSE DNS
==================================================

Perform reverse DNS / PTR lookup where available.

Show:

Reverse DNS:
mail.example.net

If unavailable:

No PTR record found

Do not treat missing PTR as malicious.

==================================================
5. DNS CONTEXT
==================================================

For extracted domains:

Resolve:

• A
• AAAA
• MX
• NS
• CNAME

Connect the resulting IPs back to the investigation.

Example:

EMAIL
 ↓
DOMAIN
 ↓
DNS
 ↓
IP
 ↓
ASN
 ↓
NETWORK
 ↓
GEO CONTEXT

==================================================
6. GEO CONFIDENCE
==================================================

Do NOT present GeoIP as exact physical location.

Add:

Geo Confidence:
HIGH / MEDIUM / LOW

Base confidence on available provider data and consistency
of the returned network information.

Use wording:

"GeoIP provides an approximate location of the observed
IP infrastructure."

==================================================
7. MULTI-SOURCE CROSS-CHECK
==================================================

Where multiple configured sources are available, compare:

GeoIP
ASN
ISP
Reverse DNS
WHOIS
DNS

If sources agree:

"Network context consistent across sources."

If sources disagree:

"Location/network information differs across sources."

Do NOT silently choose a location and present it as certain.

==================================================
8. INFRASTRUCTURE TYPE
==================================================

Where reliable data is available, classify the observed IP as:

• Residential
• Business
• Hosting / Data Center
• Cloud
• VPN / Proxy
• Tor Exit
• Educational
• Government
• Mobile / Carrier

Only display classifications supported by the available
intelligence source.

Do not infer "VPN" merely because the IP is unfamiliar.

==================================================
9. GEO MAP
==================================================

Add a clean map visualization for public IP infrastructure.

Display:

IP
↓
Approximate Geo
↓
ASN / ISP

Use a marker based on the GeoIP coordinates.

IMPORTANT:

Label the map:

"Approximate infrastructure location"

NOT:

"Attacker Location"

Do not use excessive visual effects.

==================================================
10. MULTIPLE IPs
==================================================

If the email contains multiple public IPs:

Analyze ALL of them.

Example:

IP 1 → India → ASN → ISP
IP 2 → Germany → ASN → ISP
IP 3 → USA → ASN → ISP

Show them separately.

Do NOT merge multiple IPs into one geographic location.

==================================================
11. HEADER PATH ANALYSIS
==================================================

Use Received headers to identify the observable mail-server path.

Example:

Sender
 ↓
Mail Server
 ↓
Relay
 ↓
Observed IP
 ↓
ASN / ISP
 ↓
Geo Context

Clearly distinguish:

"Observed infrastructure"

from:

"Originating sender"

Do not claim the first visible IP is necessarily the attacker's
actual origin.

==================================================
12. GEO + THREAT INTELLIGENCE CORRELATION
==================================================

GeoIP alone must NOT increase the risk score.

Combine infrastructure context with:

• IP reputation
• Domain reputation
• URL reputation
• Authentication results
• Email content
• ASN information
• Network indicators

Example:

Geo:
Germany

ASN:
AS12345

Reputation:
Suspicious

Authentication:
DMARC FAIL

Then:

"Combined evidence increases investigation confidence."

NOT:

"Germany = malicious."

==================================================
13. CACHING
==================================================

Cache successful GeoIP/network results.

Cache key:

IP address

Store:

• Provider
• Timestamp
• Result
• TTL

Use cached results when appropriate.

==================================================
14. FAILURE HANDLING
==================================================

GeoIP failure must NOT stop the investigation.

If GeoIP fails:

Show:

GeoIP:
Unavailable

But continue:

ASN
ISP
DNS
Threat Intelligence
Risk Analysis

Similarly, if ASN lookup fails, GeoIP should continue independently.

==================================================
15. SOURCE TRANSPARENCY
==================================================

Every result must show its source.

Example:

Country:
India

Source:
MaxMind GeoIP

ASN:
ASXXXX

Source:
ASN Lookup

Reverse DNS:
mail.example.com

Source:
PTR / DNS

Never display fabricated sources.

==================================================
16. GEO / NETWORK UI
==================================================

Create a clean structure:

GEOGRAPHIC & NETWORK CONTEXT

┌──────────────────────────────┐
│ OBSERVED IP                  │
│ 185.x.x.x                    │
│ Public IPv4                  │
└──────────────────────────────┘

GEOGRAPHIC CONTEXT

Country
Region
City
Timezone
Approximate Coordinates

NETWORK CONTEXT

ASN
Organization
ISP
Network
Reverse DNS
Infrastructure Type

INTELLIGENCE CONTEXT

IP Reputation
Confidence
Sources

Then:

"GeoIP identifies the geographic and network context associated
with the observed IP infrastructure. It does not identify the
attacker's exact physical location."

==================================================
17. REAL EMAIL REQUIREMENT
==================================================

When a REAL .EML is uploaded:

Do not require the IP to exist in the Local IOC Database.

Automatically:

Extract IP
 ↓
Validate IP
 ↓
Check public/private
 ↓
GeoIP lookup
 ↓
ASN lookup
 ↓
ISP/network lookup
 ↓
Reverse DNS
 ↓
Threat intelligence
 ↓
Correlate with email evidence

The Local IOC Database remains a FALLBACK only.

==================================================
18. DEMO MODE
==================================================

DO NOT change the existing demo investigation.

Demo GeoIP data must remain exactly as currently configured.

This enhancement applies primarily to REAL EMAIL ANALYSIS.

==================================================
19. ACCURACY RULE
==================================================

Never create false precision.

If the provider returns:

Country only

do NOT invent:

City
Street
Exact coordinates

If coordinates are approximate, label them:

"Approximate"

If no reliable geographic information exists:

"Geographic location unavailable"

==================================================
20. FINAL ACCEPTANCE TEST
==================================================

Test with a real .EML containing public IP addresses.

Verify:

✓ IP automatically extracted
✓ Public/private classification works
✓ GeoIP lookup runs automatically
✓ Country shown when available
✓ Region shown when available
✓ City shown when available
✓ ASN shown when available
✓ ISP shown when available
✓ Reverse DNS checked
✓ Network information shown
✓ Source shown
✓ Confidence shown
✓ Multiple IPs handled
✓ Evidence graph updated
✓ No manual IOC entry required
✓ Local IOC database is NOT required
✓ GeoIP failure does NOT stop investigation
✓ No false attacker-location claim
✓ Existing investigation process remains unchanged

FINAL INSTRUCTION:

THIS IS A GEO / NETWORK INTELLIGENCE ENHANCEMENT ONLY.

DO NOT MODIFY THE EXISTING INVESTIGATION PIPELINE.

DO NOT MODIFY THE WORKING DEMO.

DO NOT MODIFY RISK SCORING EXCEPT TO ENSURE GEOIP ALONE
CANNOT MAKE AN EMAIL MALICIOUS.

MAKE GEO / NETWORK INTELLIGENCE RICHER, MORE ACCURATE,
MORE TRANSPARENT AND MORE FORENSICALLY RESPONSIBLE.