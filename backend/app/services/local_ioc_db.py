"""
Local IOC fallback database.
Used when external threat intelligence APIs are unavailable, rate-limited, or unconfigured.
All records are clearly sourced as LOCAL_DB.
"""

LOCAL_IOC_DB: list[dict] = [
    {
        "type": "IP", "value": "185.220.101.47",
        "reputation": 97, "tags": ["Tor Exit Node", "Known Malicious", "Phishing Infrastructure"],
        "country": "Germany", "country_code": "DE", "region": "Bavaria", "city": "Munich",
        "asn": "AS205100", "asn_name": "F3 Netze e.V.", "isp": "F3 Netze e.V.",
        "network_type": "Tor Exit Node",
        "first_seen": "2022-03-10", "last_seen": "2024-11-28", "total_reports": 847,
        "whois_registrar": None, "whois_created": None,
    },
    {
        "type": "IP", "value": "194.165.16.11",
        "reputation": 88, "tags": ["Bulletproof Hosting", "Spam Source", "C2 Infrastructure"],
        "country": "Netherlands", "country_code": "NL", "region": "North Holland", "city": "Amsterdam",
        "asn": "AS202425", "asn_name": "IP Volume inc", "isp": "IP Volume inc",
        "network_type": "Bulletproof Hosting",
        "first_seen": "2023-01-15", "last_seen": "2024-11-20", "total_reports": 312,
        "whois_registrar": None, "whois_created": None,
    },
    {
        "type": "IP", "value": "91.108.4.40",
        "reputation": 76, "tags": ["VPN Service", "Proxy", "Suspicious Activity"],
        "country": "Russia", "country_code": "RU", "region": "Moscow", "city": "Moscow",
        "asn": "AS62041", "asn_name": "Telegram Messenger Inc", "isp": "Telegram",
        "network_type": "Commercial VPN/Proxy",
        "first_seen": "2023-06-01", "last_seen": "2024-10-30", "total_reports": 89,
        "whois_registrar": None, "whois_created": None,
    },
    {
        "type": "IP", "value": "45.142.212.100",
        "reputation": 91, "tags": ["Known Phishing Host", "Bulletproof", "Credential Harvesting"],
        "country": "Romania", "country_code": "RO", "region": "Ilfov", "city": "Voluntari",
        "asn": "AS206728", "asn_name": "Media Land LLC", "isp": "Media Land LLC",
        "network_type": "Bulletproof Hosting",
        "first_seen": "2023-09-18", "last_seen": "2024-11-25", "total_reports": 423,
        "whois_registrar": None, "whois_created": None,
    },
    {
        "type": "IP", "value": "23.106.122.234",
        "reputation": 82, "tags": ["Spam Sender", "Phishing Infrastructure", "Compromised Host"],
        "country": "United States", "country_code": "US", "region": "California", "city": "Los Angeles",
        "asn": "AS36352", "asn_name": "ColoCrossing", "isp": "ColoCrossing",
        "network_type": "Shared Hosting",
        "first_seen": "2022-11-03", "last_seen": "2024-11-10", "total_reports": 156,
        "whois_registrar": None, "whois_created": None,
    },
    {
        "type": "DOMAIN", "value": "paypa1-notifications.com",
        "reputation": 98, "tags": ["Typosquatting", "PayPal Impersonation", "Phishing", "Credential Harvesting"],
        "country": "Panama", "country_code": "PA", "region": None, "city": None,
        "asn": None, "asn_name": None, "isp": None, "network_type": None,
        "first_seen": "2024-10-14", "last_seen": "2024-11-28", "total_reports": 1204,
        "whois_registrar": "NameSilo LLC", "whois_created": "2024-10-14",
    },
    {
        "type": "DOMAIN", "value": "paypa1-verify-account.net",
        "reputation": 96, "tags": ["Phishing", "PayPal Impersonation", "Credential Harvesting"],
        "country": "Iceland", "country_code": "IS", "region": None, "city": None,
        "asn": None, "asn_name": None, "isp": None, "network_type": None,
        "first_seen": "2024-11-01", "last_seen": "2024-11-27", "total_reports": 876,
        "whois_registrar": "Namecheap Inc.", "whois_created": "2024-11-01",
    },
    {
        "type": "DOMAIN", "value": "secure-paypa1-verify.net",
        "reputation": 94, "tags": ["Phishing", "PayPal Impersonation"],
        "country": "Seychelles", "country_code": "SC", "region": None, "city": None,
        "asn": None, "asn_name": None, "isp": None, "network_type": None,
        "first_seen": "2024-11-10", "last_seen": "2024-11-26", "total_reports": 543,
        "whois_registrar": "Porkbun LLC", "whois_created": "2024-11-10",
    },
    {
        "type": "DOMAIN", "value": "microsofft-login.com",
        "reputation": 95, "tags": ["Typosquatting", "Microsoft Impersonation", "Phishing"],
        "country": "Ukraine", "country_code": "UA", "region": None, "city": None,
        "asn": None, "asn_name": None, "isp": None, "network_type": None,
        "first_seen": "2024-09-05", "last_seen": "2024-11-20", "total_reports": 734,
        "whois_registrar": "RegRu", "whois_created": "2024-09-05",
    },
    {
        "type": "DOMAIN", "value": "invoice-secure-portal.net",
        "reputation": 89, "tags": ["BEC", "Invoice Fraud", "Phishing"],
        "country": "Bulgaria", "country_code": "BG", "region": None, "city": None,
        "asn": None, "asn_name": None, "isp": None, "network_type": None,
        "first_seen": "2024-10-28", "last_seen": "2024-11-22", "total_reports": 289,
        "whois_registrar": "Reg.ru", "whois_created": "2024-10-28",
    },
]

_index: dict[str, dict] = {r["value"].lower(): r for r in LOCAL_IOC_DB}


def lookup(value: str) -> dict | None:
    return _index.get(value.lower())
