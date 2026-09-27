export interface LocalIOCRecord {
  type: 'IP' | 'DOMAIN' | 'URL';
  value: string;
  reputation: number;
  tags: string[];
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  asn?: string;
  asnName?: string;
  isp?: string;
  networkType?: string;
  firstSeen?: string;
  lastSeen?: string;
  totalReports?: number;
  whoisRegistrar?: string;
  whoisCreated?: string;
}

export const LOCAL_IOC_DB: LocalIOCRecord[] = [
  {
    type: 'IP', value: '185.220.101.47', reputation: 98,
    tags: ['Tor Exit Node', 'Phishing Infrastructure', 'Known Malicious', 'Bulletproof Hosting'],
    country: 'Germany', countryCode: 'DE', region: 'Bavaria', city: 'Munich',
    asn: 'AS5607', asnName: 'Sky UK Limited (Tor relay)', isp: 'Tor Project Infrastructure',
    networkType: 'Tor Exit Node / Anonymization', firstSeen: '2023-04-12', lastSeen: '2026-09-04', totalReports: 847,
  },
  {
    type: 'IP', value: '194.165.16.11', reputation: 87,
    tags: ['Spam Source', 'Phishing Infrastructure', 'Known Malicious'],
    country: 'Russia', countryCode: 'RU', region: 'Moscow', city: 'Moscow',
    asn: 'AS201814', asnName: 'MEVSPACE sp. z o.o.', isp: 'MEVSPACE',
    networkType: 'Bulletproof Hosting', firstSeen: '2024-01-15', totalReports: 234,
  },
  {
    type: 'IP', value: '91.108.4.40', reputation: 45,
    tags: ['Suspicious Activity', 'Watchlist'],
    country: 'Netherlands', countryCode: 'NL', asn: 'AS62041',
    asnName: 'Telegram Networks', networkType: 'Commercial Hosting', totalReports: 12,
  },
  {
    type: 'IP', value: '45.142.212.100', reputation: 82,
    tags: ['BEC Infrastructure', 'Business Email Compromise', 'Malicious'],
    country: 'Ukraine', countryCode: 'UA',
    asn: 'AS204957', asnName: 'Serverius B.V.', networkType: 'VPS / Cloud Hosting', totalReports: 67,
  },
  {
    type: 'IP', value: '23.106.122.234', reputation: 76,
    tags: ['C2 Server', 'Phishing Infrastructure'],
    country: 'United States', countryCode: 'US', region: 'California', city: 'Los Angeles',
    asn: 'AS8560', asnName: 'IONOS SE', networkType: 'VPS / Cloud Hosting', totalReports: 102,
  },
  {
    type: 'DOMAIN', value: 'paypa1-notifications.com', reputation: 91,
    tags: ['Typosquatting', 'Brand Impersonation', 'PayPal Lookalike', 'Newly Registered'],
    whoisRegistrar: 'Namecheap Inc.', whoisCreated: '2026-09-02',
    firstSeen: '2026-09-02', lastSeen: '2026-09-05', totalReports: 23,
  },
  {
    type: 'DOMAIN', value: 'paypa1-verify-account.net', reputation: 97,
    tags: ['Phishing Page', 'Credential Harvester', 'Active Campaign', 'Newly Registered'],
    whoisRegistrar: 'PDR Ltd.', whoisCreated: '2026-09-02',
    firstSeen: '2026-09-02', lastSeen: '2026-09-05', totalReports: 156,
  },
  {
    type: 'DOMAIN', value: 'secure-paypa1-verify.net', reputation: 93,
    tags: ['Phishing Domain', 'Reply Harvester', 'Lookalike Domain'],
    firstSeen: '2026-09-02', totalReports: 34,
  },
  {
    type: 'DOMAIN', value: 'microsofft-login.com', reputation: 88,
    tags: ['Typosquatting', 'Microsoft Impersonation', 'O365 Phishing'],
    firstSeen: '2026-07-14', totalReports: 89,
  },
  {
    type: 'DOMAIN', value: 'invoice-secure-portal.net', reputation: 72,
    tags: ['Invoice Fraud', 'BEC Infrastructure', 'Suspicious'],
    firstSeen: '2026-08-01', totalReports: 18,
  },
];

export function lookupIOC(value: string): LocalIOCRecord | null {
  const normalized = value.toLowerCase().trim();
  return LOCAL_IOC_DB.find(r =>
    r.value.toLowerCase() === normalized ||
    normalized.includes(r.value.toLowerCase()) ||
    r.value.toLowerCase().includes(normalized)
  ) || null;
}
