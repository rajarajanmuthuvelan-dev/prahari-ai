/**
 * Browser-side GeoIP + Network Intelligence module.
 * Priority: ipwho.is → ip-api.com → null
 * PTR lookup via dns.google DoH API.
 * Never queries public services for private/reserved IPs.
 */
import { isPublicIPAddress, normalizeIPAddress } from './ioc-normalizer';

export type InfraType =
  | 'Residential' | 'Business' | 'Hosting / Data Center' | 'Cloud'
  | 'VPN / Proxy' | 'Tor Exit' | 'Educational' | 'Government'
  | 'Mobile / Carrier' | 'Unknown';

export type GeoConfidence = 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

export interface GeoResult {
  // Geographic
  country: string;
  countryCode: string;
  region?: string;
  city?: string;
  postalCode?: string;
  timezone?: string;
  lat?: number;
  lon?: number;
  accuracyNote: string; // always "Approximate" per spec
  // Network
  asn: string;
  asnName: string;
  isp?: string;
  org?: string;
  network?: string;       // CIDR block when available
  networkType?: string;
  infraType: InfraType;
  // Intelligence
  reverseDns?: string;    // PTR record value or "No PTR record found"
  geoConfidence: GeoConfidence;
  source: string;
  provider: string;
  status: 'FOUND' | 'NOT_FOUND' | 'UNAVAILABLE' | 'TIMEOUT' | 'ERROR';
  checkedAt: string;
  providerResults: Record<string, Record<string, unknown>>;
  disagreements: Record<string, Record<string, string | number | null>>;
  fetchedAt: number;      // epoch ms for TTL awareness
}

// ── IP Classification ──────────────────────────────────────────────────────

const PRIVATE_RANGES: RegExp[] = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,   // RFC 6598 CGN
  /^198\.51\.100\./,    // RFC 5737 documentation
  /^203\.0\.113\./,     // RFC 5737 documentation
  /^192\.0\.2\./,       // RFC 5737 documentation
  /^192\.88\.99\./,     // 6to4 relay (deprecated)
  /^198\.18\./,         // benchmarking
  /^198\.19\./,
  // IPv6 private / special
  /^::1$/,
  /^fc[0-9a-f]{2}:/i,
  /^fd[0-9a-f]{2}:/i,
  /^fe80:/i,
  /^::$/,
];

const MULTICAST_RE = [
  /^2(2[4-9]|3\d)\./,   // 224.0.0.0 – 239.255.255.255
  /^ff[0-9a-f]{2}:/i,   // IPv6 multicast
];

const LOOPBACK_RE = [/^127\./, /^::1$/];

export type IPClass = 'PUBLIC' | 'PRIVATE' | 'LOOPBACK' | 'MULTICAST' | 'RESERVED';

export function classifyIP(ip: string): IPClass {
  const normalized = normalizeIPAddress(ip);
  if (!normalized) return 'RESERVED';
  if (LOOPBACK_RE.some(r => r.test(normalized))) return 'LOOPBACK';
  if (MULTICAST_RE.some(r => r.test(normalized))) return 'MULTICAST';
  if (!isPublicIPAddress(normalized)) {
    return PRIVATE_RANGES.some(r => r.test(normalized)) ? 'PRIVATE' : 'RESERVED';
  }
  return 'PUBLIC';
}

export function isPrivateIP(ip: string): boolean {
  return !isPublicIPAddress(ip);
}

// ── Infrastructure Type ────────────────────────────────────────────────────

function classifyInfra(networkType?: string, org?: string, asnName?: string): InfraType {
  const hay = `${networkType ?? ''} ${org ?? ''} ${asnName ?? ''}`.toLowerCase();
  if (/tor\b|onion/.test(hay)) return 'Tor Exit';
  if (/vpn|proxy|anonymi|hide|tunnel/.test(hay)) return 'VPN / Proxy';
  if (/amazon|aws|azure|google cloud|gcp|digitalocean|linode|vultr|ovh|hetzner|cloudflare|fastly|akamai|cdn/.test(hay)) return 'Cloud';
  if (/datacenter|data.?center|hosting|coloc|colo|server|dedicated|vps/.test(hay)) return 'Hosting / Data Center';
  if (/mobile|wireless|lte|5g|4g|gsm|cellular|carrier/.test(hay)) return 'Mobile / Carrier';
  if (/university|college|edu|academic|school/.test(hay)) return 'Educational';
  if (/government|gov\b|ministry|defence|defense|military/.test(hay)) return 'Government';
  if (networkType === 'isp' || /telecom|broadband|internet service|cable/.test(hay)) return 'Business';
  if (networkType === 'residential') return 'Residential';
  if (networkType === 'business') return 'Business';
  return 'Unknown';
}

// ── Geo Confidence ────────────────────────────────────────────────────────

// ── Cache with TTL ────────────────────────────────────────────────────────

const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes
const _cache = new Map<string, GeoResult>();
const _cacheTime = new Map<string, number>();

// ── PTR / Reverse DNS ─────────────────────────────────────────────────────

async function lookupPTR(ip: string): Promise<string> {
  try {
    // Build reverse-lookup name: e.g. 1.2.3.4 → 4.3.2.1.in-addr.arpa
    const ptr = ip.includes(':')
      ? ip // IPv6 PTR is complex — skip for now
      : ip.split('.').reverse().join('.') + '.in-addr.arpa';

    const r = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(ptr)}&type=PTR`,
      { signal: AbortSignal.timeout(4000) },
    );
    if (!r.ok) return 'No PTR record found';
    const d = await r.json();
    const ans = (d.Answer ?? []).find((a: { type: number }) => a.type === 12);
    return ans ? String(ans.data).replace(/\.$/, '') : 'No PTR record found';
  } catch {
    return 'No PTR record found';
  }
}

// ── DNS A/AAAA/MX/NS resolution for domains ──────────────────────────────

export interface DnsRecords {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  cname?: string;
}

const _dnsCache = new Map<string, DnsRecords>();

export async function resolveDomain(domain: string): Promise<DnsRecords> {
  if (_dnsCache.has(domain)) return _dnsCache.get(domain)!;

  const query = async (type: string): Promise<string[]> => {
    try {
      const r = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
        { signal: AbortSignal.timeout(4000) },
      );
      if (!r.ok) return [];
      const d = await r.json();
      return (d.Answer ?? []).map((a: { data: string }) => String(a.data).replace(/\.$/, ''));
    } catch { return []; }
  };

  const [a, aaaa, mx, ns, cname] = await Promise.all([
    query('A'), query('AAAA'), query('MX'), query('NS'), query('CNAME'),
  ]);

  const result: DnsRecords = { a, aaaa, mx, ns, cname: cname[0] };
  _dnsCache.set(domain, result);
  return result;
}

// ── GeoIP Providers ───────────────────────────────────────────────────────

interface GeoProviderAttempt {
  provider: string;
  status: GeoResult['status'];
  checkedAt: string;
  data?: Partial<GeoResult>;
}

function fetchFailureStatus(error: unknown): GeoResult['status'] {
  return error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name)
    ? 'TIMEOUT'
    : 'ERROR';
}

async function tryIpwhoIs(ip: string): Promise<GeoProviderAttempt> {
  const provider = 'ipwho.is';
  try {
    const r = await fetch(`https://ipwho.is/${ip}`, { signal: AbortSignal.timeout(6000) });
    const checkedAt = new Date().toISOString();
    if (!r.ok) return { provider, status: r.status === 404 ? 'NOT_FOUND' : 'ERROR', checkedAt };
    const d = await r.json();
    if (!d.success) return { provider, status: 'NOT_FOUND', checkedAt };
    return { provider, status: 'FOUND', checkedAt, data: {
      country: d.country || '',
      countryCode: d.country_code || '',
      region: d.region || undefined,
      city: d.city || undefined,
      postalCode: d.postal || undefined,
      timezone: d.timezone?.id || undefined,
      lat: typeof d.latitude === 'number' ? d.latitude : undefined,
      lon: typeof d.longitude === 'number' ? d.longitude : undefined,
      asn: d.connection?.asn ? `AS${d.connection.asn}` : '',
      asnName: d.connection?.org || '',
      isp: d.connection?.isp || undefined,
      org: d.connection?.org || undefined,
      source: provider,
    } };
  } catch (error) {
    return { provider, status: fetchFailureStatus(error), checkedAt: new Date().toISOString() };
  }
}

async function tryIpApiCom(ip: string): Promise<GeoProviderAttempt> {
  const provider = 'ip-api.com';
  try {
    const r = await fetch(
      `https://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,zip,timezone,lat,lon,as,isp,org,mobile,hosting,proxy`,
      { signal: AbortSignal.timeout(6000) },
    );
    const checkedAt = new Date().toISOString();
    if (!r.ok) return { provider, status: r.status === 404 ? 'NOT_FOUND' : 'ERROR', checkedAt };
    const d = await r.json();
    if (d.status !== 'success') return { provider, status: 'NOT_FOUND', checkedAt };
    // Derive networkType hint from ip-api flags
    let networkType: string | undefined;
    if (d.hosting) networkType = 'hosting';
    else if (d.proxy) networkType = 'proxy';
    else if (d.mobile) networkType = 'mobile';
    return { provider, status: 'FOUND', checkedAt, data: {
      country: d.country || '',
      countryCode: d.countryCode || '',
      region: d.regionName || undefined,
      city: d.city || undefined,
      postalCode: d.zip || undefined,
      timezone: d.timezone || undefined,
      lat: d.lat,
      lon: d.lon,
      asn: (d.as || '').split(' ')[0],
      asnName: d.org || '',
      isp: d.isp || undefined,
      org: d.org || undefined,
      networkType,
      source: provider,
    } };
  } catch (error) {
    return { provider, status: fetchFailureStatus(error), checkedAt: new Date().toISOString() };
  }
}

// ── Public API ────────────────────────────────────────────────────────────

export async function lookupGeoIP(ip: string): Promise<GeoResult | null> {
  if (isPrivateIP(ip)) return null;

  const cached = _cache.get(ip);
  const cachedAt = _cacheTime.get(ip) ?? 0;
  if (_cache.has(ip) && Date.now() - cachedAt < CACHE_TTL_MS) return cached ?? null;

  const attempts = await Promise.all([tryIpwhoIs(ip), tryIpApiCom(ip)]);
  const providerResults = Object.fromEntries(attempts.map(attempt => [
    attempt.provider,
    { status: attempt.status, checked_at: attempt.checkedAt, ...(attempt.data || {}) },
  ]));
  const found = attempts.filter(attempt => attempt.status === 'FOUND' && attempt.data);
  const partial = found[0]?.data;
  const disagreements: Record<string, Record<string, string | number | null>> = {};
  const comparedFields = ['country', 'countryCode', 'region', 'city', 'asn', 'asnName', 'isp'] as const;
  for (const field of comparedFields) {
    const values = found
      .filter(attempt => attempt.data?.[field] !== undefined && attempt.data[field] !== '')
      .map(attempt => [attempt.provider, attempt.data?.[field] as string | number]);
    if (new Set(values.map(([, value]) => value)).size > 1) {
      disagreements[field] = Object.fromEntries(values);
    }
  }
  const timestamps = attempts.map(attempt => attempt.checkedAt).sort();
  const checkedAt = timestamps[timestamps.length - 1] ?? new Date().toISOString();
  if (!partial) {
    const status: GeoResult['status'] =
      attempts.find(attempt => attempt.status === 'TIMEOUT')?.status ??
      attempts.find(attempt => attempt.status === 'ERROR')?.status ??
      (attempts.every(attempt => attempt.status === 'NOT_FOUND') ? 'NOT_FOUND' : 'UNAVAILABLE');
    const unavailable: GeoResult = {
      country: '', countryCode: '', accuracyNote: 'Not available',
      asn: '', asnName: '', infraType: 'Unknown', geoConfidence: 'NONE',
      source: 'UNAVAILABLE', provider: attempts.map(attempt => attempt.provider).join(', '),
      status, checkedAt, providerResults, disagreements, fetchedAt: Date.now(),
    };
    _cache.set(ip, unavailable);
    _cacheTime.set(ip, Date.now());
    return unavailable;
  }

  // Concurrent PTR lookup — does not block geo result
  const ptrPromise = lookupPTR(ip);

  const infraType = classifyInfra(partial.networkType, partial.org, partial.asnName);
  const result: GeoResult = {
    country: partial.country ?? '',
    countryCode: partial.countryCode ?? '',
    region: partial.region,
    city: partial.city,
    postalCode: partial.postalCode,
    timezone: partial.timezone,
    lat: partial.lat,
    lon: partial.lon,
    accuracyNote: 'Approximate',
    asn: partial.asn ?? '',
    asnName: partial.asnName ?? '',
    isp: partial.isp,
    org: partial.org,
    networkType: partial.networkType,
    infraType,
    geoConfidence: 'NONE',
    reverseDns: await ptrPromise,
    source: `LIVE_GEOIP (${found.map(attempt => attempt.provider).join(' + ')})`,
    provider: found.map(attempt => attempt.provider).join(', '),
    status: 'FOUND',
    checkedAt,
    providerResults,
    disagreements,
    fetchedAt: Date.now(),
  };

  _cache.set(ip, result);
  _cacheTime.set(ip, Date.now());
  return result;
}

export async function lookupGeoIPBatch(ips: string[]): Promise<Map<string, GeoResult | null>> {
  const results = await Promise.all(ips.map(ip => lookupGeoIP(ip).then(r => [ip, r] as const)));
  return new Map(results);
}
