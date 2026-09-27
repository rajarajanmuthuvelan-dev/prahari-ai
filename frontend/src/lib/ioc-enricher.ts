/**
 * Legacy browser-only IOC pipeline. Real uploads use FastAPI; this path still
 * validates and normalizes every indicator before any local or GeoIP lookup.
 */

import { EmailHeader, IOC, IOCIntelligence, IOCType, IOCRisk, ParsedEmail } from '../types';
import { lookupIOC } from '../data/ioc-db';
import { lookupGeoIPBatch, GeoResult } from './geoip-client';
import { iocEvidenceCategory } from './ioc-presentation';
import {
  extractValidIPs,
  isPublicDomain,
  isPublicIPAddress,
  normalizeDomain,
  normalizeIOC,
} from './ioc-normalizer';

function classifyRisk(reputation: number | undefined): IOCRisk {
  if (reputation === undefined) return 'UNKNOWN';
  if (reputation >= 90) return 'CRITICAL';
  if (reputation >= 70) return 'HIGH';
  if (reputation >= 40) return 'MEDIUM';
  return 'LOW';
}

function extractURLHost(url: string): { domain?: string; ip?: string } {
  try {
    const hostname = new URL(url).hostname;
    const ip = normalizeIOC('IP', hostname, 'Email Body URL');
    if (ip.valid) return { ip: ip.normalizedValue };
    return { domain: normalizeDomain(hostname) || undefined };
  } catch {
    return {};
  }
}

function geoToIntelGeo(g: GeoResult): NonNullable<IOCIntelligence['geo']> {
  return {
    country: g.country,
    countryCode: g.countryCode,
    region: g.region,
    city: g.city,
    postalCode: g.postalCode,
    timezone: g.timezone,
    lat: g.lat,
    lon: g.lon,
    accuracyNote: g.accuracyNote,
    asn: g.asn,
    asnName: g.asnName,
    isp: g.isp,
    org: g.org,
    network: g.network,
    networkType: g.networkType,
    infraType: g.infraType,
    reverseDns: g.reverseDns,
    geoConfidence: g.geoConfidence,
    source: g.source,
    provider: g.provider,
    status: g.status,
    checkedAt: g.checkedAt,
    lookupTimestamp: g.checkedAt,
    providerResults: Object.fromEntries(
      Object.entries(g.providerResults).map(([provider, result]) => [provider, result]),
    ),
    disagreements: g.disagreements,
    locationNote: 'Approximate infrastructure location; city-level data is not precise.',
  };
}

let iocCounter = 0;
function makeId(): string {
  return `ioc-${++iocCounter}`;
}

function statusForReputation(
  reputation: number | undefined,
  tags: string[] = [],
  lookupStatus: IOCIntelligence['lookupStatus'] = 'FOUND',
): IOC['status'] {
  if (lookupStatus !== 'FOUND' || reputation === undefined) return 'UNKNOWN';
  const normalizedTags = tags.join(' ').toLowerCase();
  if (/malicious|phishing|credential harvesting|botnet|\bc2\b/.test(normalizedTags)) {
    return 'MALICIOUS';
  }
  if (/suspicious|watchlist|proxy|bulletproof|spam/.test(normalizedTags)) {
    return 'SUSPICIOUS';
  }
  if (reputation >= 90) return 'MALICIOUS';
  if (reputation >= 40) return 'SUSPICIOUS';
  return 'CLEAN';
}

function riskContribution(
  reputation: number | undefined,
  lookupStatus: IOCIntelligence['lookupStatus'],
  reputationStatus: IOC['status'],
): number {
  if (
    lookupStatus !== 'FOUND'
    || reputation === undefined
    || reputationStatus === 'UNKNOWN'
    || reputationStatus === 'CLEAN'
  ) return 0;
  if (reputation >= 90) return 8;
  if (reputation >= 70) return 5;
  if (reputation >= 40) return 2;
  return 0;
}

function sourceForEmailAddress(address: string, headers: EmailHeader[]): string {
  const sourceHeader = headers.find(
    header =>
      ['from', 'to', 'reply-to'].includes(header.name.toLowerCase()) &&
      header.value.includes(address),
  );
  return sourceHeader ? `${sourceHeader.name} Header` : 'Email Body';
}

export async function extractAndEnrichIOCs(email: ParsedEmail): Promise<IOC[]> {
  iocCounter = 0;
  const raw: ReturnType<typeof normalizeIOC>[] = [];
  const seen = new Set<string>();

  const queue = (type: IOCType, value: string, source: string) => {
    const normalized = normalizeIOC(type, value, source);
    if (!normalized.valid) return;
    const canonicalValue = ['IP', 'DOMAIN', 'HASH'].includes(normalized.type)
      ? normalized.normalizedValue.toLowerCase()
      : normalized.normalizedValue;
    const key = `${normalized.type}:${canonicalValue}`;
    if (seen.has(key)) return;
    seen.add(key);
    raw.push(normalized);
  };

  if (email.receivedPath?.length) {
    for (const header of email.receivedPath) {
      for (const ip of header.ips) queue('IP', ip, 'Received Header');
      for (const host of [header.fromHost, header.byHost]) {
        if (host && !normalizeIOC('IP', host, 'Received Header').valid) {
          queue('DOMAIN', host, 'Received Header');
        }
      }
    }
  } else {
    for (const ip of email.receivedIPs) {
      queue('IP', ip, 'Received Header');
    }
  }
  if (email.xOriginatingIP) {
    for (const ip of extractValidIPs(email.xOriginatingIP)) {
      queue('IP', ip, 'X-Originating-IP Header');
    }
  }

  for (const ip of extractValidIPs(`${email.bodyText}\n${email.bodyHtml || ''}`)) {
    queue('IP', ip, 'Email Body');
  }

  const fromDomain = email.from.match(/@([^>@\s,]+)/)?.[1];
  if (fromDomain) queue('DOMAIN', fromDomain, 'From Header');

  if (email.replyTo) {
    const replyDomain = email.replyTo.match(/@([^>@\s,]+)/)?.[1];
    if (replyDomain) queue('DOMAIN', replyDomain, 'Reply-To Header');
  }

  for (const url of email.urls) {
    queue('URL', url, 'Email Body');
    const host = extractURLHost(url);
    if (host.domain) queue('DOMAIN', host.domain, 'Email Body URL');
    if (host.ip) queue('IP', host.ip, 'Email Body URL');
  }

  for (const address of email.emailAddresses) {
    queue('EMAIL', address, sourceForEmailAddress(address, email.headers));
  }

  for (const attachment of email.attachments) {
    if (attachment.sha256) {
      queue('HASH', attachment.sha256, `Attachment: ${attachment.filename}`);
    }
  }

  const publicIPs = raw
    .filter(ioc => ioc.type === 'IP' && isPublicIPAddress(ioc.normalizedValue))
    .map(ioc => ioc.normalizedValue);
  const geoMap = await lookupGeoIPBatch(publicIPs);
  const iocs: IOC[] = [];

  for (const normalized of raw) {
    const { type, value, source, normalizedValue } = normalized;
    let intelligence: IOCIntelligence | undefined;
    let status: IOC['status'] = 'UNKNOWN';
    const checkedAt = new Date().toISOString();

    if (type === 'IP') {
      const publicIP = isPublicIPAddress(normalizedValue);
      const local = lookupIOC(normalizedValue);
      const geo = publicIP ? geoMap.get(normalizedValue) : null;
      const reputation = local?.reputation;
      const lookupStatus = local ? 'FOUND' : 'NOT_FOUND';
      const reputationStatus = statusForReputation(reputation, local?.tags, lookupStatus);
      intelligence = {
        ...(reputation === undefined ? {} : { reputation }),
        reputationStatus,
        riskContribution: riskContribution(reputation, lookupStatus, reputationStatus),
        ...(local?.firstSeen ? { firstSeen: local.firstSeen } : {}),
        ...(local?.lastSeen ? { lastSeen: local.lastSeen } : {}),
        ...(local?.totalReports === undefined ? {} : { totalReports: local.totalReports }),
        tags: local?.tags ?? [],
        ...(geo?.status === 'FOUND' ? { geo: geoToIntelGeo(geo) } : {}),
        ...(geo ? { geoStatus: geo.status, geoLookup: {
          source: geo.source,
          provider: geo.provider,
          status: geo.status,
          checked_at: geo.checkedAt,
          provider_results: geo.providerResults,
          disagreements: geo.disagreements,
        } } : {}),
        ...(local?.whoisRegistrar ? { whoisRegistrar: local.whoisRegistrar } : {}),
        ...(local?.whoisCreated ? { whoisCreated: local.whoisCreated } : {}),
        source: 'LOCAL_DB',
        provider: 'Local IOC Database',
        status: lookupStatus,
        lookupStatus,
        lookupSource: local ? 'Local IOC Database' : 'No reputation result',
        checkedAt,
        lookupTimestamp: checkedAt,
        ...(!publicIP ? { geoStatus: 'UNAVAILABLE' as const } : {}),
      };
      status = reputationStatus;
    } else if (type === 'DOMAIN' || type === 'URL') {
      const domain = type === 'URL' ? extractURLHost(normalizedValue).domain : normalizedValue;
      const local = domain && isPublicDomain(domain) ? lookupIOC(domain) : null;
      const reputation = local?.reputation;
      const lookupStatus = local ? 'FOUND' : 'NOT_FOUND';
      const reputationStatus = statusForReputation(reputation, local?.tags, lookupStatus);
      intelligence = {
        ...(reputation === undefined ? {} : { reputation }),
        reputationStatus,
        riskContribution: riskContribution(reputation, lookupStatus, reputationStatus),
        ...(local?.firstSeen ? { firstSeen: local.firstSeen } : {}),
        ...(local?.lastSeen ? { lastSeen: local.lastSeen } : {}),
        ...(local?.totalReports === undefined ? {} : { totalReports: local.totalReports }),
        tags: local?.tags ?? [],
        ...(local?.whoisRegistrar ? { whoisRegistrar: local.whoisRegistrar } : {}),
        ...(local?.whoisCreated ? { whoisCreated: local.whoisCreated } : {}),
        source: 'LOCAL_DB',
        provider: 'Local IOC Database',
        status: lookupStatus,
        lookupStatus,
        lookupSource: local ? 'Local IOC Database' : 'No reputation result',
        checkedAt,
        lookupTimestamp: checkedAt,
      };
      status = reputationStatus;
    }

    const ioc: IOC = {
      id: makeId(),
      type,
      value,
      normalizedValue,
      valid: true,
      source,
      confidence: normalized.confidence,
      risk: status === 'UNKNOWN' ? 'UNKNOWN' : classifyRisk(intelligence?.reputation),
      status,
      reputationStatus: status === 'PRIVATE' ? 'UNKNOWN' : status,
      riskContribution: intelligence?.riskContribution ?? 0,
      lookupSource: intelligence?.lookupSource || 'No reputation result',
      lookupStatus: intelligence?.lookupStatus || 'UNAVAILABLE',
      geoSource: intelligence?.geo?.source,
      ...(intelligence ? { intelligence } : {}),
    };
    ioc.evidenceCategory = iocEvidenceCategory(ioc);
    iocs.push(ioc);
  }

  return iocs;
}
