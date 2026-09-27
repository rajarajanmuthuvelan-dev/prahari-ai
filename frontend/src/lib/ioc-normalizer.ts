import type { IOCType } from '../types';

const IPV4_PATTERN = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;
const DOMAIN_LABEL_PATTERN = /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i;
const EMAIL_PATTERN =
  /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const NON_PUBLIC_SUFFIXES = new Set([
  'arpa',
  'example',
  'internal',
  'invalid',
  'lan',
  'local',
  'localhost',
  'test',
]);

export interface NormalizedIOC {
  type: IOCType;
  value: string;
  source: string;
  normalizedValue: string;
  valid: boolean;
  confidence: number;
}

function parseIPv4(value: string): string | null {
  if (!IPV4_PATTERN.test(value)) return null;
  const octets = value.split('.');
  if (octets.some(octet => Number(octet) > 255)) return null;
  return octets.map(Number).join('.');
}

function parseIPv6(value: string): string | null {
  let input = value.toLowerCase();
  if (!input.includes(':') || input.includes('%')) return null;

  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    const ipv4 = parseIPv4(input.slice(lastColon + 1));
    if (!ipv4) return null;
    const octets = ipv4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    input = `${input.slice(0, lastColon)}:${high}:${low}`;
  }

  if ((input.match(/::/g) || []).length > 1) return null;
  const compressed = input.includes('::');
  const [leftText, rightText = ''] = compressed ? input.split('::') : [input, ''];
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const groups = [...left, ...right];
  if (groups.some(group => !/^[\da-f]{1,4}$/.test(group))) return null;
  if ((!compressed && groups.length !== 8) || (compressed && groups.length >= 8)) {
    return null;
  }

  const words = compressed
    ? [...left, ...Array(8 - groups.length).fill('0'), ...right]
    : groups;
  const values = words.map(group => Number.parseInt(group, 16));
  let bestStart = -1;
  let bestLength = 1;
  for (let index = 0; index < values.length;) {
    if (values[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < values.length && values[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }

  const hexWords = values.map(word => word.toString(16));
  if (bestStart < 0) return hexWords.join(':');
  const before = hexWords.slice(0, bestStart).join(':');
  const after = hexWords.slice(bestStart + bestLength).join(':');
  return `${before}::${after}`;
}

export function normalizeIPAddress(value: string): string | null {
  const candidate = value.trim().replace(/^\[|\]$/g, '');
  return parseIPv4(candidate) ?? parseIPv6(candidate);
}

export function extractValidIPs(text: string): string[] {
  const candidatePattern =
    /\[([^\]]+)\]|(?<![A-Za-z0-9:.])([0-9A-Fa-f:.]+)(?![A-Za-z0-9:.])/g;
  const found = new Set<string>();
  for (const match of text.matchAll(candidatePattern)) {
    const normalized = normalizeIPAddress(match[1] || match[2]);
    if (normalized) found.add(normalized);
  }
  return [...found];
}

export function normalizeDomain(value: string): string | null {
  const candidate = value.trim().replace(/\.$/, '');
  if (!candidate || candidate.length > 253 || /[^A-Za-z\d.-]/.test(candidate)) {
    return null;
  }
  const labels = candidate.toLowerCase().split('.');
  if (
    labels.length < 2 ||
    labels.some(label => label.length > 63 || !DOMAIN_LABEL_PATTERN.test(label)) ||
    !/^(?:[a-z]{2,63}|xn--[a-z\d-]{2,59})$/i.test(labels.at(-1) || '')
  ) {
    return null;
  }
  return labels.join('.');
}

export function isPublicIPAddress(value: string): boolean {
  const normalized = normalizeIPAddress(value);
  if (!normalized) return false;

  if (normalized.includes(':')) {
    const groups = normalized.split(':');
    if (groups[0] !== '2' && !/^[23]/.test(groups[0])) return false;
    if (normalized.startsWith('2001:db8:')) return false;
    return true;
  }

  const octets = normalized.split('.').map(Number);
  const [first, second, third] = octets;
  if (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 &&
      (second === 168 ||
        (second === 0 && third <= 2) ||
        (second === 88 && third === 99))) ||
    (first === 198 &&
      (second === 18 || second === 19 || (second === 51 && third === 100))) ||
    (first === 203 && second === 0 && third === 113)
  ) {
    return false;
  }
  return true;
}

export function normalizeIOC(
  type: IOCType,
  value: string,
  source: string,
): NormalizedIOC {
  const original = value;
  const candidate = value.trim();
  let normalizedValue: string | null = null;

  if (type === 'IP') {
    normalizedValue = normalizeIPAddress(candidate);
  } else if (type === 'DOMAIN') {
    normalizedValue = normalizeDomain(candidate);
  } else if (type === 'URL') {
    try {
      const parsed = new URL(candidate);
      const hostname = parsed.hostname.startsWith('[')
        ? normalizeIPAddress(parsed.hostname)
        : normalizeDomain(parsed.hostname);
      if (
        (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
        hostname
      ) {
        normalizedValue = parsed.href;
      }
    } catch {
      normalizedValue = null;
    }
  } else if (type === 'EMAIL' && EMAIL_PATTERN.test(candidate)) {
    const separator = candidate.lastIndexOf('@');
    const domain = normalizeDomain(candidate.slice(separator + 1));
    if (domain) normalizedValue = `${candidate.slice(0, separator)}@${domain}`;
  } else if (
    type === 'HASH' &&
    [32, 40, 64].includes(candidate.length) &&
    /^[A-Fa-f0-9]+$/.test(candidate)
  ) {
    normalizedValue = candidate.toLowerCase();
  }

  const valid = normalizedValue !== null;
  return {
    type,
    value: original,
    source,
    normalizedValue: normalizedValue || candidate,
    valid,
    confidence: valid ? 100 : 0,
  };
}

export function isPublicDomain(value: string): boolean {
  const domain = normalizeDomain(value);
  return Boolean(domain && !NON_PUBLIC_SUFFIXES.has(domain.split('.').at(-1) || ''));
}
