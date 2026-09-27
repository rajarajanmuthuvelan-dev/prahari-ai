import { ParsedEmail, EmailHeader, Attachment, ReceivedHeader } from '../types';
import { extractValidIPs, normalizeDomain, normalizeIPAddress } from './ioc-normalizer';

function parseHeaderSection(raw: string): EmailHeader[] {
  const headers: EmailHeader[] = [];
  const lines = raw.split(/\r?\n/);
  let cur: EmailHeader | null = null;
  for (const line of lines) {
    if (/^\s+/.test(line) && cur) {
      cur.value += ' ' + line.trim();
    } else {
      const m = line.match(/^([^:]+):\s*(.*)/);
      if (m) {
        if (cur) headers.push(cur);
        cur = { name: m[1].trim(), value: m[2].trim() };
      }
    }
  }
  if (cur) headers.push(cur);
  return headers;
}

function getHeader(headers: EmailHeader[], name: string): string | undefined {
  return headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value;
}

function normalizeReceivedHost(value: string): string | undefined {
  const candidate = value.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const ip = normalizeIPAddress(candidate);
  if (ip) return ip;
  if (
    !candidate ||
    candidate.length > 253 ||
    candidate.includes(':') ||
    /^\d+(?:\.\d+)*$/.test(candidate)
  ) {
    return undefined;
  }
  const hostname = candidate.toLowerCase();
  const labels = hostname.split('.');
  if (
    labels.some(
      label =>
        !/^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(label) ||
        label.length > 63,
    )
  ) {
    return undefined;
  }
  return normalizeDomain(hostname) || hostname;
}

function parseReceivedHeader(value: string): ReceivedHeader {
  const separator = value.lastIndexOf(';');
  const route = separator >= 0 ? value.slice(0, separator) : value;
  const rawTimestamp = separator >= 0 ? value.slice(separator + 1).trim() : '';
  const hosts: Pick<ReceivedHeader, 'fromHost' | 'byHost'> = {};
  const hostPattern = /\b(from|by)\s+(\[[^\]]+\]|[^\s(;]+)(?=\s|\(|;|$)/gi;

  for (const match of route.matchAll(hostPattern)) {
    const host = normalizeReceivedHost(match[2]);
    if (host) {
      const key = match[1].toLowerCase() === 'from' ? 'fromHost' : 'byHost';
      hosts[key] = host;
    }
  }

  const timestamp =
    /\b\d{4}\b/.test(rawTimestamp) && Number.isFinite(Date.parse(rawTimestamp))
    ? new Date(rawTimestamp).toISOString()
    : undefined;
  return { ...hosts, timestamp, ips: extractValidIPs(route) };
}

function extractURLs(text: string): string[] {
  const rx = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  const urls: string[] = [];
  let m;
  while ((m = rx.exec(text)) !== null) {
    const url = m[0].replace(/[.,;!?)]+$/, '');
    if (!urls.includes(url)) urls.push(url);
  }
  return urls;
}

function extractEmails(text: string): string[] {
  const rx = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
  const found: string[] = [];
  let m;
  while ((m = rx.exec(text)) !== null) {
    if (!found.includes(m[0])) found.push(m[0]);
  }
  return found;
}

function decodeMimeWord(str: string): string {
  return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g, (_, _cs, enc, encoded) => {
    try {
      if (enc.toUpperCase() === 'B') return atob(encoded);
      return encoded.replace(/_/g, ' ').replace(/=([A-Fa-f0-9]{2})/g, (_e: string, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    } catch { return encoded; }
  });
}

function decodeTransferEncoding(body: string, encoding: string): string {
  const enc = encoding.toLowerCase().trim();
  if (enc === 'quoted-printable') {
    return body.replace(/=\r?\n/g, '').replace(/=([A-Fa-f0-9]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
  if (enc === 'base64') {
    try { return atob(body.replace(/\s/g, '')); } catch { return body; }
  }
  return body;
}

interface MimePart { headers: EmailHeader[]; body: string; }

function parseMimeParts(content: string, boundary: string): MimePart[] {
  const escaped = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const boundaryRx = new RegExp(`\\r?\\n--${escaped}(?:--)?(?:\\r?\\n|$)`);
  const sections = ('\n' + content).split(boundaryRx);
  const parts: MimePart[] = [];
  for (let i = 1; i < sections.length; i++) {
    const sec = sections[i];
    if (!sec || sec.trim() === '') continue;
    const splitIdx = sec.search(/\r?\n\r?\n/);
    if (splitIdx === -1) continue;
    const headerStr = sec.substring(0, splitIdx);
    const body = sec.substring(splitIdx).replace(/^\r?\n/, '');
    parts.push({ headers: parseHeaderSection(headerStr), body });
  }
  return parts;
}

export function parseEML(raw: string): ParsedEmail {
  const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const splitIdx = normalized.indexOf('\n\n');
  const headerStr = splitIdx >= 0 ? normalized.substring(0, splitIdx) : normalized;
  const bodyStr = splitIdx >= 0 ? normalized.substring(splitIdx + 2) : '';

  const headers = parseHeaderSection(headerStr);
  const contentType = getHeader(headers, 'Content-Type') || 'text/plain';
  const transferEnc = getHeader(headers, 'Content-Transfer-Encoding') || '';

  let bodyText = '';
  let bodyHtml: string | undefined;
  const attachments: Attachment[] = [];

  const boundaryMatch = contentType.match(/boundary="?([^";]+)"?/i);

  if (boundaryMatch) {
    const boundary = boundaryMatch[1].trim();
    const parts = parseMimeParts(bodyStr, boundary);

    for (const part of parts) {
      const partCT = getHeader(part.headers, 'Content-Type') || 'text/plain';
      const partEnc = getHeader(part.headers, 'Content-Transfer-Encoding') || '';
      const partDisp = getHeader(part.headers, 'Content-Disposition') || '';
      const decoded = decodeTransferEncoding(part.body, partEnc);

      if (partDisp.toLowerCase().includes('attachment')) {
        const fnMatch = partDisp.match(/filename="?([^";]+)"?/i) || partCT.match(/name="?([^";]+)"?/i);
        attachments.push({
          filename: fnMatch ? fnMatch[1].trim() : 'unknown',
          contentType: partCT.split(';')[0].trim(),
          size: Math.round(part.body.replace(/\s/g, '').length * 0.75),
        });
      } else if (partCT.toLowerCase().includes('text/html')) {
        bodyHtml = decoded;
        if (!bodyText) bodyText = decoded.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      } else if (partCT.toLowerCase().includes('text/plain')) {
        bodyText = decoded;
      }
    }
  } else {
    const decoded = decodeTransferEncoding(bodyStr, transferEnc);
    if (contentType.toLowerCase().includes('text/html')) {
      bodyHtml = decoded;
      bodyText = decoded.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    } else {
      bodyText = decoded;
    }
  }

  const from = decodeMimeWord(getHeader(headers, 'From') || '');
  const fromNameMatch = from.match(/^"?([^"<]+?)"?\s*</);

  const receivedPath = headers
    .filter(h => h.name.toLowerCase() === 'received')
    .map(h => parseReceivedHeader(h.value));
  const receivedIPs = [...new Set(receivedPath.flatMap(header => header.ips))];
  const xOrig = getHeader(headers, 'X-Originating-IP');
  const originatingIPs = xOrig ? extractValidIPs(xOrig) : [];
  for (const ip of originatingIPs) {
    if (!receivedIPs.includes(ip)) receivedIPs.push(ip);
  }

  const allText = bodyText + ' ' + (bodyHtml || '');
  const urls = extractURLs(allText);
  const emailAddresses = extractEmails(
    (getHeader(headers, 'From') || '') +
      ' ' +
      (getHeader(headers, 'To') || '') +
      ' ' +
      (getHeader(headers, 'Reply-To') || '') +
      ' ' +
      bodyText
  );

  return {
    from,
    fromName: fromNameMatch ? fromNameMatch[1].trim() : undefined,
    to: decodeMimeWord(getHeader(headers, 'To') || ''),
    subject: decodeMimeWord(getHeader(headers, 'Subject') || ''),
    date: getHeader(headers, 'Date') || '',
    replyTo: getHeader(headers, 'Reply-To'),
    messageId: getHeader(headers, 'Message-ID'),
    headers,
    bodyText,
    bodyHtml,
    attachments,
    receivedIPs,
    receivedPath,
    xOriginatingIP: xOrig,
    urls,
    emailAddresses,
  };
}
