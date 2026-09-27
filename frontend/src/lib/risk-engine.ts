import { ParsedEmail, AuthResult, IOC, RiskScore, RiskLevel, AuthStatus, ScoreComponent } from '../types';

function scoreContent(email: ParsedEmail): ScoreComponent {
  const signals: string[] = [];
  let score = 0;
  const body = (email.bodyText + ' ' + email.subject).toLowerCase();

  const urgencyWords = ['urgent', 'immediately', 'asap', 'act now', 'action required', 'verify now',
    'suspended', 'limited time', 'expires', '24 hours', 'account.*closed', 'permanently'];
  const credWords = ['click here', 'log in', 'sign in', 'verify', 'confirm', 'update.*info',
    'enter.*password', 'banking detail', 'account access', 'credential'];
  const threatWords = ['frozen', 'terminated', 'cancelled', 'deleted', 'unauthorized',
    'suspicious activity', 'security alert', 'warning'];

  const count = (words: string[]) => words.reduce((acc, w) => acc + (new RegExp(w, 'i').test(body) ? 1 : 0), 0);

  const urgencyCount = count(urgencyWords);
  const credCount = count(credWords);
  const threatCount = count(threatWords);

  if (urgencyCount > 0) { score += Math.min(7, urgencyCount * 2); signals.push(`Urgency/pressure language (${urgencyCount} pattern${urgencyCount > 1 ? 's' : ''})`); }
  if (credCount > 0) { score += Math.min(5, credCount * 2); signals.push(`Credential-harvesting language (${credCount} pattern${credCount > 1 ? 's' : ''})`); }
  if (threatCount > 0) { score += Math.min(4, threatCount * 2); signals.push(`Threatening consequence language (${threatCount} pattern${threatCount > 1 ? 's' : ''})`); }

  if (email.urls.length > 0) {
    score += 3;
    signals.push(`${email.urls.length} URL(s) present in email body`);
    const hasObfuscated = email.urls.some(u => /[?&](token|redirect|ref|url|goto|return)=/i.test(u));
    if (hasObfuscated) { score += 2; signals.push('URL contains encoded/redirect parameter (obfuscation)'); }
  }

  if (/urgent|action required|immediately/i.test(email.subject)) {
    score += 2;
    signals.push('Subject line contains urgency indicators');
  }

  return { score: Math.min(25, Math.round(score)), max: 25, signals };
}

function scoreAuth(auth: AuthResult): ScoreComponent {
  const signals: string[] = [];
  let score = 0;

  const check = (status: AuthStatus, name: string, failPts: number, passPts: number) => {
    if (status === 'FAIL') { score += failPts; signals.push(`${name}: FAIL`); }
    else if (status === 'PASS') { signals.push(`${name}: PASS`); }
    else if (status === 'NEUTRAL' || status === 'NONE') { score += passPts; signals.push(`${name}: ${status}`); }
    else signals.push(`${name}: Not available`);
  };

  check(auth.spf, 'SPF', 7, 2);
  check(auth.dkim, 'DKIM', 7, 2);
  check(auth.dmarc, 'DMARC', 6, 1);

  return { score: Math.min(20, score), max: 20, signals };
}

function scoreReputation(iocs: IOC[]): ScoreComponent {
  const signals: string[] = [];
  let score = 0;

  for (const ioc of iocs) {
    const rep = ioc.intelligence?.reputation;
    if (
      rep === undefined
      || ioc.reputationStatus === 'UNKNOWN'
      || ioc.reputationStatus === 'CLEAN'
      || ioc.status === 'UNKNOWN'
      || ioc.status === 'CLEAN'
      || ioc.status === 'PRIVATE'
      || (ioc.intelligence?.lookupStatus !== undefined && ioc.intelligence.lookupStatus !== 'FOUND')
    ) continue;
    const label = ioc.value.length > 50 ? ioc.value.substring(0, 48) + '…' : ioc.value;
    if (rep >= 90) { score += 8; signals.push(`${ioc.type} ${label} — MALICIOUS (${rep}% threat score)`); }
    else if (rep >= 70) { score += 5; signals.push(`${ioc.type} ${label} — HIGH RISK (${rep}%)`); }
    else if (rep >= 40) { score += 2; signals.push(`${ioc.type} ${label} — SUSPICIOUS (${rep}%)`); }
  }

  return { score: Math.min(25, score), max: 25, signals };
}

function scoreInfrastructure(email: ParsedEmail, iocs: IOC[]): ScoreComponent {
  const signals: string[] = [];
  let score = 0;

  for (const ioc of iocs) {
    if (ioc.type === 'IP' && ioc.intelligence?.tags) {
      if (ioc.intelligence.tags.some(t => /tor/i.test(t))) {
        score += 6; signals.push(`Tor exit node in sending path: ${ioc.value}`);
      } else if (ioc.intelligence.tags.some(t => /bulletproof/i.test(t))) {
        score += 4; signals.push(`Bulletproof hosting detected: ${ioc.value}`);
      }
    }
    if ((ioc.type === 'DOMAIN') && ioc.intelligence?.firstSeen) {
      const daysOld = Math.floor((Date.now() - new Date(ioc.intelligence.firstSeen).getTime()) / 86400000);
      if (daysOld < 7) {
        score += 5; signals.push(`Domain "${ioc.value}" newly registered (${daysOld}d old)`);
      } else if (daysOld < 30) {
        score += 2; signals.push(`Domain "${ioc.value}" recently registered (${daysOld}d old)`);
      }
    }
  }

  const fromDomain = email.from.match(/@([^>@\s,]+)/)?.[1]?.toLowerCase() || '';
  const brands = [['paypal', 'paypa'], ['microsoft', 'microsof'], ['apple', 'app1e'], ['google', 'g00gle'], ['amazon', 'arnazon']];
  for (const [brand, fake] of brands) {
    if (fromDomain.includes(fake) && !fromDomain.endsWith(brand + '.com')) {
      score += 5; signals.push(`Lookalike/typosquatting domain: "${fromDomain}" impersonating "${brand}"`); break;
    }
  }

  const xMailer = email.headers.find(h => /x-mailer/i.test(h.name))?.value || '';
  if (/bulk|mass|blast|spam/i.test(xMailer)) {
    score += 3; signals.push(`X-Mailer indicates bulk sending tool: ${xMailer}`);
  }

  if (email.replyTo) {
    const fd = email.from.match(/@([^>@\s,]+)/)?.[1];
    const rd = email.replyTo.match(/@([^>@\s,]+)/)?.[1];
    if (fd && rd && fd !== rd) {
      score += 3; signals.push(`Reply-To domain (${rd}) differs from From domain (${fd})`);
    }
  }

  return { score: Math.min(30, score), max: 30, signals };
}

export function parseAuthFromHeaders(headers: { name: string; value: string }[]): AuthResult {
  const authResults = headers.find(h => /^authentication-results$/i.test(h.name))?.value || '';
  const spfHeader = headers.find(h => /^received-spf$/i.test(h.name))?.value || '';

  const parseStatus = (text: string, key: string): AuthStatus => {
    const m = new RegExp(`${key}=(\\w+)`, 'i').exec(text);
    if (!m) return 'NOT_AVAILABLE';
    const v = m[1].toLowerCase();
    if (v === 'pass') return 'PASS';
    if (v === 'fail' || v === 'hardfail' || v === 'softfail') return 'FAIL';
    if (v === 'neutral') return 'NEUTRAL';
    if (v === 'none') return 'NONE';
    return 'NOT_AVAILABLE';
  };

  const combined = spfHeader + ' ' + authResults;
  const spf = parseStatus(combined, 'spf');
  const dkim = parseStatus(authResults, 'dkim');
  const dmarc = parseStatus(authResults, 'dmarc');

  const failures = [spf, dkim, dmarc].filter(s => s === 'FAIL').length;
  const summary = failures === 3
    ? 'All three authentication mechanisms failed — strong indicator of sender spoofing.'
    : failures === 2 ? 'Two authentication mechanisms failed — significant spoofing indicator.'
    : failures === 1 ? 'One authentication mechanism failed — possible misconfiguration or spoofing.'
    : spf === 'PASS' && dkim === 'PASS' && dmarc === 'PASS' ? 'All authentication checks pass — sender identity verified.'
    : 'Mixed or unavailable authentication results.';

  const spfDetail = spfHeader ? spfHeader.substring(0, 120) : undefined;
  const dkimMatch = authResults.match(/dkim=\w+\s+([^;]+)/i);
  const dmarcMatch = authResults.match(/dmarc=\w+\s+([^;]+)/i);

  return { spf, spfDetail, dkim, dkimDetail: dkimMatch?.[1]?.trim(), dmarc, dmarcDetail: dmarcMatch?.[1]?.trim(), summary };
}

export function computeRiskScore(email: ParsedEmail, auth: AuthResult, iocs: IOC[]): RiskScore {
  const content = scoreContent(email);
  const authentication = scoreAuth(auth);
  const reputation = scoreReputation(iocs);
  const infrastructure = scoreInfrastructure(email, iocs);

  const total = content.score + authentication.score + reputation.score + infrastructure.score;

  let level: RiskLevel;
  if (total >= 80) level = 'CRITICAL';
  else if (total >= 60) level = 'HIGH';
  else if (total >= 40) level = 'MEDIUM';
  else if (total >= 20) level = 'LOW';
  else level = 'CLEAN';

  const drivers: string[] = [];
  if (reputation.score >= 15) drivers.push('malicious IOC reputation');
  if (authentication.score >= 12) drivers.push('authentication failure');
  if (infrastructure.score >= 12) drivers.push('suspicious infrastructure');
  if (content.score >= 12) drivers.push('high-risk content patterns');

  const explanation = drivers.length > 0
    ? `${level} risk driven primarily by: ${drivers.join(', ')}.`
    : `Risk score ${total}/100 from multi-signal weighted analysis.`;

  return {
    total, level,
    content, authentication, reputation, infrastructure,
    explanation,
  };
}
