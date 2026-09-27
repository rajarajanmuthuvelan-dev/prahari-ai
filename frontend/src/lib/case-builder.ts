import { Case, ParsedEmail, AuthResult, IOC, MitreMapping, TimelineEvent, GraphNode, GraphEdge, Verdict } from '../types';
import { computeRiskScore } from './risk-engine';
import { normalizeIOC } from './ioc-normalizer';

export function buildCase(email: ParsedEmail, iocs: IOC[], auth: AuthResult, caseId: string): Case {
  const normalizedIOCs = new Map<string, IOC>();
  for (const ioc of iocs) {
    const normalized = normalizeIOC(ioc.type, ioc.value, ioc.source);
    if (!normalized.valid) continue;
    const canonicalValue = ['IP', 'DOMAIN', 'HASH'].includes(ioc.type)
      ? normalized.normalizedValue.toLowerCase()
      : normalized.normalizedValue;
    const key = `${ioc.type}:${canonicalValue}`;
    if (!normalizedIOCs.has(key)) {
      normalizedIOCs.set(key, {
        ...ioc,
        normalizedValue: normalized.normalizedValue,
        valid: true,
        confidence: ioc.confidence ?? normalized.confidence,
      });
    }
  }
  const validIOCs = [...normalizedIOCs.values()];
  const riskScore = computeRiskScore(email, auth, validIOCs);
  const now = new Date().toISOString();

  // MITRE mappings — evidence-driven only
  const mitreMappings: MitreMapping[] = [];

  const hasPhishLink = validIOCs.some(i => i.type === 'URL' && (i.risk === 'CRITICAL' || i.risk === 'HIGH'));
  if (hasPhishLink || email.urls.length > 0) {
    mitreMappings.push({
      techniqueId: 'T1566.002',
      techniqueName: 'Phishing: Spearphishing Link',
      tactic: 'Initial Access', tacticId: 'TA0001',
      description: 'Email contains URL(s) potentially leading to credential harvesting or malware delivery.',
      evidence: [
        ...validIOCs.filter(i => i.type === 'URL').map(i => `URL: ${i.value.substring(0, 80)}`),
        ...email.urls.slice(0, 2).map(u => `Body URL: ${u.substring(0, 80)}`),
      ].slice(0, 3),
    });
  }

  if (auth.spf === 'FAIL' || auth.dkim === 'FAIL') {
    mitreMappings.push({
      techniqueId: 'T1036.005',
      techniqueName: 'Masquerading: Match Legitimate Name',
      tactic: 'Defense Evasion', tacticId: 'TA0005',
      description: 'Email authentication failures indicate sender identity spoofing or unauthorized sending infrastructure.',
      evidence: [
        auth.spf === 'FAIL' ? 'SPF FAIL — sender IP not authorized' : '',
        auth.dkim === 'FAIL' ? 'DKIM FAIL — signature invalid' : '',
        auth.dmarc === 'FAIL' ? 'DMARC FAIL — policy enforcement failure' : '',
      ].filter(Boolean),
    });
  }

  if (email.replyTo) {
    const fd = email.from.match(/@([^>@\s,]+)/)?.[1];
    const rd = email.replyTo.match(/@([^>@\s,]+)/)?.[1];
    if (fd && rd && fd !== rd) {
      mitreMappings.push({
        techniqueId: 'T1598.003',
        techniqueName: 'Phishing for Information: Spearphishing Link',
        tactic: 'Reconnaissance', tacticId: 'TA0043',
        description: 'Reply-To address routes victim responses to an attacker-controlled mailbox.',
        evidence: [`Reply-To (${rd}) differs from From domain (${fd})`],
      });
    }
  }

  // Timeline
  const timeline: TimelineEvent[] = [
    { id: 'tl-submit', timestamp: now, event: 'Email Submitted to PRAHARI AI', detail: `EML file uploaded for forensic investigation. From: ${email.from.substring(0, 60)}`, type: 'info' },
    { id: 'tl-parse', timestamp: now, event: 'Email Parsed', detail: `${email.headers.length} headers extracted. ${email.receivedIPs.length} public IP(s) in routing chain. ${email.urls.length} URL(s). ${email.attachments.length} attachment(s).`, type: 'success' },
    { id: 'tl-auth', timestamp: now, event: 'Authentication Analysis', detail: `SPF: ${auth.spf} | DKIM: ${auth.dkim} | DMARC: ${auth.dmarc}`, type: (auth.spf === 'FAIL' || auth.dkim === 'FAIL') ? 'critical' : 'success' },
    { id: 'tl-ioc', timestamp: now, event: 'IOC Extraction & Enrichment', detail: `${validIOCs.length} IOC(s) extracted. ${validIOCs.filter(i => i.status === 'MALICIOUS').length} confirmed malicious.`, type: validIOCs.some(i => i.risk === 'CRITICAL') ? 'critical' : 'warning' },
    { id: 'tl-geo', timestamp: now, event: 'Geographic & Network Context', detail: validIOCs.find(i => i.intelligence?.geo) ? `Geo context: ${validIOCs.find(i => i.intelligence?.geo)!.intelligence!.geo!.country} / ${validIOCs.find(i => i.intelligence?.geo)!.intelligence!.geo!.asnName} [Source: ${validIOCs.find(i => i.intelligence?.geo)!.intelligence!.geo!.source}]` : 'No geo context available for observed IPs', type: 'info' },
    { id: 'tl-score', timestamp: now, event: 'Risk Assessment Complete', detail: `Multi-signal score: ${riskScore.total}/100 (${riskScore.level}). Evidence coverage is unavailable without backend pipeline results. ${mitreMappings.length} MITRE technique(s). Verdict: ${riskScore.total >= 70 ? 'MALICIOUS' : riskScore.total >= 50 ? 'SUSPICIOUS' : 'INVESTIGATING'}.`, type: riskScore.total >= 60 ? 'critical' : 'info' },
  ];

  // Evidence graph
  const graphNodes: GraphNode[] = [];
  const graphEdges: GraphEdge[] = [];

  graphNodes.push({ id: 'email', type: 'EMAIL', label: 'Email', detail: email.subject.substring(0, 50), x: 420, y: 90 });

  let ipIdx = 0, domIdx = 0, urlIdx = 0;
  const nodeMap: Record<string, string> = {};

  for (const ioc of validIOCs.slice(0, 9)) {
    const nid = `n-${ioc.id}`;
    nodeMap[ioc.value] = nid;

    if (ioc.type === 'IP') {
      const x = 580 + ipIdx * 60, y = 240 + ipIdx * 80;
      graphNodes.push({ id: nid, type: 'IP', label: ioc.value, detail: ioc.intelligence?.geo?.networkType || 'IP Address', risk: ioc.risk, x, y });
      graphEdges.push({ id: `e-em-${nid}`, source: 'email', target: nid, label: 'from IP' });
      if (ioc.intelligence?.geo) {
        const gid = `geo-${ioc.id}`;
        graphNodes.push({ id: gid, type: 'GEO', label: ioc.intelligence.geo.country, detail: ioc.intelligence.geo.asnName, risk: 'LOW', x: x + 130, y: y + 70 });
        graphEdges.push({ id: `e-${nid}-${gid}`, source: nid, target: gid, label: 'geo' });
      }
      ipIdx++;
    } else if (ioc.type === 'DOMAIN') {
      const x = 200 + domIdx * 30, y = 240 + domIdx * 80;
      const label = ioc.value.length > 28 ? ioc.value.substring(0, 26) + '…' : ioc.value;
      graphNodes.push({ id: nid, type: 'DOMAIN', label, detail: ioc.source, risk: ioc.risk, x, y });
      graphEdges.push({ id: `e-em-${nid}`, source: 'email', target: nid, label: 'domain' });
      domIdx++;
    } else if (ioc.type === 'URL' && urlIdx < 2) {
      const x = 410, y = 240 + urlIdx * 90;
      const label = ioc.value.length > 36 ? ioc.value.substring(0, 34) + '…' : ioc.value;
      graphNodes.push({ id: nid, type: 'URL', label, detail: 'Email Body URL', risk: ioc.risk, x, y });
      graphEdges.push({ id: `e-em-${nid}`, source: 'email', target: nid, label: 'contains' });
      urlIdx++;
    }
  }

  if (riskScore.reputation.score >= 12) {
    graphNodes.push({ id: 'rep', type: 'REPUTATION', label: 'MALICIOUS', detail: 'Local IOC Database', risk: 'CRITICAL', x: 580, y: 500 });
    const ipNode = graphNodes.find(n => n.type === 'IP');
    if (ipNode) graphEdges.push({ id: 'e-rep', source: ipNode.id, target: 'rep', label: 'reputation' });
  }

  const verdict: Verdict = riskScore.total >= 80 ? 'MALICIOUS'
    : riskScore.total >= 55 ? 'SUSPICIOUS'
    : riskScore.total >= 35 ? 'INVESTIGATING'
    : riskScore.total >= 15 ? 'LIKELY_CLEAN'
    : 'CLEAN';

  const whyFlagged = [
    ...riskScore.content.signals.slice(0, 2),
    ...riskScore.authentication.signals.filter(s => s.includes('FAIL')).slice(0, 2),
    ...(riskScore.reputation.score > 0 ? riskScore.reputation.signals.slice(0, 2) : []),
    ...riskScore.infrastructure.signals.slice(0, 2),
  ].filter(Boolean);

  return {
    id: caseId,
    createdAt: now,
    analysisTimestamp: now,
    severity: riskScore.level,
    verdict,
    email,
    auth,
    iocs: validIOCs,
    riskScore,
    mitreMappings,
    timeline,
    graphNodes,
    graphEdges,
    summary: `${caseId}: ${verdict} email (score ${riskScore.total}/100, ${riskScore.level}). ${validIOCs.length} IOC(s), ${mitreMappings.length} MITRE technique(s).`,
    whyFlagged,
    evidenceCount: validIOCs.length + mitreMappings.length,
    isDemo: false,
  };
}
