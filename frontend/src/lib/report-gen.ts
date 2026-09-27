import { Case, GeoContext } from '../types';
import { iocEvidenceCategory } from './ioc-presentation';
import {
  AI_INTERPRETATION,
  formatInvestigationExplanation,
  RISK_FLOW,
  RISK_FLOW_TEXT,
  riskPresentation,
} from './risk-presentation';

function geoFieldValue(geo: GeoContext, field: string, value?: string): string {
  if (value) return value;
  if (geo.fieldStatus?.[field] === 'NOT_RETURNED_BY_SOURCE') {
    return 'Not returned by source';
  }
  if (['LOOKUP_FAILED', 'ERROR', 'TIMEOUT'].includes(geo.fieldStatus?.[field] || '')) {
    return 'Lookup failed';
  }
  return 'Not available';
}

function normalizedIOC(ioc: Case['iocs'][number]): Case['iocs'][number] {
  const intel = ioc.intelligence;
  const hasReputation = intel?.lookupStatus === 'FOUND' && intel.reputation !== undefined;
  const reputationStatus = hasReputation
    ? intel.reputationStatus
      ?? (intel.reputation! >= 90 ? 'MALICIOUS'
        : intel.reputation! >= 40 ? 'SUSPICIOUS' : 'CLEAN')
    : 'UNKNOWN';
  const riskContribution = hasReputation && reputationStatus !== 'UNKNOWN' && reputationStatus !== 'CLEAN'
    ? intel.riskContribution
      ?? (intel.reputation! >= 90 ? 8 : intel.reputation! >= 70 ? 5 : intel.reputation! >= 40 ? 2 : 0)
    : 0;
  return {
    ...ioc,
    status: reputationStatus,
    reputationStatus,
    riskContribution,
    intelligence: intel ? {
      ...intel,
      reputationStatus,
      riskContribution,
      reason: reputationStatus === 'UNKNOWN'
        ? intel.reason || 'No threat-intelligence result available'
        : intel.reason,
    } : intel,
  };
}

export function downloadJSON(c: Case): void {
  const iocs = c.iocs.map(normalizedIOC);
  const modelEvidence = c.aiAnalysis?.models.map(model => ({
    name: model.name,
    modelId: model.modelId,
    status: model.status,
    classMapping: model.classMapping,
    benignProbability: model.benignProbability,
    phishingProbability: model.phishingProbability,
    predictedLabel: model.predictedLabel,
    predictedClass: model.predictedClass,
    error: model.error,
  })) ?? [];
  const report = {
    reportType: 'PRAHARI AI Forensic Investigation Report',
    reportVersion: '1.0',
    generatedAt: new Date().toISOString(),
    disclaimer: 'This report is generated for analytical and investigative purposes only. It does not constitute legal evidence or certification.',
    isDemo: c.isDemo || false,
    case: {
      id: c.id,
      threatType: c.threatType || 'Suspicious',
      threat_type: c.threatType || 'Suspicious Email',
      createdAt: c.createdAt,
      severity: c.severity,
      verdict: c.verdict,
      evidenceCoverage: c.riskScore.evidenceCoverage,
    },
    threat_type: c.threatType || 'Suspicious Email',
    threat_type_interpretation: 'Investigative classification based on available evidence; not a certainty.',
    riskPresentation: riskPresentation(c.riskScore, c.verdict),
    emailSummary: { from: c.email.from, to: c.email.to, subject: c.email.subject, date: c.email.date, replyTo: c.email.replyTo, messageId: c.email.messageId },
    authentication: c.auth,
    riskScore: {
      total: c.riskScore.total,
      level: c.riskScore.level,
      evidenceCoverage: c.riskScore.evidenceCoverage,
      presentation: riskPresentation(c.riskScore, c.verdict),
      breakdown: {
        content: { score: c.riskScore.content.score, max: 25, signals: c.riskScore.content.signals },
        authentication: { score: c.riskScore.authentication.score, max: 20, signals: c.riskScore.authentication.signals },
        reputation: { score: c.riskScore.reputation.score, max: 25, signals: c.riskScore.reputation.signals },
        infrastructure: { score: c.riskScore.infrastructure.score, max: 30, signals: c.riskScore.infrastructure.signals },
      },
      explanation: formatInvestigationExplanation(c.riskScore),
    },
    riskFlow: RISK_FLOW,
    riskFlowDisplay: RISK_FLOW_TEXT,
    aiInterpretation: AI_INTERPRETATION,
    evidenceCoverage: c.riskScore.evidenceCoverage,
    aiAnalysis: c.aiAnalysis,
    aiEvidence: {
      models: modelEvidence,
      combinedSignal: c.aiAnalysis?.combinedAISignal,
      interpretation: AI_INTERPRETATION,
      authentication: {
        spf: c.auth.spf,
        dkim: c.auth.dkim,
        dmarc: c.auth.dmarc,
        summary: c.auth.summary,
        details: [c.auth.spfDetail, c.auth.dkimDetail, c.auth.dmarcDetail].filter(Boolean),
        riskScore: c.riskScore.authentication.score,
        signals: c.riskScore.authentication.signals,
      },
      iocReputation: {
        riskScore: c.riskScore.reputation.score,
        signals: c.riskScore.reputation.signals,
        lookups: iocs.filter(ioc => ioc.valid).map(ioc => ({
          type: ioc.type,
          value: ioc.value,
          status: ioc.intelligence?.lookupStatus ?? ioc.intelligence?.status ?? 'UNAVAILABLE',
          reputation: ioc.intelligence?.reputation,
          reputationStatus: ioc.reputationStatus || ioc.status,
          riskContribution: ioc.riskContribution ?? 0,
          provider: ioc.intelligence?.provider,
          geoSource: ioc.intelligence?.geo?.source,
        })),
      },
      infrastructure: {
        riskScore: c.riskScore.infrastructure.score,
        signals: c.riskScore.infrastructure.signals,
      },
      finalRisk: {
        total: c.riskScore.total,
        level: c.riskScore.level,
        verdict: c.verdict,
        explanation: formatInvestigationExplanation(c.riskScore),
      },
    },
    iocs: iocs.map(i => ({
      type: i.type,
      value: i.value,
      source: i.source,
      evidenceCategory: iocEvidenceCategory(i),
      risk: i.risk,
      status: i.status,
      reputationStatus: i.reputationStatus,
      riskContribution: i.riskContribution,
      lookupSource: i.intelligence?.lookupSource || 'No reputation result',
      lookupStatus: i.intelligence?.lookupStatus || 'UNAVAILABLE',
      geoSource: i.intelligence?.geo?.source,
      intelligence: i.intelligence,
    })),
    mitreMappings: c.mitreMappings,
    geoNetworkContext: c.iocs.filter(i => i.intelligence?.geo).map(i => ({ ioc: i.value, ...i.intelligence!.geo })),
    timeline: c.timeline,
    summary: c.summary,
    whyFlagged: c.whyFlagged,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `PRAHARI-${c.id}-Report.json`; a.click();
  URL.revokeObjectURL(url);
}

export async function printPDF(c: Case): Promise<void> {
  // Pure jsPDF — programmatic generation, works in any sandboxed iframe.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { jsPDF } = (await import('jspdf')) as any;

  const doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'portrait' });
  const PW = 210, ML = 14, MR = 14, CW = PW - ML - MR, YMAX = 278, FH = 297;
  let y = 0;

  const rc: [number, number, number] =
    c.riskScore.level === 'CRITICAL' || c.riskScore.level === 'HIGH' ? [220, 38, 38]
    : c.riskScore.level === 'MEDIUM' ? [217, 119, 6]
    : [5, 150, 105];

  const newPage = () => { doc.addPage(); y = 16; };
  const chk = (n = 10) => { if (y + n > YMAX) newPage(); };

  // Draw text at current y, with optional jsPDF text options
  const txt = (text: string, x: number, opts?: Record<string, unknown>) =>
    doc.text(String(text ?? ''), x, y, opts ?? {});

  // Wrap text to fit within maxW mm
  const wrap = (text: string, maxW: number): string[] =>
    doc.splitTextToSize(String(text ?? ''), maxW);

  // Section header: label + rule
  const section = (title: string) => {
    chk(16); y += 6;
    doc.setFillColor(241, 245, 249);
    doc.rect(ML - 2, y - 5, CW + 4, 7, 'F');
    doc.setFontSize(7); doc.setFont('helvetica', 'bold');
    doc.setTextColor(71, 85, 105);
    txt(title.toUpperCase(), ML);
    y += 4;
    doc.setDrawColor(203, 213, 225); doc.line(ML, y, PW - MR, y);
    y += 5;
  };

  // Key / value row — label left-aligned in 40mm gutter, value right
  const kv = (label: string, value: string) => {
    chk(7);
    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(148, 163, 184);
    txt(label, ML);
    doc.setFont('helvetica', 'normal'); doc.setTextColor(15, 23, 42);
    const lines = wrap(value || '—', CW - 42);
    doc.text(lines, ML + 42, y);
    y += Math.max(lines.length, 1) * 4.2 + 1;
  };

  const authRGB = (s: string): [number, number, number] =>
    s === 'PASS' ? [5, 150, 105] : s === 'FAIL' ? [220, 38, 38] : [148, 163, 184];

  // ── HEADER BAND ─────────────────────────────────────────────────────────
  // Dark background
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, PW, 58, 'F');
  // Blue accent left stripe
  doc.setFillColor(59, 130, 246);
  doc.rect(0, 0, 3, 58, 'F');

  // PRAHARI AI label
  doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(59, 130, 246);
  y = 10; txt('PRAHARI AI  ·  FORENSIC INTELLIGENCE PLATFORM', ML + 2);

  // Title
  doc.setFontSize(18); doc.setFont('helvetica', 'bold'); doc.setTextColor(255, 255, 255);
  y = 21; txt('Forensic Investigation Report', ML + 2);

  // Subtitle
  doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(148, 163, 184);
  y = 29; txt('Email Threat Detection & Forensic Intelligence Analysis', ML + 2);

  // Case ID
  doc.setFontSize(10.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(96, 165, 250);
  y = 39; txt(`CASE ID: ${c.id}`, ML + 2);

  // Generated date
  doc.setFontSize(7.5); doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 116, 139);
  y = 46; txt(`Generated: ${new Date().toUTCString()}`, ML + 2);

  // Verdict and the separate risk metrics.
  const metricColumns = [ML + 2, ML + 49, ML + 96, ML + 143];
  const metricValues = [
    ['VERDICT', c.verdict],
    ['RISK SCORE', `${c.riskScore.total} / 100`],
    ['RISK BAND', c.riskScore.level],
    ['EVIDENCE COVERAGE', c.riskScore.evidenceCoverage
      ? `${c.riskScore.evidenceCoverage.percentage.toFixed(0)}%` : 'Not available'],
  ];
  doc.setFont('helvetica', 'bold'); doc.setTextColor(100, 116, 139); doc.setFontSize(6.5);
  metricValues.forEach(([label], index) => doc.text(label, metricColumns[index], 53));
  doc.setTextColor(...rc); doc.setFontSize(8.5);
  metricValues.forEach(([, value], index) => doc.text(value, metricColumns[index], 58));
  doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(100, 116, 139);
  doc.text('THREAT TYPE', ML + 2, 63);
  doc.setFontSize(8.5); doc.setTextColor(...rc);
  doc.text(c.threatType || 'Suspicious Email', ML + 25, 63);
  doc.setFontSize(6); doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 116, 139);
  doc.text(
    'Investigative classification based on available evidence; not a certainty.',
    ML + 2,
    67,
  );
  if (c.isDemo) {
    doc.setFillColor(245, 158, 11);
    doc.roundedRect(PW - MR - 32, y - 5, 32, 6, 1, 1, 'F');
    doc.setFontSize(6.5); doc.setTextColor(255, 255, 255);
    doc.text('DEMO INVESTIGATION', PW - MR - 16, y - 1, { align: 'center' });
  }

  y = 74;

  // ── EMAIL SUMMARY ────────────────────────────────────────────────────────
  section('Email Summary');
  kv('FROM', c.email.from);
  kv('TO', c.email.to);
  kv('SUBJECT', c.email.subject);
  kv('DATE', c.email.date);
  kv('REPLY-TO', c.email.replyTo || 'Not set');
  kv('MESSAGE-ID', c.email.messageId || 'N/A');

  // ── RISK ASSESSMENT ──────────────────────────────────────────────────────
  section('Risk Assessment');
  chk(32);

  // Score card — compact two-column: big number left, breakdown right
  const scoreY = y;
  doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(100, 116, 139);
  doc.text('RISK SCORE', ML, scoreY);
  // Big score number — measure width BEFORE changing font size
  doc.setFontSize(40); doc.setFont('helvetica', 'bold'); doc.setTextColor(...rc);
  const scoreStr = String(c.riskScore.total);
  const scoreW = doc.getTextWidth(scoreStr); // measure at 40pt, same size used to draw
  doc.text(scoreStr, ML, scoreY + 12);
  // "/100" — same baseline, same color, smaller size, placed immediately after score
  doc.setFontSize(11); doc.setFont('helvetica', 'normal'); doc.setTextColor(...rc);
  doc.text('/100', ML + scoreW + 1.5, scoreY + 12);
  // Risk band is distinct from the numeric risk score.
  doc.setFontSize(8.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(...rc);
  doc.text(`RISK BAND: ${c.riskScore.level}`, ML, scoreY + 18);

  // Progress bars on right
  const barX = ML + 62, barW = CW - 62;
  let barY = scoreY + 2;
  const cats: [string, number, number][] = [
    ['Content', c.riskScore.content.score, 25],
    ['Authentication', c.riskScore.authentication.score, 20],
    ['Reputation', c.riskScore.reputation.score, 25],
    ['Infrastructure', c.riskScore.infrastructure.score, 30],
  ];
  for (const [cat, score, max] of cats) {
    doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(71, 85, 105);
    doc.text(cat, barX, barY + 3);
    doc.setFontSize(6.5); doc.setFont('helvetica', 'normal'); doc.setTextColor(148, 163, 184);
    doc.text(`${score}/${max}`, PW - MR, barY + 3, { align: 'right' });
    // Track
    doc.setFillColor(226, 232, 240); doc.roundedRect(barX, barY + 4, barW, 2.5, 0.5, 0.5, 'F');
    // Fill
    const fillW = max > 0 ? (score / max) * barW : 0;
    if (fillW > 0) {
      doc.setFillColor(...rc); doc.roundedRect(barX, barY + 4, fillW, 2.5, 0.5, 0.5, 'F');
    }
    barY += 9;
  }

  y = Math.max(scoreY + 22, barY) + 3;

  // Explanation text
  doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(55, 65, 81);
  const expL = wrap(formatInvestigationExplanation(c.riskScore), CW);
  chk(expL.length * 4 + 4);
  doc.text(expL, ML, y); y += expL.length * 4 + 5;
  if (c.riskScore.evidenceCoverage) {
    const coverage = c.riskScore.evidenceCoverage;
    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(71, 85, 105);
    txt(`Evidence Coverage: ${coverage.percentage.toFixed(0)}%`, ML);
    y += 4;
    doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 116, 139);
    const counts = wrap(
      `${coverage.availableCount} available, ${coverage.partialCount} partial, `
      + `${coverage.unavailableCount} unavailable of ${coverage.applicableCount} applicable categories. `
      + 'Partial categories count as half.',
      CW,
    );
    chk(counts.length * 3.5 + 3);
    doc.text(counts, ML, y);
    y += counts.length * 3.5 + 2;
    if (coverage.unavailable.length > 0) {
      const unavailable = wrap(`Unavailable: ${coverage.unavailable.join(', ')}`, CW);
      chk(unavailable.length * 3.5 + 3);
      doc.text(unavailable, ML, y);
      y += unavailable.length * 3.5 + 2;
    }
    if (coverage.partial.length > 0) {
      const partial = wrap(`Partial: ${coverage.partial.join(', ')}`, CW);
      chk(partial.length * 3.5 + 3);
      doc.text(partial, ML, y);
      y += partial.length * 3.5 + 2;
    }
  }

  if (c.aiAnalysis) {
    section('AI CONTENT SIGNAL');
    chk(8);
    doc.setFontSize(7.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(71, 85, 105);
    txt(`Status: ${c.aiAnalysis.status}`, ML); y += 5;
    const combinedPhishing = c.aiAnalysis.combinedAISignal?.phishingProbability
      ?? c.aiAnalysis.aggregatePhishingProbability;
    for (const model of c.aiAnalysis.models.filter(result => /bert|roberta/i.test(result.name))) {
      doc.setFont('helvetica', 'normal');
      txt(`${model.name}: ${model.phishingProbability !== undefined
        ? `${(model.phishingProbability * 100).toFixed(2)}% phishing`
        : 'Not available'}`, ML);
      y += 5;
    }
    if (combinedPhishing !== undefined) {
      doc.setFont('helvetica', 'normal');
      txt(`Combined AI signal: ${(combinedPhishing * 100).toFixed(1)}% phishing`, ML);
      y += 5;
    }
    doc.setFontSize(7); doc.setTextColor(37, 99, 235);
    const aiDisclaimer = wrap(
      AI_INTERPRETATION,
      CW,
    );
    chk(aiDisclaimer.length * 3.5 + 3);
    doc.text(aiDisclaimer, ML, y);
    y += aiDisclaimer.length * 3.5 + 2;
    doc.setTextColor(100, 116, 139);
    const flowLines = wrap(RISK_FLOW_TEXT, CW);
    chk(flowLines.length * 3.5 + 3);
    doc.text(flowLines, ML, y);
    y += flowLines.length * 3.5 + 3;
    for (const model of c.aiAnalysis.models) {
      chk(12);
      doc.setFont('helvetica', 'bold'); doc.setTextColor(15, 23, 42);
      txt(`${model.name} — ${model.status}`, ML); y += 4;
      doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 116, 139);
      const detail = [
        `Model: ${model.modelId}`,
        model.predictedLabel ? `Predicted label: ${model.predictedLabel}` : '',
        `Benign probability: ${model.benignProbability !== undefined
          ? `${(model.benignProbability * 100).toFixed(2)}%` : 'Not available'}`,
        `Phishing probability: ${model.phishingProbability !== undefined
          ? `${(model.phishingProbability * 100).toFixed(2)}%` : 'Not available'}`,
        model.classMapping
          ? `Class mapping: ${Object.entries(model.classMapping)
            .map(([raw, normalized]) => `${raw} → ${normalized || 'unmapped'}`).join(', ')}`
          : '',
        model.labels
          ? model.labels.map(label => `${label.label}: ${(label.probability * 100).toFixed(1)}%`).join(' · ')
          : model.error || '',
        model.chunks !== undefined
          ? `Chunks: ${model.chunks}; ${model.aggregation || 'no aggregation detail'}`
          : '',
      ].filter(Boolean).join('  |  ');
      const lines = wrap(detail, CW);
      chk(lines.length * 3.5 + 4);
      doc.text(lines, ML, y); y += lines.length * 3.5 + 2;
    }
    const authenticationEvidence = [
      `SPF ${c.auth.spf}${c.auth.spfDetail ? ` (${c.auth.spfDetail})` : ''}`,
      `DKIM ${c.auth.dkim}${c.auth.dkimDetail ? ` (${c.auth.dkimDetail})` : ''}`,
      `DMARC ${c.auth.dmarc}${c.auth.dmarcDetail ? ` (${c.auth.dmarcDetail})` : ''}`,
      `Score ${c.riskScore.authentication.score}/20`,
      ...c.riskScore.authentication.signals,
    ];
    const reputationEvidence = [
      `Score ${c.riskScore.reputation.score}/25`,
      ...c.riskScore.reputation.signals,
      ...c.iocs.filter(ioc => ioc.valid).map(ioc => {
        const intel = ioc.intelligence;
        const status = intel?.lookupStatus ?? intel?.status ?? 'UNAVAILABLE';
        const reputation = intel?.reputation === undefined
          ? 'Not available'
          : `${intel.reputation}/100`;
        return `${ioc.type} ${ioc.value}: ${status}, reputation ${reputation}` +
          (intel?.provider ? ` (${intel.provider})` : '');
      }),
    ];
    const infrastructureEvidence = [
      `Score ${c.riskScore.infrastructure.score}/30`,
      ...(c.riskScore.infrastructure.signals.length
        ? c.riskScore.infrastructure.signals
        : ['No scored infrastructure evidence']),
    ];
    const evidenceGroups: [string, string[]][] = [
      ['Authentication evidence', authenticationEvidence],
      ['IOC / reputation evidence', reputationEvidence],
      ['Infrastructure evidence', infrastructureEvidence],
      ['Final risk score', [
        `Risk Score: ${c.riskScore.total} / 100`,
        `Risk Band: ${c.riskScore.level}`,
        `Verdict: ${c.verdict}`,
        formatInvestigationExplanation(c.riskScore),
      ]],
    ];
    for (const [title, items] of evidenceGroups) {
      chk(8);
      doc.setFont('helvetica', 'bold'); doc.setTextColor(71, 85, 105);
      txt(title, ML); y += 4;
      doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 116, 139);
      for (const item of items) {
        const lines = wrap(`• ${item}`, CW - 2);
        chk(lines.length * 3.5 + 2);
        doc.text(lines, ML + 2, y);
        y += lines.length * 3.5 + 1;
      }
      y += 2;
    }
    doc.setTextColor(71, 85, 105);
    txt(`Model-derived risk contribution: ${c.aiAnalysis.riskContribution}/${c.aiAnalysis.riskWeight} content points`, ML);
    y += 6;
  }

  // ── AUTHENTICATION ───────────────────────────────────────────────────────
  section('Authentication');
  const authBadgeW = 18, authLabelW = 14, authDetailX = ML + authLabelW + authBadgeW + 6;
  for (const [name, status, detail] of [
    ['SPF',  c.auth.spf,  c.auth.spfDetail],
    ['DKIM', c.auth.dkim, c.auth.dkimDetail],
    ['DMARC',c.auth.dmarc,c.auth.dmarcDetail],
  ] as [string, string, string | undefined][]) {
    chk(10);
    const rowY = y;
    // Protocol name
    doc.setFontSize(8); doc.setFont('helvetica', 'bold'); doc.setTextColor(15, 23, 42);
    doc.text(name, ML, rowY + 4);
    // Badge pill
    const ac = authRGB(status);
    doc.setFillColor(...ac);
    doc.roundedRect(ML + authLabelW, rowY, authBadgeW, 6, 1.2, 1.2, 'F');
    doc.setFontSize(7); doc.setTextColor(255, 255, 255);
    doc.text(status, ML + authLabelW + authBadgeW / 2, rowY + 4, { align: 'center' });
    // Detail text
    if (detail) {
      doc.setFont('helvetica', 'normal'); doc.setFontSize(7); doc.setTextColor(100, 116, 139);
      const dl = wrap(detail.substring(0, 160), CW - authDetailX + ML);
      doc.text(dl, authDetailX, rowY + 4);
      y += Math.max(dl.length * 3.8, 7) + 2;
    } else { y += 9; }
  }
  doc.setFontSize(8); doc.setFont('helvetica', 'normal'); doc.setTextColor(55, 65, 81);
  const authL = wrap(c.auth.summary, CW);
  chk(authL.length * 4 + 4);
  doc.text(authL, ML, y); y += authL.length * 4 + 5;

  // ── IOCs TABLE ───────────────────────────────────────────────────────────
  section(`Indicators of Compromise  (${c.iocs.length})`);
  const iH = 9; // row height
  const reportIOCs = c.iocs.map(normalizedIOC);
  // Column X positions: TYPE | INDICATOR | EVIDENCE SOURCE | REPUTATION | RISK POINTS | LOOKUP
  const iCols = [ML, ML + 15, ML + 64, ML + 105, ML + 133, ML + 160];
  // Header row
  doc.setFillColor(30, 41, 59); doc.rect(ML, y, CW, iH, 'F');
  doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(148, 163, 184);
  y += 4.5;
  ['TYPE', 'INDICATOR', 'EVIDENCE SOURCE', 'REPUTATION', 'RISK PTS', 'LOOKUP'].forEach((h, i) => txt(h, iCols[i]));
  y += 2.5;

  const riskRGB: Record<string, [number,number,number]> = {
    CRITICAL:[220,38,38], HIGH:[220,38,38], MEDIUM:[217,119,6], LOW:[5,150,105], UNKNOWN:[148,163,184],
    MALICIOUS:[220,38,38], SUSPICIOUS:[217,119,6], CLEAN:[5,150,105],
  };
  let rowAlt = false;
  for (const ioc of reportIOCs) {
    chk(iH + 1);
    if (rowAlt) { doc.setFillColor(248, 250, 252); doc.rect(ML, y, CW, iH, 'F'); }
    rowAlt = !rowAlt;
    doc.setDrawColor(226, 232, 240); doc.line(ML, y, PW - MR, y);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(6.5); doc.setTextColor(15, 23, 42);
    y += 3.5;
    txt(ioc.type, iCols[0]);
    txt(ioc.value.length > 38 ? ioc.value.slice(0, 36) + '…' : ioc.value, iCols[1]);
    txt(ioc.source.length > 34 ? ioc.source.slice(0, 32) + '…' : ioc.source, iCols[2]);
    doc.setFontSize(5.5); doc.setTextColor(100, 116, 139);
    const sourceDetail = `${iocEvidenceCategory(ioc)} · ${ioc.intelligence?.lookupSource || 'No reputation result'}`;
    doc.text(sourceDetail.length > 39 ? sourceDetail.slice(0, 37) + '…' : sourceDetail, iCols[2], y + 3);
    doc.setFontSize(6.5); doc.setTextColor(15, 23, 42);
    const reputation = ioc.reputationStatus || ioc.status;
    const rr = riskRGB[reputation] ?? [148, 163, 184];
    doc.setFillColor(...rr); doc.roundedRect(iCols[3], y - 3, 26, 5, 0.8, 0.8, 'F');
    doc.setFont('helvetica', 'bold'); doc.setTextColor(255, 255, 255);
    doc.text(reputation, iCols[3] + 13, y - 0.5, { align: 'center' });
    doc.setFont('helvetica', 'normal'); doc.setTextColor(71, 85, 105);
    txt(`+${ioc.riskContribution ?? 0}`, iCols[4]);
    txt(ioc.intelligence?.lookupStatus || 'UNAVAILABLE', iCols[5]);
    y += 5.5;
  }
  doc.setDrawColor(226, 232, 240); doc.line(ML, y, PW - MR, y);
  y += 5;

  // ── GEO / NETWORK INTELLIGENCE ───────────────────────────────────────────
  const geoIOCs = reportIOCs.filter(i => i.type === 'IP' && i.intelligence?.geo);
  if (geoIOCs.length > 0) {
    section('Geographic & Network Intelligence');

    // Forensic disclaimer box
    chk(10);
    doc.setFillColor(254, 243, 199); doc.roundedRect(ML, y, CW, 8, 1, 1, 'F');
    doc.setDrawColor(252, 211, 77); doc.roundedRect(ML, y, CW, 8, 1, 1, 'S');
    doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(146, 64, 14);
    doc.text('⚠  FORENSIC NOTE', ML + 3, y + 3.5);
    doc.setFont('helvetica', 'normal'); doc.setTextColor(120, 53, 15);
    doc.text('GeoIP identifies approximate infrastructure location — NOT the attacker\'s physical location.', ML + 28, y + 3.5);
    doc.setTextColor(146, 64, 14);
    doc.text('GeoIP alone does not increase risk score.', ML + 3, y + 6.5);
    y += 11;

    for (let gi = 0; gi < geoIOCs.length; gi++) {
      const ioc = geoIOCs[gi];
      const geo = ioc.intelligence!.geo!;
      const g = geo as typeof geo & {
        postalCode?: string; timezone?: string; infraType?: string;
        reverseDns?: string; geoConfidence?: string; accuracyNote?: string;
        lat?: number; lon?: number; org?: string;
      };

      chk(18);
      // IP card header
      doc.setFillColor(15, 23, 42); doc.rect(ML, y, CW, 9, 'F');
      doc.setFillColor(59, 130, 246); doc.rect(ML, y, 2.5, 9, 'F');
      doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(148, 163, 184);
      doc.text(`OBSERVED IP #${gi + 1}  ·  ${ioc.source}`, ML + 5, y + 3.5);
      doc.setFontSize(9); doc.setTextColor(255, 255, 255);
      doc.text(ioc.value, ML + 5, y + 7.5);
      // Risk badge
      const rr = riskRGB[ioc.reputationStatus || ioc.status] ?? [148, 163, 184];
      doc.setFillColor(...rr); doc.roundedRect(PW - MR - 22, y + 1.5, 20, 6, 1, 1, 'F');
      doc.setFontSize(7); doc.setFont('helvetica', 'bold'); doc.setTextColor(255, 255, 255);
      doc.text(ioc.reputationStatus || ioc.status, PW - MR - 12, y + 5.5, { align: 'center' });
      // Geo confidence
      if (g.geoConfidence) {
        const gcRGB: [number,number,number] =
          g.geoConfidence === 'HIGH' ? [5, 150, 105] :
          g.geoConfidence === 'MEDIUM' ? [217, 119, 6] : [148, 163, 184];
        doc.setFillColor(...gcRGB); doc.roundedRect(PW - MR - 45, y + 1.5, 21, 6, 1, 1, 'F');
        doc.setFontSize(6); doc.setTextColor(255, 255, 255);
        doc.text(`Conf: ${g.geoConfidence}`, PW - MR - 34.5, y + 5.5, { align: 'center' });
      }
      // Infra type
      if (g.infraType && g.infraType !== 'Unknown') {
        doc.setFontSize(6); doc.setFont('helvetica', 'normal'); doc.setTextColor(96, 165, 250);
        doc.text(g.infraType, ML + 5, y + 3.5 + 0.1, { align: 'right', maxWidth: 50 });
      }
      y += 12;

      // Two columns: Geographic | Network
      const colW = (CW - 4) / 2;
      const col2 = ML + colW + 4;
      const geoStartY = y;

      // Geographic Context sub-header
      chk(8);
      doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(59, 130, 246);
      doc.text('GEOGRAPHIC CONTEXT', ML, y); y += 4;

      const geoRows: [string, string][] = [
        ['Country',     geo.country ? `${geo.country} (${geo.countryCode})` : 'Not available'],
        ['Region',      geo.region || 'Not available'],
        ['City',        geo.city || 'Not available'],
        ['Postal Code', g.postalCode || 'Not available'],
        ['Timezone',    g.timezone || 'Not available'],
        ['Coordinates', g.lat !== undefined ? `${g.lat.toFixed(4)}°, ${g.lon!.toFixed(4)}° (${g.accuracyNote ?? 'Approximate'})` : 'Not available'],
      ];

      const netStartY = geoStartY + 4;
      let ny = netStartY;

      // Network Context sub-header (right column)
      doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(124, 58, 237);
      doc.text('NETWORK CONTEXT', col2, netStartY - 4 + (y - geoStartY - 4) * 0 + 0);

      for (const [lbl, val] of geoRows) {
        chk(5);
        doc.setFontSize(6); doc.setFont('helvetica', 'bold'); doc.setTextColor(148, 163, 184);
        doc.text(lbl.toUpperCase(), ML, y);
        doc.setFont('helvetica', 'normal'); doc.setTextColor(15, 23, 42);
        const vl = wrap(val, colW - 2);
        doc.text(vl, ML, y + 3);
        y += vl.length * 3.5 + 4;
      }

      // Network context in right column, parallel to geo
      const netRows: [string, string][] = [
        ['ASN',            geo.asn || 'Not available'],
        ['ASN Org',        geo.asnName || 'Not available'],
        ['ISP',            geo.isp || 'Not available'],
        ['Organization',   g.org || 'Not available'],
        ['Network',        geoFieldValue(geo, 'network', geo.network)],
        ['Infra Type',     geoFieldValue(geo, 'infrastructure_type', g.infraType)],
        ['Reverse DNS',    geoFieldValue(geo, 'reverse_dns', g.reverseDns)],
        ['IP Domain / Hostname', geo.domainHostname
          ? `${geo.domainHostname}${geo.domainHostnameSource ? ` (${geo.domainHostnameSource})` : ''}`
          : 'Not available'],
        ['Connection',     geoFieldValue(geo, 'network_type', geo.networkType)],
        ['Source',         geo.source],
      ];

      ny = netStartY;
      doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(124, 58, 237);
      doc.text('NETWORK CONTEXT', col2, geoStartY);
      ny = geoStartY + 4;

      for (const [lbl, val] of netRows) {
        doc.setFontSize(6); doc.setFont('helvetica', 'bold'); doc.setTextColor(148, 163, 184);
        doc.text(lbl.toUpperCase(), col2, ny);
        doc.setFont('helvetica', 'normal'); doc.setTextColor(15, 23, 42);
        const vl = wrap(val, colW - 2);
        doc.text(vl, col2, ny + 3);
        ny += vl.length * 3.5 + 4;
      }

      // If net rows overflow below geo column, continue below
      if (ny > y) {
        y = ny;
      }

      // Intelligence row
      chk(10);
      doc.setFillColor(248, 250, 252); doc.rect(ML, y, CW, 8, 'F');
      doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(100, 116, 139);
      y += 5;
      const repStr = ioc.intelligence?.reputation !== undefined ? ` · ${ioc.intelligence.reputation}/100` : '';
      const confStr = ioc.intelligence?.confidence !== undefined ? `${ioc.intelligence.confidence}%` : '—';
      doc.text('Reputation:', ML + 2, y);
      doc.setFont('helvetica', 'normal'); doc.setTextColor(15, 23, 42);
      doc.text(`${ioc.reputationStatus || ioc.status}${repStr}`, ML + 22, y);
      doc.setFont('helvetica', 'bold'); doc.setTextColor(100, 116, 139);
      doc.text('Risk pts:', ML + 77, y);
      doc.setFont('helvetica', 'normal'); doc.setTextColor(15, 23, 42);
      doc.text(`+${ioc.riskContribution ?? 0}`, ML + 94, y);
      doc.setFont('helvetica', 'bold'); doc.setTextColor(100, 116, 139);
      doc.text('Lookup:', ML + 108, y);
      doc.setFont('helvetica', 'normal'); doc.setTextColor(15, 23, 42);
      doc.text(ioc.intelligence?.lookupStatus || 'UNAVAILABLE', ML + 124, y);
      doc.setFont('helvetica', 'bold'); doc.setTextColor(100, 116, 139);
      doc.text('Confidence:', ML + 153, y);
      doc.setFont('helvetica', 'normal'); doc.setTextColor(15, 23, 42);
      doc.text(confStr, ML + 176, y);
      y += 5;

      // Tags
      if (ioc.intelligence?.tags && ioc.intelligence.tags.length > 0) {
        chk(8);
        doc.setFontSize(6.5); doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 116, 139);
        const tagLine = wrap('Tags: ' + ioc.intelligence.tags.join('  ·  '), CW);
        doc.text(tagLine, ML, y); y += tagLine.length * 3.5;
      }

      doc.setDrawColor(226, 232, 240); doc.line(ML, y, PW - MR, y); y += 6;
    }
  }

  // ── MITRE ATT&CK ─────────────────────────────────────────────────────────
  if (c.mitreMappings.length > 0) {
    section('MITRE ATT&CK Techniques');
    for (const m of c.mitreMappings) {
      chk(22);
      const mY = y;
      // Card background + accent stripe
      doc.setFillColor(248, 250, 252); doc.rect(ML, mY, CW, 5.5, 'F');
      doc.setFillColor(59, 130, 246); doc.rect(ML, mY, 2.5, 5.5, 'F');
      // Technique ID
      doc.setFontSize(8); doc.setFont('helvetica', 'bold'); doc.setTextColor(59, 130, 246);
      doc.text(m.techniqueId, ML + 5, mY + 4);
      const tidW = doc.getTextWidth(m.techniqueId);
      // Technique name
      doc.setTextColor(15, 23, 42);
      doc.text(m.techniqueName, ML + 5 + tidW + 3, mY + 4);
      // Tactic tag
      doc.setFontSize(6.5); doc.setTextColor(67, 56, 202);
      doc.text(m.tactic.toUpperCase(), PW - MR, mY + 4, { align: 'right' });
      y += 7;
      // Description
      doc.setFont('helvetica', 'normal'); doc.setFontSize(7.5); doc.setTextColor(55, 65, 81);
      const dl = wrap(m.description, CW - 6); chk(dl.length * 3.8 + 4);
      doc.text(dl, ML + 5, y); y += dl.length * 3.8 + 2;
      // Evidence
      if (m.evidence.length > 0) {
        doc.setFontSize(6.5); doc.setTextColor(100, 116, 139);
        const el = wrap('Evidence: ' + m.evidence.join('  ·  '), CW - 6);
        chk(el.length * 3.5 + 5); doc.text(el, ML + 5, y); y += el.length * 3.5 + 5;
      } else { y += 4; }
    }
  }

  // ── TIMELINE ─────────────────────────────────────────────────────────────
  section('Forensic Timeline');
  for (const e of c.timeline) {
    chk(16);
    const eY = y;
    // Timeline dot + connector line
    doc.setFillColor(59, 130, 246); doc.circle(ML + 2, eY + 1, 1.5, 'F');
    doc.setDrawColor(203, 213, 225); doc.setLineWidth(0.3);
    doc.line(ML + 2, eY + 2.5, ML + 2, eY + 15);
    doc.setLineWidth(0.2);
    // Timestamp
    doc.setFontSize(6.5); doc.setFont('helvetica', 'normal'); doc.setTextColor(148, 163, 184);
    doc.text(e.timestamp + (e.isDemo ? '  [DEMO DATA]' : ''), ML + 7, eY + 3.5);
    // Event title
    doc.setFont('helvetica', 'bold'); doc.setFontSize(8); doc.setTextColor(15, 23, 42);
    doc.text(e.event, ML + 7, eY + 8);
    // Detail
    doc.setFont('helvetica', 'normal'); doc.setFontSize(7); doc.setTextColor(100, 116, 139);
    const dl = wrap(e.detail, CW - 10); chk(dl.length * 3.5 + 5);
    doc.text(dl, ML + 7, eY + 12.5);
    y += dl.length * 3.5 + 14;
  }
  y += 3;

  // ── CASE SUMMARY ─────────────────────────────────────────────────────────
  section('Case Summary & Findings');
  kv('THREAT TYPE', c.threatType || 'Suspicious Email');
  const classificationNote = wrap(
    'Investigative classification based on available evidence; not a certainty.',
    CW,
  );
  chk(classificationNote.length * 3.5 + 3);
  doc.setFontSize(7); doc.setTextColor(100, 116, 139);
  doc.text(classificationNote, ML, y);
  y += classificationNote.length * 3.5 + 2;
  doc.setFont('helvetica', 'normal'); doc.setFontSize(8.5); doc.setTextColor(55, 65, 81);
  const smL = wrap(c.summary, CW); chk(smL.length * 4.2 + 4);
  doc.text(smL, ML, y); y += smL.length * 4.2 + 5;

  if (c.whyFlagged.length > 0) {
    chk(10);
    doc.setFontSize(7.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(71, 85, 105);
    txt('WHY FLAGGED', ML); y += 5.5;
    doc.setFont('helvetica', 'normal'); doc.setFontSize(8); doc.setTextColor(55, 65, 81);
    for (const r of c.whyFlagged) {
      const rl = wrap(`•  ${r}`, CW - 4); chk(rl.length * 4.2 + 1);
      doc.text(rl, ML + 2, y); y += rl.length * 4.2 + 1;
    }
  }

  // ── FOOTER on every page ─────────────────────────────────────────────────
  const total = doc.getNumberOfPages();
  for (let p = 1; p <= total; p++) {
    doc.setPage(p);
    // Footer band
    doc.setFillColor(15, 23, 42); doc.rect(0, FH - 9, PW, 9, 'F');
    doc.setFillColor(59, 130, 246); doc.rect(0, FH - 9, 3, 9, 'F');
    doc.setFontSize(6.5); doc.setFont('helvetica', 'bold'); doc.setTextColor(96, 165, 250);
    doc.text('PRAHARI AI', ML, FH - 4);
    doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 116, 139);
    doc.text('— Forensic Intelligence Report  ·  Not legally certified  ·  For analytical use only', ML + 20, FH - 4);
    doc.setFont('helvetica', 'bold'); doc.setTextColor(148, 163, 184);
    doc.text(`Page ${p} of ${total}`, PW - MR, FH - 4, { align: 'right' });
  }

  doc.save(`PRAHARI-${c.id}-Report.pdf`);
}
