import { RiskScore } from '../types';

export const RISK_FLOW = [
  'AI Content',
  'Authentication',
  'IOC Reputation',
  'Infrastructure',
  'Multi-Signal Risk Engine',
  'Risk Score + Verdict',
];
export const RISK_FLOW_TEXT =
  'AI Content + Authentication + IOC Reputation + Infrastructure ↓ Multi-Signal Risk Engine ↓ Risk Score + Verdict';
export const AI_INTERPRETATION =
  'AI is one evidence source. Final risk is determined by multi-signal analysis.';

export function formatInvestigationExplanation(riskScore: RiskScore): string {
  const reasons: string[] = [];
  if (riskScore.authentication.score > 0) {
    reasons.push(
      riskScore.authentication.signals.some(signal => /fail/i.test(signal))
        ? 'authentication failures'
        : 'authentication evidence',
    );
  }
  if (riskScore.content.score > 0) reasons.push('high-risk content patterns');
  if (riskScore.reputation.score > 0) reasons.push('IOC reputation evidence');
  if (riskScore.infrastructure.score > 0) reasons.push('infrastructure evidence');

  if (reasons.length === 0) {
    return 'No scored evidence triggered additional risk points.';
  }
  const reasonText = reasons.length === 1
    ? reasons[0]
    : reasons.length === 2
      ? `${reasons[0]} and ${reasons[1]}`
      : `${reasons.slice(0, -1).join(', ')}, and ${reasons[reasons.length - 1]}`;
  return `Investigation triggered by: ${reasonText}.`;
}

export function riskPresentation(
  riskScore: RiskScore,
  verdict: string,
): {
  verdict: string;
  riskScore: string;
  riskBand: string;
  evidenceCoverage: string;
  explanation: string;
  riskFlow: string[];
  riskFlowDisplay: string;
  aiInterpretation: string;
} {
  return {
    verdict,
    riskScore: `${riskScore.total} / 100`,
    riskBand: riskScore.level,
    evidenceCoverage: riskScore.evidenceCoverage
      ? `${riskScore.evidenceCoverage.percentage.toFixed(0)}%`
      : 'Not available',
    explanation: formatInvestigationExplanation(riskScore),
    riskFlow: RISK_FLOW,
    riskFlowDisplay: RISK_FLOW_TEXT,
    aiInterpretation: AI_INTERPRETATION,
  };
}
