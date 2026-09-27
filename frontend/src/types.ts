export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH';
export type IOCRisk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type IOCReputationStatus = 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
export type AuthStatus = 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE' | 'NOT_AVAILABLE';
export type DataSource = 'API' | 'LOCAL_DB' | 'DEMO' | 'PARSED' | 'LIVE_GEOIP' | 'NO_DATA' | 'PRIVATE' | string;
export type Verdict = 'MALICIOUS' | 'SUSPICIOUS' | 'LIKELY_CLEAN' | 'CLEAN' | 'INVESTIGATING';
export type ThreatType = 'Phishing' | 'BEC' | 'Impersonation' | 'Malware' | 'Suspicious' | 'Clean';

export interface EmailHeader {
  name: string;
  value: string;
}

export interface ReceivedHeader {
  fromHost?: string;
  byHost?: string;
  timestamp?: string;
  ips: string[];
}

export interface Attachment {
  filename: string;
  contentType: string;
  size: number;
  sha256?: string;
}

export interface ParsedEmail {
  from: string;
  fromName?: string;
  to: string;
  subject: string;
  date: string;
  replyTo?: string;
  messageId?: string;
  headers: EmailHeader[];
  bodyText: string;
  bodyHtml?: string;
  attachments: Attachment[];
  receivedIPs: string[];
  receivedPath?: ReceivedHeader[];
  xOriginatingIP?: string;
  urls: string[];
  emailAddresses: string[];
}

export interface AuthResult {
  spf: AuthStatus;
  spfDetail?: string;
  dkim: AuthStatus;
  dkimDetail?: string;
  dmarc: AuthStatus;
  dmarcDetail?: string;
  summary: string;
}

export interface GeoContext {
  country: string;
  countryCode: string;
  region?: string;
  city?: string;
  postalCode?: string;
  timezone?: string;
  lat?: number;
  lon?: number;
  accuracyNote?: string;
  accuracyRadiusKm?: number;
  asn: string;
  asnName: string;
  isp?: string;
  org?: string;
  network?: string;
  domainHostname?: string;
  domainHostnameSource?: string;
  networkType?: string;
  infraType?: string;
  reverseDns?: string;
  geoConfidence?: string;
  source: DataSource;
  provider?: string;
  status?: 'FOUND' | 'NOT_FOUND' | 'UNAVAILABLE' | 'TIMEOUT' | 'ERROR';
  confidence?: number;
  checkedAt?: string;
  lookupTimestamp?: string;
  fieldStatus?: Record<string, string>;
  providerResults?: Record<string, Record<string, unknown>>;
  disagreements?: Record<string, Record<string, string | number | null>>;
  locationNote?: string;
  raw?: unknown;
}

export type LookupStatus = 'FOUND' | 'NOT_FOUND' | 'UNAVAILABLE' | 'TIMEOUT' | 'ERROR';

export interface IOCIntelligence {
  reputation?: number;
  reputationStatus?: IOCReputationStatus;
  riskContribution?: number;
  reason?: string;
  firstSeen?: string;
  lastSeen?: string;
  totalReports?: number;
  tags: string[];
  geo?: GeoContext;
  whoisRegistrar?: string;
  whoisCreated?: string;
  whoisExpires?: string;
  dnsMx?: string[];
  source: DataSource;
  confidence?: number;
  provider?: string;
  lookupSource?: string;
  lookupStatus?: LookupStatus;
  status?: LookupStatus;
  checkedAt?: string;
  lookupTimestamp?: string;
  providerResults?: Record<string, Record<string, unknown>>;
  geoLookup?: Record<string, unknown>;
  geoStatus?: LookupStatus;
  domainHostname?: string;
  domainHostnameSource?: string;
  raw?: unknown;
}

export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  source: string;
  normalizedValue?: string;
  valid?: boolean;
  confidence?: number;
  risk: IOCRisk;
  status: IOCReputationStatus | 'PRIVATE';
  reputationStatus?: IOCReputationStatus;
  riskContribution?: number;
  lookupSource?: string;
  lookupStatus?: LookupStatus;
  geoSource?: string;
  evidenceCategory?: string;
  intelligence?: IOCIntelligence;
}

export interface ScoreComponent {
  score: number;
  max: number;
  signals: string[];
  ruleScore?: number;
  aiScore?: number;
}

export interface AIModelPrediction {
  label: string;
  normalizedLabel?: string;
  probability: number;
}

export interface AIModelResult {
  name: string;
  modelId: string;
  status: string;
  labels?: AIModelPrediction[];
  classMapping?: Record<string, string>;
  predictedLabel?: string;
  predictedClass?: string;
  benignProbability?: number;
  phishingProbability?: number;
  chunks?: number;
  aggregation?: string;
  error?: string;
}

export interface AICombinedSignal {
  benignProbability?: number;
  phishingProbability?: number;
  modelsUsed: number;
  aggregation: string;
}

export interface AIAnalysis {
  status: string;
  models: AIModelResult[];
  aggregatePhishingProbability?: number;
  riskContribution: number;
  riskWeight: number;
  phishingThreshold: number;
  combinedAISignal?: AICombinedSignal;
  inputTruncated: boolean;
  inputCharacters: number;
}

export interface RiskScore {
  total: number;
  level: RiskLevel;
  content: ScoreComponent;
  authentication: ScoreComponent;
  reputation: ScoreComponent;
  infrastructure: ScoreComponent;
  explanation: string;
  confidence?: number;
  evidenceCoverage?: EvidenceCoverage;
}

export interface EvidenceCoverageCategory {
  label: string;
  status: 'AVAILABLE' | 'PARTIAL' | 'UNAVAILABLE' | 'NOT_APPLICABLE';
  detail: string;
}

export interface EvidenceCoverage {
  percentage: number;
  availableCount: number;
  partialCount: number;
  unavailableCount: number;
  applicableCount: number;
  categories: Record<string, EvidenceCoverageCategory>;
  available: string[];
  partial: string[];
  unavailable: string[];
  notApplicable: string[];
  summary: string;
}

export interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  tacticId: string;
  description: string;
  evidence: string[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event: string;
  detail: string;
  type: 'info' | 'warning' | 'critical' | 'success';
  isDemo?: boolean;
}

export interface GraphNode {
  id: string;
  type: 'EMAIL' | 'URL' | 'DOMAIN' | 'IP' | 'ASN' | 'GEO' | 'REPUTATION' | 'ATTACHMENT';
  label: string;
  detail?: string;
  risk?: IOCRisk;
  x: number;
  y: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface Case {
  id: string;
  createdAt: string;
  analysisTimestamp: string;
  threatType?: ThreatType;
  severity: RiskLevel;
  verdict: Verdict;
  email: ParsedEmail;
  auth: AuthResult;
  iocs: IOC[];
  riskScore: RiskScore;
  aiAnalysis?: AIAnalysis;
  mitreMappings: MitreMapping[];
  timeline: TimelineEvent[];
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  summary: string;
  whyFlagged: string[];
  evidenceCount: number;
  isDemo?: boolean;
}

export interface CaseListItem {
  id: string;
  subject: string;
  riskScore: number;
  verdict: Verdict;
  iocCount: number;
  status: string;
  timestamp: string;
  severity: RiskLevel;
  threatType?: ThreatType;
}
