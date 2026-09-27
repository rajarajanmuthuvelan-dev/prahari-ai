import {
  Attachment,
  AIAnalysis,
  AIModelResult,
  AuthResult,
  Case,
  CaseListItem,
  EmailHeader,
  EvidenceCoverage,
  EvidenceCoverageCategory,
  GraphEdge,
  GraphNode,
  IOC,
  IOCIntelligence,
  IOCReputationStatus,
  IOCType,
  MitreMapping,
  ReceivedHeader,
  RiskLevel,
  RiskScore,
  TimelineEvent,
  ThreatType,
  Verdict,
} from '../types';

const BASE = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/+$/, '') || '';

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid FastAPI response: ${label} must be an object.`);
  }
  return value as JsonRecord;
}

function valueOf(source: JsonRecord, camel: string, snake: string): unknown {
  return source[camel] ?? source[snake];
}

function stringOf(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Invalid FastAPI response: ${label} must be a string.`);
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

const THREAT_TYPES: readonly ThreatType[] = [
  'Phishing',
  'BEC',
  'Impersonation',
  'Malware',
  'Suspicious',
  'Clean',
];

function optionalThreatType(value: unknown): ThreatType | undefined {
  if (value === undefined || value === null || value === '') return undefined;

  if (typeof value !== 'string') {
    throw new Error('Invalid FastAPI response: threat type must be a string.');
  }

  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ');

  const mapping: Record<string, ThreatType> = {
    phishing: 'Phishing',
    'phishing email': 'Phishing',

    bec: 'BEC',
    'business email compromise': 'BEC',
    'business email compromise (bec)': 'BEC',

    impersonation: 'Impersonation',
    'sender impersonation': 'Impersonation',

    malware: 'Malware',
    'malware attachment': 'Malware',
    'suspicious attachment': 'Malware',

    suspicious: 'Suspicious',

    clean: 'Clean',
    legitimate: 'Clean',
    benign: 'Clean',
  };

  const threatType = mapping[normalized];

  if (threatType) {
    return threatType;
  }

  // Don't crash the whole investigation because of an unexpected
  // backend classification. Preserve the case as suspicious.
  return 'Suspicious';
}

function optionalStringRecord(value: unknown, label: string): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined;
  return Object.fromEntries(
    Object.entries(record(value, label)).map(([key, item]) => [
      key,
      stringOf(item, `${label} ${key}`),
    ]),
  );
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' ? value : undefined;
}

function optionalProbability(value: unknown, label: string): number | undefined {
  const probability = optionalNumber(value);
  if (probability !== undefined && (probability < 0 || probability > 1)) {
    throw new Error(`Invalid FastAPI response: ${label} must be between 0 and 1.`);
  }
  return probability;
}

function normalizeAIAnalysis(value: unknown): AIAnalysis | undefined {
  if (value === undefined || value === null) return undefined;
  const analysis = record(value, 'AI analysis');
  const models: AIModelResult[] = arrayOf(analysis.models, 'AI models').map((rawModel) => {
    const model = record(rawModel, 'AI model result');
    const labelsValue = model.labels;
    const labels = labelsValue === undefined || labelsValue === null
      ? undefined
      : arrayOf(labelsValue, 'AI model labels').map((rawLabel) => {
          const prediction = record(rawLabel, 'AI model label');
          const probability = Number(prediction.probability);
          if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
            throw new Error('Invalid FastAPI response: AI class probability must be between 0 and 1.');
          }
          return {
            label: stringOf(prediction.label, 'AI model label name'),
            normalizedLabel: optionalString(
              valueOf(prediction, 'normalizedLabel', 'normalized_label'),
            ),
            probability,
          };
        });
    const classMappingValue = model.class_mapping;
    const classMapping = classMappingValue === undefined || classMappingValue === null
      ? undefined
      : Object.fromEntries(
          Object.entries(record(classMappingValue, 'AI class mapping')).map(
            ([label, normalized]) => [label, stringOf(normalized, 'normalized AI class')],
          ),
        );
    return {
      name: stringOf(model.name, 'AI model name'),
      modelId: stringOf(valueOf(model, 'modelId', 'model_id'), 'AI model ID'),
      status: stringOf(model.status, 'AI model status'),
      labels,
      classMapping,
      predictedLabel: optionalString(valueOf(model, 'predictedLabel', 'predicted_label')),
      predictedClass: optionalString(valueOf(model, 'predictedClass', 'predicted_class')),
      benignProbability: optionalProbability(
        valueOf(model, 'benignProbability', 'benign_probability'),
        'AI benign probability',
      ),
      phishingProbability: optionalProbability(
        valueOf(model, 'phishingProbability', 'phishing_probability'),
        'AI phishing probability',
      ),
      chunks: optionalNumber(model.chunks),
      aggregation: optionalString(model.aggregation),
      error: optionalString(model.error),
    };
  });
  const combinedRaw = valueOf(analysis, 'combinedAiSignal', 'combined_ai_signal');
  const combinedRecord = combinedRaw == null
    ? undefined
    : record(combinedRaw, 'combined AI signal');
  const aggregatePhishingProbability = optionalProbability(
    valueOf(analysis, 'aggregatePhishingProbability', 'aggregate_phishing_probability'),
    'AI aggregate phishing probability',
  );
  const aggregateBenignProbability = optionalProbability(
    valueOf(analysis, 'aggregateBenignProbability', 'aggregate_benign_probability'),
    'AI aggregate benign probability',
  );
  const combinedPhishingProbability = combinedRecord
    ? optionalProbability(
        valueOf(combinedRecord, 'phishingProbability', 'phishing_probability'),
        'combined AI phishing probability',
      )
    : undefined;
  const combinedBenignProbability = combinedRecord
    ? optionalProbability(
        valueOf(combinedRecord, 'benignProbability', 'benign_probability'),
        'combined AI benign probability',
      )
    : undefined;
  const probabilityPairs = models.filter(
    (model) =>
      model.status === 'AVAILABLE' &&
      model.benignProbability !== undefined &&
      model.phishingProbability !== undefined,
  );
  const expectedPhishingProbability = probabilityPairs.length
    ? Number((
        probabilityPairs.reduce((sum, model) => sum + model.phishingProbability!, 0) /
        probabilityPairs.length
      ).toFixed(6))
    : undefined;
  const expectedBenignProbability = expectedPhishingProbability === undefined
    ? undefined
    : Number((1 - expectedPhishingProbability).toFixed(6));
  if (
    expectedPhishingProbability !== undefined &&
    [aggregatePhishingProbability, combinedPhishingProbability].some(
      (probability) =>
        probability !== undefined &&
        Math.abs(probability - expectedPhishingProbability) > 0.000001,
    )
  ) {
    throw new Error('Invalid FastAPI response: combined phishing probability does not match the model outputs.');
  }
  if (
    expectedBenignProbability !== undefined &&
    [aggregateBenignProbability, combinedBenignProbability].some(
      (probability) =>
        probability !== undefined &&
        Math.abs(probability - expectedBenignProbability) > 0.000001,
    )
  ) {
    throw new Error('Invalid FastAPI response: combined benign probability does not match the model outputs.');
  }
  if (
    combinedRecord &&
    Number(valueOf(combinedRecord, 'modelsUsed', 'models_used')) !== probabilityPairs.length
  ) {
    throw new Error('Invalid FastAPI response: combined AI model count does not match normalized model outputs.');
  }
  if (
    combinedPhishingProbability !== undefined &&
    combinedBenignProbability !== undefined &&
    Math.abs(combinedPhishingProbability + combinedBenignProbability - 1) > 0.000001
  ) {
    throw new Error('Invalid FastAPI response: combined benign and phishing probabilities must sum to 1.');
  }
  return {
    status: stringOf(analysis.status, 'AI analysis status'),
    models,
    aggregatePhishingProbability,
    aggregateBenignProbability,
    combinedAISignal: combinedRecord ? {
      benignProbability: combinedBenignProbability,
      phishingProbability: combinedPhishingProbability,
      modelsUsed: Number(valueOf(combinedRecord, 'modelsUsed', 'models_used')) || 0,
      aggregation: stringOf(combinedRecord.aggregation, 'combined AI aggregation'),
    } : undefined,
    riskContribution: Number(valueOf(analysis, 'riskContribution', 'risk_contribution')) || 0,
    riskWeight: Number(valueOf(analysis, 'riskWeight', 'risk_weight')) || 0,
    phishingThreshold: Number(valueOf(analysis, 'phishingThreshold', 'phishing_threshold')) || 0,
    inputTruncated: valueOf(analysis, 'inputTruncated', 'input_truncated') === true,
    inputCharacters: Number(valueOf(analysis, 'inputCharacters', 'input_characters')) || 0,
  };
}

function arrayOf(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`Invalid FastAPI response: ${label} must be an array.`);
  }
  return value;
}

function nestedRecord(value: unknown): Record<string, Record<string, unknown>> | undefined {
  if (value === undefined || value === null) return undefined;
  const outer = record(value, 'provider results');
  return Object.fromEntries(
    Object.entries(outer).map(([key, entry]) => [key, record(entry, `provider result ${key}`)]),
  );
}

function disagreementRecord(
  value: unknown,
): Record<string, Record<string, string | number | null>> | undefined {
  if (value === undefined || value === null) return undefined;
  const outer = record(value, 'GeoIP provider disagreements');
  return Object.fromEntries(
    Object.entries(outer).map(([field, result]) => {
      const providers = record(result, `GeoIP disagreement ${field}`);
      const values: Record<string, string | number | null> = {};
      for (const [provider, providerValue] of Object.entries(providers)) {
        if (
          providerValue !== null &&
          typeof providerValue !== 'string' &&
          typeof providerValue !== 'number'
        ) {
          throw new Error(`Invalid FastAPI response: GeoIP disagreement ${field} is malformed.`);
        }
        values[provider] = providerValue;
      }
      return [field, values];
    }),
  );
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      ...init,
      headers: { ...(init?.headers || {}) },
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Unable to reach the PRAHARI API at ${BASE || 'the current origin'}${path}. ` +
      `Verify FastAPI is running, VITE_API_URL is correct, and CORS/proxy settings allow this origin. (${detail})`,
    );
  }

  if (!response.ok) {
    const body = await response.text();
    let detail = body || response.statusText;
    try {
      const payload = JSON.parse(body) as JsonRecord;
      const apiDetail = payload.detail;
      if (typeof apiDetail === 'string') detail = apiDetail;
      else if (apiDetail !== undefined) detail = JSON.stringify(apiDetail);
    } catch {
      // Keep the actual response body when the server did not return JSON.
    }
    throw new Error(`PRAHARI API ${response.status}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

function normalizeEmail(raw: unknown): Case['email'] {
  const email = record(raw, 'email');
  const headers = arrayOf(email.headers, 'email.headers').map((item) => {
    const header = record(item, 'email header');
    return {
      name: stringOf(header.name, 'email header name'),
      value: stringOf(header.value, 'email header value'),
    } satisfies EmailHeader;
  });
  const attachments = arrayOf(email.attachments, 'email.attachments').map((item) => {
    const attachment = record(item, 'attachment');
    return {
      filename: stringOf(attachment.filename, 'attachment filename'),
      contentType: stringOf(valueOf(attachment, 'contentType', 'content_type'), 'attachment content type'),
      size: Number(attachment.size) || 0,
      sha256: optionalString(attachment.sha256),
    } satisfies Attachment;
  });
  const receivedPath = arrayOf(
    valueOf(email, 'receivedPath', 'received_path') ?? [],
    'email.received_path',
  ).map((item) => {
    const header = record(item, 'received header');
    return {
      fromHost: optionalString(valueOf(header, 'fromHost', 'from_host')),
      byHost: optionalString(valueOf(header, 'byHost', 'by_host')),
      timestamp: optionalString(header.timestamp),
      ips: arrayOf(header.ips ?? [], 'received header IPs').filter(
        (ip): ip is string => typeof ip === 'string',
      ),
    } satisfies ReceivedHeader;
  });

  return {
    from: stringOf(valueOf(email, 'from', 'from_addr'), 'email.from'),
    to: stringOf(valueOf(email, 'to', 'to_addr'), 'email.to'),
    subject: stringOf(email.subject, 'email.subject'),
    date: stringOf(email.date, 'email.date'),
    replyTo: optionalString(valueOf(email, 'replyTo', 'reply_to')),
    messageId: optionalString(valueOf(email, 'messageId', 'message_id')),
    headers,
    bodyText: stringOf(valueOf(email, 'bodyText', 'body_text'), 'email.body_text'),
    attachments,
    receivedIPs: arrayOf(
      valueOf(email, 'receivedIPs', 'received_ips'),
      'email.received_ips',
    ).filter((ip): ip is string => typeof ip === 'string'),
    receivedPath,
    urls: arrayOf(email.urls, 'email.urls').filter(
      (url): url is string => typeof url === 'string',
    ),
    emailAddresses: arrayOf(
      valueOf(email, 'emailAddresses', 'email_addresses'),
      'email.email_addresses',
    ).filter((address): address is string => typeof address === 'string'),
  };
}

function normalizeIOC(raw: unknown): IOC {
  const item = record(raw, 'IOC');
  const type = stringOf(item.type, 'IOC type').toUpperCase();
  if (!(['IP', 'DOMAIN', 'URL', 'EMAIL', 'HASH'] as string[]).includes(type)) {
    throw new Error(`Invalid FastAPI response: unsupported IOC type "${type}".`);
  }
  const value = stringOf(item.value, 'IOC value');
  const rawIntelligence = item.intelligence;
  let intelligence: IOCIntelligence | undefined;
  if (rawIntelligence && typeof rawIntelligence === 'object') {
    const rawIntel = record(rawIntelligence, 'IOC intelligence');
    const reputation = typeof rawIntel.reputation === 'number' ? rawIntel.reputation : undefined;
    const lookupStatus = optionalString(valueOf(rawIntel, 'lookupStatus', 'lookup_status'))
      ?? optionalString(rawIntel.status);
    const rawReputationStatus = optionalString(
      valueOf(rawIntel, 'reputationStatus', 'reputation_status')
        ?? valueOf(item, 'reputationStatus', 'reputation_status'),
    );
    const reputationStatus: IOCReputationStatus = lookupStatus !== 'FOUND' || reputation === undefined
      ? 'UNKNOWN'
      : ['MALICIOUS', 'SUSPICIOUS', 'CLEAN', 'UNKNOWN'].includes(rawReputationStatus || '')
        ? rawReputationStatus as IOCReputationStatus
        : reputation >= 90 ? 'MALICIOUS'
          : reputation >= 40 ? 'SUSPICIOUS'
            : 'CLEAN';
    const riskContribution = lookupStatus === 'FOUND'
      && reputation !== undefined
      && reputationStatus !== 'UNKNOWN'
      && reputationStatus !== 'CLEAN'
      ? optionalNumber(valueOf(rawIntel, 'riskContribution', 'risk_contribution'))
        ?? (reputation >= 90 ? 8 : reputation >= 70 ? 5 : reputation >= 40 ? 2 : 0)
      : 0;
    const provider = optionalString(rawIntel.provider);
    const rawSource = optionalString(valueOf(rawIntel, 'lookupSource', 'lookup_source'))
      || provider
      || optionalString(rawIntel.source);
    const lookupSource = reputationStatus !== 'UNKNOWN'
      ? rawSource && !['UNKNOWN', 'UNAVAILABLE', 'NO_DATA'].includes(rawSource.toUpperCase())
        ? rawSource
        : 'Threat intelligence provider'
      : 'No reputation result';
    const rawGeo = rawIntel.geo;
    let geo: IOCIntelligence['geo'];
    if (rawGeo && typeof rawGeo === 'object') {
      const geoData = record(rawGeo, 'IOC GeoIP result');
      const confidence = Number(geoData.confidence);
      const providerResults = nestedRecord(
        valueOf(geoData, 'providerResults', 'provider_results'),
      );
      const domainHostname = optionalString(
        valueOf(geoData, 'domainHostname', 'domain_hostname'),
      );
      const domainHostnameSource = optionalString(
        valueOf(geoData, 'domainHostnameSource', 'domain_hostname_source'),
      );
      const reverseDns = optionalString(
        valueOf(geoData, 'reverseDns', 'reverse_dns'),
      ) ?? (domainHostnameSource === 'DNS_PTR' ? domainHostname : undefined);
      const fieldStatus = optionalStringRecord(
        valueOf(geoData, 'fieldStatus', 'field_status'),
        'GeoIP field status',
      ) ?? Object.fromEntries(
        Object.entries({
          reverse_dns: reverseDns,
          network: optionalString(geoData.network),
          network_type: optionalString(valueOf(geoData, 'networkType', 'network_type')),
          infrastructure_type: optionalString(valueOf(geoData, 'infraType', 'infrastructure_type')),
        }).map(([field, fieldValue]) => {
          const sourceResults = Object.values(providerResults ?? {});
          const ptrResult = providerResults?.DNS_PTR;
          const ptrStatus = typeof ptrResult?.status === 'string' ? ptrResult.status : undefined;
          const status = fieldValue
            ? 'AVAILABLE'
            : field === 'reverse_dns' && ptrStatus === 'ERROR'
              ? 'LOOKUP_FAILED'
              : field === 'reverse_dns' && ptrStatus === 'NOT_FOUND'
                ? 'NOT_AVAILABLE'
                : sourceResults.some(source => source.status === 'FOUND')
                  ? 'NOT_RETURNED_BY_SOURCE'
                  : sourceResults.some(source => source.status === 'ERROR' || source.status === 'TIMEOUT')
                    ? 'LOOKUP_FAILED'
                    : 'NOT_AVAILABLE';
          return [field, status];
        }),
      );
      geo = {
        country: optionalString(geoData.country) || '',
        countryCode: optionalString(valueOf(geoData, 'countryCode', 'country_code')) || '',
        region: optionalString(geoData.region),
        city: optionalString(geoData.city),
        postalCode: optionalString(valueOf(geoData, 'postalCode', 'postal_code')),
        timezone: optionalString(geoData.timezone),
        lat: optionalNumber(valueOf(geoData, 'lat', 'latitude')),
        lon: optionalNumber(valueOf(geoData, 'lon', 'longitude')),
        asn: optionalString(geoData.asn) || '',
        asnName: optionalString(valueOf(geoData, 'asnName', 'asn_name')) || '',
        isp: optionalString(geoData.isp),
        org: optionalString(geoData.org),
        network: optionalString(geoData.network),
        domainHostname,
        domainHostnameSource,
        networkType: optionalString(valueOf(geoData, 'networkType', 'network_type')),
        infraType: optionalString(valueOf(geoData, 'infraType', 'infrastructure_type')),
        reverseDns,
        geoConfidence: confidence
          ? confidence >= 80 ? 'HIGH' : confidence >= 60 ? 'MEDIUM' : 'LOW'
          : undefined,
        source: stringOf(geoData.source, 'GeoIP source'),
        provider: optionalString(geoData.provider),
        status: optionalString(geoData.status) as IOCIntelligence['geoStatus'],
        confidence: optionalNumber(geoData.confidence),
        checkedAt: optionalString(valueOf(geoData, 'checkedAt', 'checked_at')),
        accuracyNote: optionalString(valueOf(geoData, 'accuracyNote', 'location_note')),
        accuracyRadiusKm: optionalNumber(valueOf(geoData, 'accuracyRadiusKm', 'accuracy_radius_km')),
        lookupTimestamp: optionalString(valueOf(geoData, 'lookupTimestamp', 'lookup_timestamp'))
          ?? optionalString(valueOf(geoData, 'checkedAt', 'checked_at')),
        fieldStatus,
        providerResults,
        disagreements: disagreementRecord(geoData.disagreements),
        locationNote: optionalString(valueOf(geoData, 'locationNote', 'location_note')),
        raw: geoData.raw,
      };
    }
    intelligence = {
      reputation,
      reputationStatus,
      riskContribution,
      reason: optionalString(rawIntel.reason)
        ?? (reputationStatus === 'UNKNOWN' ? 'No threat-intelligence result available' : undefined),
      firstSeen: optionalString(valueOf(rawIntel, 'firstSeen', 'first_seen')),
      lastSeen: optionalString(valueOf(rawIntel, 'lastSeen', 'last_seen')),
      totalReports: optionalNumber(valueOf(rawIntel, 'totalReports', 'total_reports')),
      tags: arrayOf(rawIntel.tags ?? [], 'IOC intelligence tags').filter(
        (tag): tag is string => typeof tag === 'string',
      ),
      geo,
      whoisRegistrar: optionalString(valueOf(rawIntel, 'whoisRegistrar', 'whois_registrar')),
      whoisCreated: optionalString(valueOf(rawIntel, 'whoisCreated', 'whois_created')),
      source: optionalString(rawIntel.source) || '',
      confidence: optionalNumber(rawIntel.confidence),
      provider,
      lookupSource,
      status: optionalString(rawIntel.status) as IOCIntelligence['status'],
      checkedAt: optionalString(valueOf(rawIntel, 'checkedAt', 'checked_at'))
        ?? optionalString(valueOf(rawIntel, 'lookupTimestamp', 'lookup_timestamp')),
      lookupStatus: lookupStatus as IOCIntelligence['lookupStatus'],
      lookupTimestamp: optionalString(valueOf(rawIntel, 'checkedAt', 'checked_at'))
        ?? optionalString(valueOf(rawIntel, 'lookupTimestamp', 'lookup_timestamp')),
      providerResults: nestedRecord(valueOf(rawIntel, 'providerResults', 'provider_results')),
      geoLookup: rawIntel.geo_lookup && typeof rawIntel.geo_lookup === 'object'
        ? record(rawIntel.geo_lookup, 'IOC GeoIP provider result')
        : undefined,
      geoStatus: optionalString(valueOf(rawIntel, 'geoStatus', 'geo_status')) as IOCIntelligence['geoStatus'],
      domainHostname: optionalString(valueOf(rawIntel, 'domainHostname', 'domain_hostname')),
      domainHostnameSource: optionalString(valueOf(rawIntel, 'domainHostnameSource', 'domain_hostname_source')),
      raw: rawIntel.raw,
    };
  }

  return {
    id: stringOf(item.id, 'IOC id'),
    type: type as IOCType,
    value,
    source: stringOf(item.source, 'IOC source'),
    normalizedValue: stringOf(
      valueOf(item, 'normalizedValue', 'normalized_value') ?? value,
      'IOC normalized_value',
    ),
    valid: item.valid === true,
    confidence: typeof item.confidence === 'number' ? item.confidence : 0,
    risk: stringOf(item.risk, 'IOC risk') as IOC['risk'],
    status: intelligence?.reputationStatus ?? 'UNKNOWN',
    reputationStatus: intelligence?.reputationStatus ?? 'UNKNOWN',
    riskContribution: intelligence?.riskContribution
      ?? optionalNumber(valueOf(item, 'riskContribution', 'risk_contribution'))
      ?? 0,
    lookupSource: optionalString(valueOf(item, 'lookupSource', 'lookup_source'))
      ?? intelligence?.lookupSource,
    lookupStatus: (optionalString(valueOf(item, 'lookupStatus', 'lookup_status'))
      ?? intelligence?.lookupStatus) as IOC['lookupStatus'],
    geoSource: optionalString(valueOf(item, 'geoSource', 'geo_source'))
      ?? intelligence?.geo?.source,
    evidenceCategory: optionalString(valueOf(item, 'evidenceCategory', 'evidence_category')),
    intelligence,
  };
}

export function normalizeCase(raw: unknown): Case {
  const data = record(raw, 'case');
  const risk = record(valueOf(data, 'riskScore', 'risk_score'), 'case risk score');
  const riskComponent = (key: string): RiskScore['content'] => {
    const component = record(risk[key], `risk score ${key}`);
    return {
      score: Number(component.score) || 0,
      max: Number(component.max) || 0,
      ruleScore: optionalNumber(valueOf(component, 'ruleScore', 'rule_score')),
      aiScore: optionalNumber(valueOf(component, 'aiScore', 'ai_score')),
      signals: arrayOf(component.signals ?? [], `risk score ${key} signals`).filter(
        (signal): signal is string => typeof signal === 'string',
      ),
    };
  };
  const total = Number(risk.total);
  const confidence = Number(risk.confidence);
  const level = stringOf(risk.level, 'risk score level');
  if (!Number.isFinite(total) || !Number.isFinite(confidence)) {
    throw new Error('Invalid FastAPI response: risk score values are not numeric.');
  }
  const riskScore: RiskScore = {
    total,
    level: level as RiskLevel,
    confidence,
    evidenceCoverage: (() => {
      const rawCoverage = valueOf(risk, 'evidenceCoverage', 'evidence_coverage');
      if (!rawCoverage || typeof rawCoverage !== 'object') return undefined;
      const coverage = record(rawCoverage, 'evidence coverage');
      const rawCategories = record(coverage.categories, 'evidence coverage categories');
      const categories: EvidenceCoverage['categories'] = {};
      for (const [key, rawCategory] of Object.entries(rawCategories)) {
        const category = record(rawCategory, `evidence coverage category ${key}`);
        const status = stringOf(category.status, `evidence coverage ${key} status`);
        if (!['AVAILABLE', 'PARTIAL', 'UNAVAILABLE', 'NOT_APPLICABLE'].includes(status)) {
          throw new Error(`Invalid FastAPI response: unsupported evidence coverage status ${status}.`);
        }
        categories[key] = {
          label: stringOf(category.label, `evidence coverage ${key} label`),
          status: status as EvidenceCoverageCategory['status'],
          detail: stringOf(category.detail, `evidence coverage ${key} detail`),
        };
      }
      const stringList = (key: string) =>
        arrayOf(coverage[key] ?? [], `evidence coverage ${key}`).filter(
          (value): value is string => typeof value === 'string',
        );
      const normalized: EvidenceCoverage = {
        percentage: Number(coverage.percentage),
        availableCount: Number(valueOf(coverage, 'availableCount', 'available_count')),
        partialCount: Number(valueOf(coverage, 'partialCount', 'partial_count')),
        unavailableCount: Number(valueOf(coverage, 'unavailableCount', 'unavailable_count')),
        applicableCount: Number(valueOf(coverage, 'applicableCount', 'applicable_count')),
        categories,
        available: stringList('available'),
        partial: stringList('partial'),
        unavailable: stringList('unavailable'),
        notApplicable: stringList('not_applicable'),
        summary: stringOf(coverage.summary, 'evidence coverage summary'),
      };
      if (!Number.isFinite(normalized.percentage)) {
        throw new Error('Invalid FastAPI response: evidence coverage percentage is not numeric.');
      }
      return normalized;
    })(),
    content: riskComponent('content'),
    authentication: riskComponent('authentication'),
    reputation: riskComponent('reputation'),
    infrastructure: riskComponent('infrastructure'),
    explanation: optionalString(risk.explanation) || '',
  };
  const aiAnalysis = normalizeAIAnalysis(
    valueOf(data, 'aiAnalysis', 'ai_analysis') ?? risk.ai_analysis,
  );

  const rawAuth = record(data.auth, 'case authentication');
  const auth: AuthResult = {
    spf: stringOf(rawAuth.spf, 'SPF status') as AuthResult['spf'],
    spfDetail: optionalString(valueOf(rawAuth, 'spfDetail', 'spf_detail')),
    dkim: stringOf(rawAuth.dkim, 'DKIM status') as AuthResult['dkim'],
    dkimDetail: optionalString(valueOf(rawAuth, 'dkimDetail', 'dkim_detail')),
    dmarc: stringOf(rawAuth.dmarc, 'DMARC status') as AuthResult['dmarc'],
    dmarcDetail: optionalString(valueOf(rawAuth, 'dmarcDetail', 'dmarc_detail')),
    summary: stringOf(rawAuth.summary, 'authentication summary'),
  };
  const iocs = arrayOf(data.iocs, 'case IOCs').map(normalizeIOC);
  const mitreMappings: MitreMapping[] = arrayOf(
    valueOf(data, 'mitreMappings', 'mitre_mappings'),
    'case MITRE mappings',
  ).map((rawMapping) => {
    const mapping = record(rawMapping, 'MITRE mapping');
    return {
      techniqueId: stringOf(valueOf(mapping, 'techniqueId', 'technique_id'), 'MITRE technique ID'),
      techniqueName: stringOf(valueOf(mapping, 'techniqueName', 'technique_name'), 'MITRE technique name'),
      tactic: stringOf(mapping.tactic, 'MITRE tactic'),
      tacticId: stringOf(valueOf(mapping, 'tacticId', 'tactic_id'), 'MITRE tactic ID'),
      description: stringOf(mapping.description, 'MITRE description'),
      evidence: arrayOf(mapping.evidence, 'MITRE evidence').filter(
        (evidence): evidence is string => typeof evidence === 'string',
      ),
    };
  });
  const timeline: TimelineEvent[] = arrayOf(data.timeline, 'case timeline').map((rawEvent) => {
    const event = record(rawEvent, 'timeline event');
    return {
      id: stringOf(event.id, 'timeline event ID'),
      timestamp: stringOf(event.timestamp, 'timeline timestamp'),
      event: stringOf(event.event, 'timeline event name'),
      detail: stringOf(event.detail, 'timeline detail'),
      type: stringOf(event.type, 'timeline event type') as TimelineEvent['type'],
      isDemo: event.is_demo === true || event.isDemo === true,
    };
  });
  const graphNodes: GraphNode[] = arrayOf(
    valueOf(data, 'graphNodes', 'graph_nodes'),
    'case graph nodes',
  ).map((rawNode) => {
    const node = record(rawNode, 'graph node');
    return {
      id: stringOf(node.id, 'graph node ID'),
      type: stringOf(node.type, 'graph node type') as GraphNode['type'],
      label: stringOf(node.label, 'graph node label'),
      detail: optionalString(node.detail),
      risk: optionalString(node.risk) as GraphNode['risk'],
      x: Number(node.x),
      y: Number(node.y),
    };
  });
  const graphEdges: GraphEdge[] = arrayOf(
    valueOf(data, 'graphEdges', 'graph_edges'),
    'case graph edges',
  ).map((rawEdge) => {
    const edge = record(rawEdge, 'graph edge');
    return {
      id: stringOf(edge.id, 'graph edge ID'),
      source: stringOf(edge.source, 'graph edge source'),
      target: stringOf(edge.target, 'graph edge target'),
      label: optionalString(edge.label),
    };
  });

  const createdAt = stringOf(valueOf(data, 'createdAt', 'created_at'), 'case creation time');
  return {
    id: stringOf(data.id, 'case ID'),
    createdAt,
    threatType: optionalThreatType(valueOf(data, 'threatType', 'threat_type')),
    analysisTimestamp: optionalString(
      valueOf(data, 'analysisTimestamp', 'analysis_timestamp'),
    ) || createdAt,
    severity: stringOf(data.severity, 'case severity') as RiskLevel,
    verdict: stringOf(data.verdict, 'case verdict') as Verdict,
    email: normalizeEmail(data.email),
    auth,
    iocs,
    riskScore,
    aiAnalysis,
    mitreMappings,
    timeline,
    graphNodes,
    graphEdges,
    summary: stringOf(data.summary, 'case summary'),
    whyFlagged: arrayOf(
      valueOf(data, 'whyFlagged', 'why_flagged'),
      'case why_flagged',
    ).filter((signal): signal is string => typeof signal === 'string'),
    evidenceCount: Number(valueOf(data, 'evidenceCount', 'evidence_count')) || 0,
    isDemo: valueOf(data, 'isDemo', 'is_demo') === true,
  };
}

function normalizeCaseListItem(raw: unknown): CaseListItem {
  const item = record(raw, 'case list item');
  return {
    id: stringOf(item.id, 'case list ID'),
    subject: stringOf(item.subject, 'case list subject'),
    riskScore: Number(valueOf(item, 'riskScore', 'risk_score_total')) || 0,
    verdict: stringOf(item.verdict, 'case list verdict') as Verdict,
    iocCount: Number(valueOf(item, 'iocCount', 'ioc_count')) || 0,
    status: stringOf(item.verdict, 'case list status'),
    timestamp: stringOf(valueOf(item, 'timestamp', 'created_at'), 'case list timestamp'),
    severity: stringOf(item.severity, 'case list severity') as RiskLevel,
    threatType: optionalThreatType(valueOf(item, 'threatType', 'threat_type')),
  };
}

export const api = {
  isAvailable: (): boolean => true,

  uploadEmail: async (file: File): Promise<Case> => {
    const form = new FormData();
    form.append('file', file);
    const raw = await request<unknown>('/api/email/upload', {
      method: 'POST',
      body: form,
    });
    return normalizeCase(raw);
  },

  listCases: async (): Promise<CaseListItem[]> => {
    const raw = await request<unknown[]>('/api/cases');
    return raw.map(normalizeCaseListItem);
  },

  getCase: async (id: string): Promise<Case> =>
    normalizeCase(await request<unknown>(`/api/cases/${encodeURIComponent(id)}`)),

  deleteCase: (id: string): Promise<unknown> =>
    request(`/api/cases/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  lookupIOC: (value: string, type = 'IP'): Promise<unknown> =>
    request(`/api/ioc/lookup?value=${encodeURIComponent(value)}&type=${encodeURIComponent(type)}`),

  getLocalDB: (): Promise<unknown> => request('/api/ioc/db'),

  reportJsonUrl: (id: string): string =>
    `${BASE}/api/reports/${encodeURIComponent(id)}/json`,

  reportHtmlUrl: (id: string): string =>
    `${BASE}/api/reports/${encodeURIComponent(id)}/html`,
};
