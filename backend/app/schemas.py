from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Any
from datetime import datetime


class GeoContext(BaseModel):
    country: str = ""
    country_code: str = ""
    region: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: Optional[float] = None
    location_note: Optional[str] = None
    asn: str = ""
    asn_name: str = ""
    isp: Optional[str] = None
    org: Optional[str] = None
    reverse_dns: Optional[str] = None
    network: Optional[str] = None
    network_type: Optional[str] = None
    infrastructure_type: Optional[str] = None
    domain_hostname: Optional[str] = None
    domain_hostname_source: Optional[str] = None
    source: str = "UNKNOWN"
    provider: Optional[str] = None
    status: Optional[str] = None
    checked_at: Optional[str] = None
    confidence: Optional[int] = None
    field_status: Optional[dict[str, str]] = None
    provider_results: Optional[dict[str, Any]] = None
    disagreements: Optional[dict[str, Any]] = None
    raw: Optional[Any] = None


class IOCIntelligence(BaseModel):
    reputation: Optional[int] = None
    reputation_status: str = "UNKNOWN"
    risk_contribution: int = 0
    reason: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_reports: Optional[int] = None
    tags: List[str] = []
    geo: Optional[GeoContext] = None
    whois_registrar: Optional[str] = None
    whois_created: Optional[str] = None
    source: str = "UNKNOWN"
    confidence: Optional[int] = None
    provider: Optional[str] = None
    lookup_source: Optional[str] = None
    status: Optional[str] = None
    checked_at: Optional[str] = None
    lookup_status: Optional[str] = None
    lookup_timestamp: Optional[str] = None
    provider_results: Optional[dict[str, Any]] = None
    geo_status: Optional[str] = None
    geo_lookup: Optional[dict[str, Any]] = None
    domain_hostname: Optional[str] = None
    domain_hostname_source: Optional[str] = None
    raw: Optional[Any] = None


class IOCOut(BaseModel):
    id: str
    type: str
    value: str
    source: str
    risk: str
    status: str
    normalized_value: str
    valid: bool
    confidence: int
    reputation_status: str = "UNKNOWN"
    risk_contribution: int = 0
    lookup_source: Optional[str] = None
    lookup_status: str = "UNAVAILABLE"
    geo_source: Optional[str] = None
    evidence_category: str = "Email evidence"
    intelligence: Optional[IOCIntelligence] = None

    class Config:
        from_attributes = True


class AuthResult(BaseModel):
    spf: str
    spf_detail: Optional[str] = None
    dkim: str
    dkim_detail: Optional[str] = None
    dmarc: str
    dmarc_detail: Optional[str] = None
    summary: str


class ScoreComponent(BaseModel):
    score: int
    max: int
    signals: List[str]
    rule_score: Optional[int] = None
    ai_score: Optional[int] = None


class RiskScore(BaseModel):
    total: int
    level: str
    confidence: float
    evidence_coverage: dict[str, Any] = Field(default_factory=dict)
    content: ScoreComponent
    authentication: ScoreComponent
    reputation: ScoreComponent
    infrastructure: ScoreComponent
    explanation: str


class ModelClassProbability(BaseModel):
    label: str
    normalized_label: Optional[str] = None
    probability: float = Field(ge=0, le=1)


class AIModelResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    name: str
    model_id: str
    status: str
    labels: Optional[List[ModelClassProbability]] = None
    class_mapping: dict[str, str] = Field(default_factory=dict)
    predicted_label: Optional[str] = None
    predicted_class: Optional[str] = None
    benign_probability: Optional[float] = Field(default=None, ge=0, le=1)
    phishing_probability: Optional[float] = Field(default=None, ge=0, le=1)
    chunks: Optional[int] = None
    aggregation: Optional[str] = None
    error: Optional[str] = None


class AIAnalysis(BaseModel):
    status: str
    models: List[AIModelResult]
    aggregate_phishing_probability: Optional[float] = Field(default=None, ge=0, le=1)
    aggregate_benign_probability: Optional[float] = Field(default=None, ge=0, le=1)
    combined_ai_signal: Optional[dict[str, Any]] = None
    risk_contribution: int = Field(default=0, ge=0)
    risk_weight: int = Field(default=0, ge=0, le=25)
    phishing_threshold: float = Field(default=0.5, ge=0, le=1)
    input_truncated: bool = False
    input_characters: int = Field(default=0, ge=0)


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    description: str
    evidence: List[str]


class TimelineEvent(BaseModel):
    id: str
    timestamp: str
    event: str
    detail: str
    type: str
    is_demo: bool = False


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    detail: Optional[str] = None
    risk: Optional[str] = None
    x: float
    y: float


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = None


class EmailSummary(BaseModel):
    from_addr: str
    to_addr: str
    subject: str
    date: str
    reply_to: Optional[str] = None
    message_id: Optional[str] = None
    received_ips: List[str] = []
    received_path: List[dict] = []
    urls: List[str] = []
    email_addresses: List[str] = []
    headers: List[dict] = []
    attachments: List[dict] = []
    body_text: str = ""


class CaseOut(BaseModel):
    id: str
    created_at: datetime
    threat_type: Optional[str] = None
    severity: str
    verdict: str
    is_demo: bool
    risk_score: RiskScore
    ai_analysis: Optional[AIAnalysis] = None
    email: EmailSummary
    auth: AuthResult
    iocs: List[IOCOut]
    mitre_mappings: List[MitreMapping]
    timeline: List[TimelineEvent]
    graph_nodes: List[GraphNode]
    graph_edges: List[GraphEdge]
    why_flagged: List[str]
    summary: str
    evidence_count: int

    class Config:
        from_attributes = True


class CaseListItem(BaseModel):
    id: str
    created_at: datetime
    threat_type: Optional[str] = None
    verdict: str
    severity: str
    risk_score_total: int
    from_addr: str
    subject: str
    ioc_count: int
    is_demo: bool

    class Config:
        from_attributes = True


class IOCLookupResult(BaseModel):
    value: str
    found: bool
    intelligence: Optional[IOCIntelligence] = None


class NLPResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    signals: List[str]
    score_contribution: int
    model_used: str
    is_rule_based: bool
