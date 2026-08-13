"""
Pydantic models for request / response schemas.
"""

from pydantic import BaseModel


class ScanRequest(BaseModel):
    """Incoming scan submission."""
    target: str


class DomainInfo(BaseModel):
    """Parsed domain information."""
    host: str
    parent_domain: str


class ScanResponse(BaseModel):
    """Response returned after creating a scan job."""
    scan_id: int
    status: str


class ScanStatusResponse(BaseModel):
    """Response for polling scan status."""
    scan_id: int
    domain: str
    status: str


class AssetsResponse(BaseModel):
    """Response listing discovered assets for a scan."""
    scan_id: int
    assets: list[str]


class TlsResultItem(BaseModel):
    """Single TLS scan result."""
    id: int
    hostname: str
    port: int
    ip_address: str | None = None
    tls_version: str | None
    cipher_suite: str | None
    key_algorithm: str | None
    key_size: int | None
    signature_algorithm: str | None
    certificate_expiry: str | None
    hostname_mismatch: bool | None = None
    is_self_signed: bool | None = None
    is_expired: bool | None = None
    days_until_expiry: int | None = None
    issuer: str | None = None


class TlsResultsResponse(BaseModel):
    """Response listing TLS results for a scan."""
    scan_id: int
    results: list[TlsResultItem]


class QuantumRiskResultItem(BaseModel):
    """Single Quantum Risk assessment result.

    The first six component fields predate the v2 scoring model and keep
    their original names and meaning; the remaining fields expose the four
    components v2 added plus the scoring stages (composite, floor, HNDL
    uplift) so a consumer can reproduce the total instead of trusting it.
    """
    hostname: str
    port: int
    risk_score: int
    risk_label: str
    key_exchange_score: int
    signature_score: int
    tls_score: int
    key_size_penalty: int
    certificate_validity_score: int
    cipher_score: int
    forward_secrecy_score: int = 0
    cipher_mode_score: int = 0
    hash_score: int = 0
    certificate_trust_score: int = 0
    composite_score: float = 0.0
    applied_floor: str | None = None
    hndl_multiplier: float = 1.0
    hndl_uplift: float = 0.0
    quantum_safe_key_exchange: bool = False
    quantum_safe_signature: bool = False


class QuantumRiskResponse(BaseModel):
    """Response listing Quantum Risk results for a scan."""
    scan_id: int
    results: list[QuantumRiskResultItem]


class HndlResultItem(BaseModel):
    """Single HNDL detection result."""
    hostname: str
    port: int
    service: str
    multiplier: float
    risk: str


class HndlResponse(BaseModel):
    """Response listing HNDL results for a scan."""
    scan_id: int
    targets: list[HndlResultItem]


class AlgorithmAnalysisItem(BaseModel):
    """Single algorithm intelligence analysis result."""
    hostname: str
    cipher_suite: str | None
    key_exchange: str
    signature: str
    encryption: str
    hash: str
    classification: str
    quantum_risk_estimate: int


class AlgorithmAnalysisResponse(BaseModel):
    """Response listing algorithm analysis results for a scan."""
    scan_id: int
    results: list[AlgorithmAnalysisItem]


class ScoreComponent(BaseModel):
    """One weighted component of the quantum risk score."""
    key: str
    label: str
    raw_score: int
    weight: float
    weighted_contribution: float


class AssetScoreBreakdown(BaseModel):
    """Component scores for the quantum risk (raw 0-100, higher is worse)."""
    key_exchange: int
    signature: int
    tls: int
    key_size: int
    certificate: int
    cipher: int
    forward_secrecy: int = 0
    cipher_mode: int = 0
    hash: int = 0
    certificate_trust: int = 0


class AssetDetailsResponse(BaseModel):
    """Detailed drill-down for a single asset."""
    asset_id: int
    host: str
    port: int
    tls_version: str | None
    cipher_suite: str | None
    score: int
    score_breakdown: AssetScoreBreakdown
    key_exchange_algorithm: str | None
    signature_algorithm: str | None
    key_size: int | None
    certificate_expiry: str | None
    hndl_level: str | None
    pqc_recommendations: list[str]
    hostname_mismatch: bool | None = None
    is_self_signed: bool | None = None
    is_expired: bool | None = None
    days_until_expiry: int | None = None
    issuer: str | None = None
    # Full v2 scoring detail: every component ranked by how much it
    # actually contributed to this asset's score, plus the stages that
    # produced the total.
    score_components: list[ScoreComponent] = []
    composite_score: float = 0.0
    applied_floor: str | None = None
    hndl_multiplier: float = 1.0
    hndl_uplift: float = 0.0
    risk_label: str | None = None


class ScanFailureItem(BaseModel):
    """Single scan failure record."""
    id: int
    hostname: str
    failure_category: str
    failure_reason: str
    attempt_count: int
    created_at: str


class ScanFailuresResponse(BaseModel):
    """Response listing failed scan domains for a scan."""
    scan_id: int
    total_failures: int
    failures: list[ScanFailureItem]


class DomainScanHistoryItem(BaseModel):
    """Single scan in a domain's history."""
    scan_id: int
    domain: str
    status: str
    tls_count: int
    failure_count: int
    created_at: str


class AgentChatMessage(BaseModel):
    """Single turn in a Qubit conversation."""
    role: str  # "user" or "assistant"
    content: str


class AgentChatRequest(BaseModel):
    """Request body for the Qubit chat proxy."""
    system: str
    messages: list[AgentChatMessage]


class DomainScanHistoryResponse(BaseModel):
    """Response listing all scans for a specific domain."""
    domain: str
    total_scans: int
    scans: list[DomainScanHistoryItem]


class DomainsListResponse(BaseModel):
    """Response listing all scanned domains."""
    total_domains: int
    domains: list[str]
