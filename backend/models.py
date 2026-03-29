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
    tls_version: str | None
    cipher_suite: str | None
    key_algorithm: str | None
    key_size: int | None
    signature_algorithm: str | None
    certificate_expiry: str | None


class TlsResultsResponse(BaseModel):
    """Response listing TLS results for a scan."""
    scan_id: int
    results: list[TlsResultItem]


class QuantumRiskResultItem(BaseModel):
    """Single Quantum Risk assessment result."""
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


class AssetScoreBreakdown(BaseModel):
    """Component scores for the quantum risk."""
    key_exchange: int
    signature: int
    tls: int
    key_size: int
    certificate: int
    cipher: int


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

