"""Typed cross-service flows built on the mesh.

Each function is one business-meaningful integration between two services.
All are fail-closed: when the peer is unconfigured or unreachable the
caller gets status="unavailable" with a reason and continues degraded —
never an exception, never an invented enrichment.
"""

from __future__ import annotations

from typing import Any, Optional

from mesh import Mesh, get_mesh


# ---------------------------------------------------------------------------
# intel-service — national / cultural fraud intelligence
# ---------------------------------------------------------------------------

def intel_national_summary(mesh: Optional[Mesh] = None) -> dict[str, Any]:
    """National fraud-rate posterior + trend + top typologies."""
    return (mesh or get_mesh()).intel.get("/v1/intel/national/summary")


def intel_state(code: str, mesh: Optional[Mesh] = None) -> dict[str, Any]:
    """State-level posterior (e.g. 'LA' for Lagos) for geo-risk enrichment."""
    return (mesh or get_mesh()).intel.get(f"/v1/intel/states/{code}")


def intel_hotspots(mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return (mesh or get_mesh()).intel.get("/v1/intel/hotspots")


# ---------------------------------------------------------------------------
# kyc-api — identity screening + risk
# ---------------------------------------------------------------------------

def kyc_pep_screening(name: str, mesh: Optional[Mesh] = None,
                      **extra) -> dict[str, Any]:
    """Screen a person name against the PEP list (for land sellers, KYB
    beneficial owners, etc. — any service that meets a new identity)."""
    payload = {"name": name, **extra}
    return (mesh or get_mesh()).kyc.post("/api/v1/screening/pep", payload)


def kyc_sanctions_screening(name: str, mesh: Optional[Mesh] = None,
                            **extra) -> dict[str, Any]:
    payload = {"name": name, **extra}
    return (mesh or get_mesh()).kyc.post("/api/v1/screening/sanctions",
                                         payload)


def kyc_fraud_check(payload: dict, mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return (mesh or get_mesh()).kyc.post("/api/v1/risk/fraud-check", payload)


# ---------------------------------------------------------------------------
# land-verification-service
# ---------------------------------------------------------------------------

def land_verification_status(verification_id: str,
                             mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return (mesh or get_mesh()).land.get(
        f"/api/v1/status/{verification_id}")


def land_verify(payload: dict, mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return (mesh or get_mesh()).land.post("/api/v1/verify", payload)


# ---------------------------------------------------------------------------
# onboarding-service — KYB lifecycle
# ---------------------------------------------------------------------------

def onboarding_kyb_status(app_id: str,
                          mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return (mesh or get_mesh()).onboarding.get(
        f"/api/v1/onboarding/kyb/{app_id}")


# ---------------------------------------------------------------------------
# doc-verification intelligence engine (HTTP mode — in-process embedding
# stays the default; DOC_INTEL_URL enables the sidecar deployment)
# ---------------------------------------------------------------------------

def doc_intel_analyze(payload: dict, mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return (mesh or get_mesh()).doc_intel.post("/documents/intelligence",
                                               payload)


# ---------------------------------------------------------------------------
# fraud-signals-service — developing-market fraud detectors
# ---------------------------------------------------------------------------

def fraud_signal(detector: str, subject_id: str, payload: dict,
                 events: Optional[list] = None,
                 mesh: Optional[Mesh] = None) -> dict[str, Any]:
    """Evaluate one fraud-signal detector via the mesh.

    Returns the service's {score, verdict, factors, audit_hash} envelope, or
    the mesh's fail-closed {"status": "unavailable", ...} when the service is
    down — callers MUST treat both as advisory unless they explicitly check
    the verdict field.
    """
    body: dict[str, Any] = {"subject_id": subject_id, "payload": payload}
    if events is not None:
        body["events"] = events
    return (mesh or get_mesh()).fraud_signals.post(
        f"/api/v1/signals/{detector}", body)


def fraud_signal_app_scam(subject_id: str, payload: dict,
                          mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("app_scam", subject_id, payload, mesh=mesh)


def fraud_signal_mule(subject_id: str, payload: dict,
                      events: Optional[list] = None,
                      mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("mule", subject_id, payload, events=events, mesh=mesh)


def fraud_signal_agent(subject_id: str, payload: dict,
                       mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("agent", subject_id, payload, mesh=mesh)


def fraud_signal_loan_stacking(subject_id: str, payload: dict,
                               mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("loan_stacking", subject_id, payload, mesh=mesh)


def fraud_signal_issuance(subject_id: str, payload: dict,
                          mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("issuance", subject_id, payload, mesh=mesh)


def fraud_signal_channel(subject_id: str, payload: dict,
                         mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("channel", subject_id, payload, mesh=mesh)


def fraud_signal_ghost_payroll(subject_id: str, payload: dict,
                               mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("ghost_payroll", subject_id, payload, mesh=mesh)


def fraud_signal_subsidy(subject_id: str, payload: dict,
                         mesh: Optional[Mesh] = None) -> dict[str, Any]:
    return fraud_signal("subsidy", subject_id, payload, mesh=mesh)
