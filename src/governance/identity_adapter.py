"""Federated-identity claim normalisation for a future API Gateway authorizer.

The Learner Lab console still authenticates local temporary users.  This module
defines the strict trust-boundary contract that a production Cognito/OIDC/SAML
authorizer must satisfy before claims are converted into DataSentinel roles.
It deliberately does not decode or accept unsigned JWTs inside the application.
"""

from dataclasses import dataclass

ROLE_MAP = {
    "datasentinel-admin": "ADMIN",
    "datasentinel-owner": "DATA_OWNER",
    "datasentinel-reviewer": "REVIEWER",
    "datasentinel-auditor": "AUDITOR",
}


@dataclass(frozen=True)
class FederatedPrincipal:
    subject: str
    username: str
    role: str
    tenant_id: str
    issuer: str
    authentication: str = "FEDERATED_AUTHORIZER_CLAIMS"


def principal_from_verified_claims(claims: dict, *, trusted_issuer: str) -> FederatedPrincipal:
    """Convert claims already verified by an upstream authorizer.

    Signature, issuer, audience and expiry verification belongs at API Gateway
    or the selected identity provider.  Missing or ambiguous claims fail closed.
    """

    issuer = str(claims.get("iss", "")).strip()
    subject = str(claims.get("sub", "")).strip()
    username = str(claims.get("preferred_username") or claims.get("email") or "").strip()
    tenant_id = str(claims.get("custom:tenant_id", "")).strip()
    raw_groups = claims.get("cognito:groups") or claims.get("groups") or []
    groups = [raw_groups] if isinstance(raw_groups, str) else list(raw_groups)
    roles = {ROLE_MAP[group] for group in groups if group in ROLE_MAP}

    if issuer != trusted_issuer:
        raise ValueError("Federated issuer is not trusted")
    if not subject or not username or not tenant_id:
        raise ValueError("Federated identity is missing required subject, username or tenant")
    if len(roles) != 1:
        raise ValueError("Federated identity must resolve to exactly one DataSentinel role")
    return FederatedPrincipal(subject, username, roles.pop(), tenant_id, issuer)
