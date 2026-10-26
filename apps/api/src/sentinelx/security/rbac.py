"""Roles and permissions. Least privilege; enforced server-side on every endpoint."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    SUPER_ADMIN = "SUPER_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    IT_OPERATOR = "IT_OPERATOR"
    VIEWER = "VIEWER"


class Perm(StrEnum):
    INCIDENT_READ = "incident:read"
    INCIDENT_CREATE = "incident:create"
    INCIDENT_UPDATE = "incident:update"
    INCIDENT_CLOSE = "incident:close"
    ALERT_READ = "alert:read"
    EVENT_READ = "event:read"
    ASSET_READ = "asset:read"
    ASSET_UPDATE = "asset:update"
    RULE_READ = "rule:read"
    RULE_MANAGE = "rule:manage"
    THREATINTEL_READ = "threatintel:read"
    THREATINTEL_MANAGE = "threatintel:manage"
    AI_INVESTIGATE = "ai:investigate"
    RESPONSE_EXECUTE = "response:execute"
    REPORT_GENERATE = "report:generate"
    INGEST_WRITE = "ingest:write"
    AUDIT_READ = "audit:read"
    ADMIN_MANAGE = "admin:manage"
    TENANT_SWITCH = "tenant:switch"
    PLATFORM_MANAGE = "platform:manage"  # installation-wide: rule repository, custom rules, organizations, demo


_READ = {Perm.INCIDENT_READ, Perm.ALERT_READ, Perm.EVENT_READ, Perm.ASSET_READ, Perm.RULE_READ, Perm.THREATINTEL_READ}

ROLE_PERMISSIONS: dict[Role, frozenset[Perm]] = {
    Role.VIEWER: frozenset(_READ),
    Role.IT_OPERATOR: frozenset(_READ | {Perm.ASSET_UPDATE, Perm.INCIDENT_UPDATE, Perm.REPORT_GENERATE}),
    Role.SECURITY_ANALYST: frozenset(
        _READ
        | {
            Perm.INCIDENT_CREATE,
            Perm.INCIDENT_UPDATE,
            Perm.INCIDENT_CLOSE,
            Perm.ASSET_UPDATE,
            Perm.THREATINTEL_MANAGE,
            Perm.AI_INVESTIGATE,
            Perm.RESPONSE_EXECUTE,
            Perm.REPORT_GENERATE,
        }
    ),
    Role.TENANT_ADMIN: frozenset(set(Perm) - {Perm.TENANT_SWITCH, Perm.PLATFORM_MANAGE}),
    Role.SUPER_ADMIN: frozenset(Perm),
}

ROLE_DESCRIPTIONS = {
    Role.SUPER_ADMIN: "Full control of every organization (tenant) on this SentinelX installation.",
    Role.TENANT_ADMIN: "Manages users, rules, integrations and settings of their organization.",
    Role.SECURITY_ANALYST: "Investigates and resolves incidents, uses the AI analyst, manages threat intel.",
    Role.IT_OPERATOR: "Views security data, updates assets and incident status, generates reports.",
    Role.VIEWER: "Read-only access to incidents, alerts, events and assets.",
}


# Plain-language wording shown to people on their account page, so everyone can see what their role allows.
PERM_DESCRIPTIONS: dict[Perm, str] = {
    Perm.INCIDENT_READ: "View incidents, the dashboard and ATT&CK coverage",
    Perm.INCIDENT_CREATE: "Open incidents by hand and merge duplicates",
    Perm.INCIDENT_UPDATE: "Change incident status and owner, add notes, complete tasks",
    Perm.INCIDENT_CLOSE: "Resolve and close incidents and record a verdict",
    Perm.ALERT_READ: "View alerts",
    Perm.EVENT_READ: "Search raw security events",
    Perm.ASSET_READ: "View assets and monitored identities",
    Perm.ASSET_UPDATE: "Change asset criticality and identity details",
    Perm.RULE_READ: "View detection rules and integrations",
    Perm.RULE_MANAGE: "Turn detection rules on or off and retrain the ML model",
    Perm.THREATINTEL_READ: "View threat-intelligence indicators",
    Perm.THREATINTEL_MANAGE: "Add, import and remove threat-intelligence indicators",
    Perm.AI_INVESTIGATE: "Ask the AI analyst to investigate an incident",
    Perm.RESPONSE_EXECUTE: "Record response actions (tasks, watchlist entries)",
    Perm.REPORT_GENERATE: "Download incident reports",
    Perm.INGEST_WRITE: "Send telemetry to SentinelX",
    Perm.AUDIT_READ: "Read the audit log",
    Perm.ADMIN_MANAGE: "Manage users, ingest tokens and organization settings",
    Perm.TENANT_SWITCH: "Switch between organizations",
    Perm.PLATFORM_MANAGE: "Manage the installation: organizations, custom rules, demo data",
}


def permissions_for(role: str) -> frozenset[Perm]:
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()


ROLE_ORDER = [Role.VIEWER, Role.IT_OPERATOR, Role.SECURITY_ANALYST, Role.TENANT_ADMIN, Role.SUPER_ADMIN]


def _rank(role: str) -> int:
    try:
        return ROLE_ORDER.index(Role(role))
    except ValueError:
        return -1


def can_assign(actor_role: str, target_role: str) -> bool:
    """Which roles an actor may grant. SUPER_ADMIN may grant any role; everyone else only roles strictly
    below their own (an admin cannot mint more admins - least privilege, no lateral escalation)."""
    if _rank(actor_role) < 0 or _rank(target_role) < 0:
        return False
    if actor_role == Role.SUPER_ADMIN:
        return True
    return _rank(target_role) < _rank(actor_role)


def can_manage(actor_role: str, target_role: str) -> bool:
    """Whether an actor may modify (role, activation, name) an existing user with ``target_role``.
    Same rule as granting: peers cannot lock each other out; only SUPER_ADMIN manages admins."""
    return can_assign(actor_role, target_role)
