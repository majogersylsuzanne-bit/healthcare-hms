"""Enumeration types for the application."""
from enum import Enum


class RoleType(str, Enum):
    """User role types across different portals."""

    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    PROVIDER = "provider"
    PATIENT = "patient"
    PUBLIC_USER = "public_user"


class PortalType(str, Enum):
    """Portal types in the system."""

    PUBLIC = "public"
    PATIENT = "patient"
    PROVIDER = "provider"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class PermissionAction(str, Enum):
    """Permission action types."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXPORT = "export"
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOGS = "view_audit_logs"


class AuditEventType(str, Enum):
    """Audit log event types."""

    USER_LOGIN = "user_login"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    DATA_ACCESSED = "data_accessed"
    DATA_CREATED = "data_created"
    DATA_UPDATED = "data_updated"
    DATA_DELETED = "data_deleted"
    DATA_EXPORTED = "data_exported"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"
    TOKEN_REVOKED = "token_revoked"
    UNAUTHORIZED_ACCESS_ATTEMPT = "unauthorized_access_attempt"


class AuditEventStatus(str, Enum):
    """Audit event outcome status."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
