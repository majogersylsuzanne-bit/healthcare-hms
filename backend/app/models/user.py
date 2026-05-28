"""User and authentication-related database models."""
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Table,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime, timezone
from app.core.enums import RoleType, PortalType, PermissionAction, AuditEventType, AuditEventStatus
from app.database import Base


# Association table for users and roles (many-to-many)
user_role = Table(
    "user_role",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    """User model for authentication and authorization."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(RoleType), nullable=False, index=True)
    portal = Column(Enum(PortalType), nullable=False, index=True)
    is_active = Column(Boolean, default=True, index=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    last_login = Column(DateTime, nullable=True, index=True)
    last_login_ip = Column(String(45), nullable=True)
    login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user")
    roles = relationship("Role", secondary=user_role, back_populates="users")

    # Indexes for common queries
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        Index("ix_users_role_portal", "role", "portal"),
        Index("ix_users_active_created", "is_active", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"


class Role(Base):
    """Role model for RBAC."""

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    role_type = Column(Enum(RoleType), unique=True, nullable=False, index=True)
    description = Column(String(500), nullable=True)
    portal = Column(Enum(PortalType), nullable=False, index=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    users = relationship("User", secondary=user_role, back_populates="roles")
    permissions = relationship("Permission", back_populates="role", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("name", "portal", name="uq_roles_name_portal"),
        Index("ix_roles_portal_active", "portal", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<Role(id={self.id}, name={self.name}, role_type={self.role_type})>"


class Permission(Base):
    """Permission model for fine-grained access control."""

    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    resource = Column(String(100), nullable=False)
    action = Column(Enum(PermissionAction), nullable=False)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    role = relationship("Role", back_populates="permissions")

    __table_args__ = (
        UniqueConstraint("role_id", "resource", "action", name="uq_permissions_role_resource_action"),
        Index("ix_permissions_resource_action", "resource", "action"),
    )

    def __repr__(self) -> str:
        return f"<Permission(role_id={self.role_id}, resource={self.resource}, action={self.action})>"


class AuditLog(Base):
    """Immutable audit log for compliance tracking."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(Enum(AuditEventType), nullable=False, index=True)
    status = Column(Enum(AuditEventStatus), nullable=False)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(255), nullable=True, index=True)
    action = Column(String(100), nullable=False)
    details = Column(String(1000), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_timestamp_event", "timestamp", "event_type"),
        Index("ix_audit_logs_user_timestamp", "user_id", "timestamp"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, event_type={self.event_type}, status={self.status}, timestamp={self.timestamp})>"
