"""Audit logging service for compliance tracking."""
from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from app.models.user import AuditLog
from app.core.enums import AuditEventType, AuditEventStatus


class AuditService:
    """Handles immutable audit logging for HIPAA compliance."""

    def __init__(self, db: Session):
        """Initialize audit service.

        Args:
            db: Database session
        """
        self.db = db

    def log_event(
        self,
        event_type: AuditEventType,
        status: AuditEventStatus,
        resource_type: str,
        action: str,
        user_id: Optional[int] = None,
        resource_id: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """Log an audit event.

        Args:
            event_type: Type of event
            status: Event outcome status
            resource_type: Type of resource affected
            action: Specific action performed
            user_id: ID of user performing action
            resource_id: ID of affected resource
            details: Additional event details (will be redacted if sensitive)
            ip_address: IP address of requester
            user_agent: User agent of requester

        Returns:
            AuditLog: Created audit log entry
        """
        # Redact sensitive information from details
        redacted_details = self._redact_sensitive_data(details) if details else None

        # Create audit log entry
        audit_log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            status=status,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            details=redacted_details,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.now(timezone.utc),
        )

        self.db.add(audit_log)
        self.db.commit()
        self.db.refresh(audit_log)

        return audit_log

    def _redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive information from audit log details.

        Args:
            text: Text to redact

        Returns:
            str: Redacted text
        """
        # List of patterns to redact
        sensitive_keywords = [
            "password",
            "ssn",
            "credit_card",
            "cvv",
            "secret",
            "token",
            "key",
        ]

        redacted_text = text
        for keyword in sensitive_keywords:
            redacted_text = redacted_text.replace(
                keyword.lower(),
                "[REDACTED]",
            )

        return redacted_text

    def get_audit_logs(
        self,
        user_id: Optional[int] = None,
        event_type: Optional[AuditEventType] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AuditLog], int]:
        """Query audit logs with filters.

        Args:
            user_id: Filter by user ID
            event_type: Filter by event type
            resource_type: Filter by resource type
            start_date: Filter from date
            end_date: Filter to date
            limit: Number of results
            offset: Pagination offset

        Returns:
            tuple: (audit_logs, total_count)
        """
        query = self.db.query(AuditLog)

        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if event_type:
            query = query.filter(AuditLog.event_type == event_type)
        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)

        total_count = query.count()
        audit_logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()

        return audit_logs, total_count
