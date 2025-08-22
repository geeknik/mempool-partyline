"""
Security-aware logging configuration
Prevents secrets and sensitive data from being logged
"""

import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional
from logging.handlers import RotatingFileHandler

from partyline.constants import LOG_FILE_MODE


class SecureFilter(logging.Filter):
    """Filter to redact sensitive information from logs"""
    
    # Patterns to redact
    SENSITIVE_PATTERNS = [
        (r'(password|passwd|pwd|secret|token|key|api_key)[\"\']?\s*[:=]\s*[\"\']?([^\s\"\']+)', r'\1=***REDACTED***'),
        (r'(Authorization|X-Api-Key):\s*([^\s]+)', r'\1: ***REDACTED***'),
        (r'([a-fA-F0-9]{64,})', lambda m: m.group(0)[:8] + '...' + m.group(0)[-8:]),  # Long hex strings
        (r'(bitcoin|bc1|tb1|bcrt1)([a-zA-Z0-9]{20,})', r'\1***'),  # Bitcoin addresses
        (r'([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})', 
         lambda m: m.group(0)[:8] + '...'),  # UUIDs (keep prefix for correlation)
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive information from log records"""
        # Redact message
        msg = str(record.getMessage())
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
        record.msg = msg
        
        # Redact args if present
        if hasattr(record, 'args') and record.args:
            redacted_args = []
            for arg in record.args:
                arg_str = str(arg)
                for pattern, replacement in self.SENSITIVE_PATTERNS:
                    arg_str = re.sub(pattern, replacement, arg_str, flags=re.IGNORECASE)
                redacted_args.append(arg_str)
            record.args = tuple(redacted_args)
        
        return True


class SecureFormatter(logging.Formatter):
    """Custom formatter with security context"""
    
    def __init__(self, *args, include_context: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.include_context = include_context
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with optional security context"""
        # Add security context if available
        if self.include_context:
            if hasattr(record, 'event_id'):
                record.msg = f"[EventID: {record.event_id}] {record.msg}"
            if hasattr(record, 'persona'):
                record.msg = f"[Persona: {record.persona}] {record.msg}"
            if hasattr(record, 'session_id'):
                # Only show first 8 chars of session ID
                sid = str(record.session_id)[:8] + '...'
                record.msg = f"[Session: {sid}] {record.msg}"
        
        return super().format(record)


def setup_logging(
    log_file: Optional[Path] = None,
    log_level: str = "INFO",
    console_output: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    include_audit: bool = True
) -> logging.Logger:
    """
    Configure secure logging with rotation and filtering
    
    Args:
        log_file: Path to log file (will be created with secure permissions)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        console_output: Whether to also log to console
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        include_audit: Whether to include audit logger
    
    Returns:
        Configured logger instance
    """
    # Get root logger
    logger = logging.getLogger('partyline')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = SecureFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = SecureFormatter(
        '%(levelname)s: %(message)s',
        include_context=False
    )
    
    # Add secure filter
    secure_filter = SecureFilter()
    
    # File handler with rotation
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions on log file
        if not log_file.exists():
            log_file.touch(mode=LOG_FILE_MODE)
        else:
            os.chmod(log_file, LOG_FILE_MODE)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(detailed_formatter)
        file_handler.addFilter(secure_filter)
        logger.addHandler(file_handler)
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(simple_formatter)
        console_handler.addFilter(secure_filter)
        # Only show INFO and above on console
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler)
    
    # Audit logger for security events
    if include_audit:
        audit_logger = logging.getLogger('partyline.audit')
        audit_logger.setLevel(logging.INFO)
        
        if log_file:
            audit_file = log_file.parent / 'audit.log'
            if not audit_file.exists():
                audit_file.touch(mode=LOG_FILE_MODE)
            else:
                os.chmod(audit_file, LOG_FILE_MODE)
            
            audit_handler = RotatingFileHandler(
                audit_file,
                maxBytes=max_bytes,
                backupCount=backup_count * 2  # Keep more audit logs
            )
            audit_formatter = logging.Formatter(
                '%(asctime)s - AUDIT - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            audit_handler.setFormatter(audit_formatter)
            audit_handler.addFilter(secure_filter)
            audit_logger.addHandler(audit_handler)
    
    # Suppress noisy libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return logger


def log_security_event(
    event_type: str,
    details: dict[str, Any],
    severity: str = "INFO"
) -> None:
    """
    Log a security-relevant event to the audit log
    
    Args:
        event_type: Type of security event (e.g., "auth_failure", "key_rotation")
        details: Event details (will be sanitized)
        severity: Log level for the event
    """
    audit_logger = logging.getLogger('partyline.audit')
    
    # Sanitize details
    safe_details = {}
    for key, value in details.items():
        if any(sensitive in key.lower() for sensitive in ['password', 'key', 'secret', 'token']):
            safe_details[key] = '***REDACTED***'
        elif isinstance(value, str) and len(value) > 100:
            safe_details[key] = value[:50] + '...'
        else:
            safe_details[key] = value
    
    # Generate event ID for correlation
    import uuid
    event_id = str(uuid.uuid4())[:8]
    
    message = f"[{event_id}] {event_type}: {safe_details}"
    
    level = getattr(logging, severity.upper(), logging.INFO)
    audit_logger.log(level, message, extra={'event_id': event_id})
    
    return event_id
