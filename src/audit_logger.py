"""Audit logging for execution tracking and compliance"""

import json
from typing import Dict, Any, List
from datetime import datetime
import logging


class AuditLogger:
    """Centralized audit logging for all runtime activities"""
    
    # Log levels
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"
    
    def __init__(self, name: str = "agent-runtime"):
        self.name = name
        self.logs: List[Dict[str, Any]] = []
        
        # Setup standard logging
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        handler = logging.FileHandler(f"{name}.log")
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log(self,
            level: str,
            event: str,
            context: Dict[str, Any] = None,
            tags: List[str] = None):
        """
        Log an audit event
        
        Args:
            level: Log level (CRITICAL/ERROR/WARNING/INFO/DEBUG)
            event: Event description
            context: Additional context data
            tags: Event tags for filtering
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "event": event,
            "context": context or {},
            "tags": tags or []
        }
        
        self.logs.append(log_entry)
        
        # Also log to standard logger
        log_func = getattr(self.logger, level.lower(), self.logger.info)
        log_func(json.dumps(log_entry))
    
    def log_intent_recognition(self, intent: str, confidence: float):
        """Log intent recognition event"""
        self.log(
            self.INFO,
            f"Intent recognized: {intent}",
            {"intent": intent, "confidence": confidence},
            ["intent-recognition", "gateway"]
        )
    
    def log_behavior_analysis(self, profile_summary: str):
        """Log behavior analysis event"""
        self.log(
            self.INFO,
            f"Behavior analyzed: {profile_summary}",
            {},
            ["behavior-analysis", "profiling"]
        )
    
    def log_isolation_decision(self, isolation_mode: str, confidence: float):
        """Log isolation decision event"""
        self.log(
            self.INFO,
            f"Isolation decided: {isolation_mode}",
            {"isolation_mode": isolation_mode, "confidence": confidence},
            ["isolation-decision", "capability-mapping"]
        )
    
    def log_credential_created(self, token_prefix: str, scope: List[str]):
        """Log credential creation event"""
        self.log(
            self.INFO,
            f"Credential created",
            {"token_prefix": token_prefix, "scope": scope},
            ["credential", "security"]
        )
    
    def log_execution_start(self, isolation_mode: str, timeout: int):
        """Log execution start event"""
        self.log(
            self.INFO,
            f"Task execution started",
            {"isolation_mode": isolation_mode, "timeout_seconds": timeout},
            ["execution", "sandbox"]
        )
    
    def log_execution_end(self, status: str, duration: float):
        """Log execution end event"""
        self.log(
            self.INFO,
            f"Task execution ended: {status}",
            {"status": status, "duration_seconds": duration},
            ["execution", "sandbox"]
        )
    
    def log_security_event(self, event_type: str, severity: str, details: Dict):
        """Log security-related event"""
        level = self.CRITICAL if severity == "high" else self.WARNING
        self.log(
            level,
            f"Security event: {event_type}",
            {"event_type": event_type, "severity": severity, **details},
            ["security", "threat"]
        )
    
    def get_logs(self, tags: List[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve logs, optionally filtered by tags
        
        Args:
            tags: Optional tag filters (AND logic)
        
        Returns:
            Filtered list of log entries
        """
        if not tags:
            return self.logs.copy()
        
        filtered = []
        for log in self.logs:
            if all(tag in log["tags"] for tag in tags):
                filtered.append(log)
        return filtered
    
    def export_logs(self, filepath: str):
        """
        Export logs to JSON file for compliance/auditing
        
        Args:
            filepath: Path to save logs
        """
        with open(filepath, 'w') as f:
            json.dump(self.logs, f, indent=2)
    
    def clear_logs(self):
        """Clear in-memory logs"""
        self.logs.clear()
