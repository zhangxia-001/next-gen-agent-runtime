"""Core data models for the agent runtime"""

from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional, Any
from datetime import datetime
from enum import Enum
import uuid


@dataclass
class AgentBehaviorProfile:
    """Comprehensive behavioral characterization of an agent"""
    
    # System call features
    system_call_types: Set[str] = field(default_factory=set)
    privileged_syscalls: int = 0
    file_access_pattern: Dict[str, int] = field(default_factory=dict)
    
    # Network features
    network_connections: int = 0
    external_ips_accessed: int = 0
    sensitive_ports: Set[int] = field(default_factory=set)
    
    # Process features
    child_processes_spawned: int = 0
    privilege_escalation_attempts: int = 0
    
    # Resource features
    memory_access_patterns: str = "unknown"  # random/sequential/suspicious
    cpu_intensive: bool = False
    
    # Temporal features
    execution_duration: float = 0.0
    api_call_frequency: float = 0.0
    
    # Data features
    data_size_accessed: int = 0
    encryption_usage: bool = False
    
    # Metadata
    profiled_at: datetime = field(default_factory=datetime.now)
    
    def has_high_privilege_risk(self) -> bool:
        """Check if profile indicates high privilege escalation risk"""
        return self.privileged_syscalls > 5 or self.privilege_escalation_attempts > 0
    
    def has_file_access_risk(self, sensitive_dirs: Set[str]) -> bool:
        """Check if accessing sensitive files"""
        for path in self.file_access_pattern.keys():
            if any(path.startswith(d) for d in sensitive_dirs):
                return True
        return False
    
    def has_network_risk(self) -> bool:
        """Check if network activity is suspicious"""
        return self.network_connections > 10 or self.external_ips_accessed > 5
    
    def has_process_risk(self) -> bool:
        """Check if process creation is suspicious"""
        return self.child_processes_spawned > 3
    
    def has_resource_risk(self) -> bool:
        """Check if resource usage is suspicious"""
        return self.cpu_intensive or self.data_size_accessed > 1_000_000_000


@dataclass
class ExecutionTrace:
    """Record of agent execution for behavior analysis"""
    agent_id: str
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    syscall_log: List[Dict[str, Any]] = field(default_factory=list)
    network_log: List[Dict[str, Any]] = field(default_factory=list)
    file_access_log: List[Dict[str, Any]] = field(default_factory=list)
    process_log: List[Dict[str, Any]] = field(default_factory=list)
    resource_log: List[Dict[str, Any]] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    def duration(self) -> float:
        """Get execution duration in seconds"""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()


@dataclass
class IntentResult:
    """Result of intent recognition"""
    intent: str
    confidence: float
    entities: List[Dict[str, Any]] = field(default_factory=list)
    alternatives: List[tuple] = field(default_factory=list)  # (intent, score) pairs
    method: str = "unknown"  # nlp/behavior/history/hybrid
    
    def is_high_confidence(self, threshold: float = 0.7) -> bool:
        return self.confidence >= threshold


@dataclass
class Credential:
    """Temporary credential for sandboxed execution"""
    token: str
    scope: List[str]  # Allowed tools/resources
    ttl_seconds: int
    created_at: datetime = field(default_factory=datetime.now)
    
    def is_expired(self) -> bool:
        """Check if credential has expired"""
        age = (datetime.now() - self.created_at).total_seconds()
        return age > self.ttl_seconds
    
    def can_access(self, resource: str) -> bool:
        """Check if credential grants access to resource"""
        return resource in self.scope or "*" in self.scope


@dataclass
class IsolationDecision:
    """Decision result for agent isolation"""
    isolation_mode: str  # "eBPF" | "CONTAINER" | "VM"
    required_capabilities: Dict[str, int]
    behavior_profile: AgentBehaviorProfile
    reasoning: str
    confidence: float
    decision_time: datetime = field(default_factory=datetime.now)
    
    def is_high_confidence(self, threshold: float = 0.7) -> bool:
        return self.confidence >= threshold


@dataclass
class ExecutionResult:
    """Result of task execution"""
    status: str  # success | failure | timeout
    output: Optional[str] = None
    error: Optional[str] = None
    isolation_mode: Optional[str] = None
    execution_time: float = 0.0
    resource_used: Dict[str, Any] = field(default_factory=dict)
    audit_log: List[str] = field(default_factory=list)
