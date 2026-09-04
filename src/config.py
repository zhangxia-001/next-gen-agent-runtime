"""Global configuration and constants"""

from enum import Enum
from typing import Dict, Set


class IsolationMode(str, Enum):
    """Supported isolation modes"""
    EBPF = "eBPF"
    CONTAINER = "CONTAINER"
    VM = "VM"


class SensitivityLevel(str, Enum):
    """Data/task sensitivity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CapabilityLevel(int, Enum):
    """Isolation capability strength levels"""
    NONE = 0
    WEAK = 1
    MEDIUM = 2
    STRONG = 3


class RuntimeConfig:
    """Runtime configuration constants"""
    
    # Isolation defaults
    ISOLATION_DEFAULT = IsolationMode.EBPF
    
    # Credential TTL
    CREDENTIAL_TTL_SECONDS = 30
    
    # Max reasoning depth (prevent infinite loops)
    MAX_REASONING_DEPTH = 15
    
    # Execution timeout
    EXECUTION_TIMEOUT_SECONDS = 300
    
    # Resource limits
    DEFAULT_MEMORY_LIMIT_MB = 512
    DEFAULT_CPU_LIMIT = 1.0  # 100% of one CPU
    DEFAULT_DISK_LIMIT_MB = 1024
    
    # Node pools configuration
    TRUSTED_NODE_POOLS = {
        "cn-east": {
            "nodes": ["sh-tee-01", "hz-tee-02", "nj-ebpf-03"],
            "compliance_tags": ["GDPR-CN", "MLPS-3"],
            "hardware_tee": True,
            "supported_runtimes": [IsolationMode.EBPF, IsolationMode.CONTAINER, IsolationMode.VM]
        },
        "cn-south": {
            "nodes": ["gz-tee-01", "sz-ebpf-02", "dg-wasm-03"],
            "compliance_tags": ["PDPA", "MLPS-2"],
            "hardware_tee": True,
            "supported_runtimes": [IsolationMode.EBPF, IsolationMode.CONTAINER]
        }
    }


# Isolation capability matrix
ISOLATION_CAPABILITY_MATRIX: Dict[str, Dict[str, int]] = {
    "eBPF": {
        "syscall_filtering": CapabilityLevel.MEDIUM.value,
        "file_access_control": CapabilityLevel.WEAK.value,
        "network_isolation": CapabilityLevel.MEDIUM.value,
        "child_process_control": CapabilityLevel.WEAK.value,
        "privilege_escalation_prevention": CapabilityLevel.WEAK.value,
        "resource_limits": CapabilityLevel.NONE.value,
        "memory_isolation": CapabilityLevel.NONE.value,
        "kernel_module_execution": CapabilityLevel.NONE.value,
    },
    "CONTAINER": {
        "syscall_filtering": CapabilityLevel.MEDIUM.value,  # via seccomp
        "file_access_control": CapabilityLevel.STRONG.value,  # isolated filesystem
        "network_isolation": CapabilityLevel.STRONG.value,  # network namespace
        "child_process_control": CapabilityLevel.STRONG.value,  # PID namespace
        "privilege_escalation_prevention": CapabilityLevel.MEDIUM.value,  # user namespace
        "resource_limits": CapabilityLevel.STRONG.value,  # cgroups
        "memory_isolation": CapabilityLevel.MEDIUM.value,  # virtual memory
        "kernel_module_execution": CapabilityLevel.WEAK.value,  # hard to load
    },
    "VM": {
        "syscall_filtering": CapabilityLevel.STRONG.value,  # isolated kernel
        "file_access_control": CapabilityLevel.STRONG.value,  # full OS isolation
        "network_isolation": CapabilityLevel.STRONG.value,  # virtual network
        "child_process_control": CapabilityLevel.STRONG.value,  # virtual OS
        "privilege_escalation_prevention": CapabilityLevel.STRONG.value,  # independent kernel
        "resource_limits": CapabilityLevel.STRONG.value,  # hypervisor
        "memory_isolation": CapabilityLevel.STRONG.value,  # hardware MMU
        "kernel_module_execution": CapabilityLevel.MEDIUM.value,  # isolated kernel
    }
}

# Behavior characteristics to capability requirements mapping
BEHAVIOR_CAPABILITY_MAPPING = {
    "high_privileged_syscalls": {
        "required_capabilities": ["syscall_filtering", "privilege_escalation_prevention"],
        "min_levels": {"syscall_filtering": 2, "privilege_escalation_prevention": 2}
    },
    "sensitive_file_access": {
        "required_capabilities": ["file_access_control"],
        "min_levels": {"file_access_control": 3}
    },
    "high_network_activity": {
        "required_capabilities": ["network_isolation"],
        "min_levels": {"network_isolation": 2}
    },
    "high_process_creation": {
        "required_capabilities": ["child_process_control"],
        "min_levels": {"child_process_control": 2}
    },
    "suspicious_memory_access": {
        "required_capabilities": ["memory_isolation", "resource_limits"],
        "min_levels": {"memory_isolation": 2, "resource_limits": 2}
    },
    "kernel_access_attempts": {
        "required_capabilities": ["kernel_module_execution"],
        "min_levels": {"kernel_module_execution": 2}
    }
}

# Sensitivity level to minimum isolation mapping
SENSITIVITY_ISOLATION_MAP = {
    SensitivityLevel.LOW: None,  # Auto-select
    SensitivityLevel.MEDIUM: None,  # Auto-select
    SensitivityLevel.HIGH: IsolationMode.EBPF,
    SensitivityLevel.CRITICAL: IsolationMode.CONTAINER,
}
