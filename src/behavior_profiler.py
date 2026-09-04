"""Agent behavior profiling and characterization"""

from typing import Dict, Set, List, Any
from .models import AgentBehaviorProfile, ExecutionTrace


class AgentBehaviorProfiler:
    """Profiles agent behavior from execution traces"""
    
    SENSITIVE_DIRS = {"/etc", "/root", "/sys", "/proc", "/dev", "/boot"}
    SENSITIVE_PORTS = {22, 23, 445, 3306, 5432, 6379, 27017, 9200}
    PRIVILEGED_SYSCALLS = {
        "ptrace", "prctl", "ioctl", "mmap", "mprotect",
        "setuid", "setgid", "capset", "clone", "fork"
    }
    
    def profile_from_trace(self, trace: ExecutionTrace) -> AgentBehaviorProfile:
        """
        Build behavior profile from execution trace
        
        Args:
            trace: ExecutionTrace object
        
        Returns:
            AgentBehaviorProfile with extracted features
        """
        profile = AgentBehaviorProfile()
        
        # Parse syscall log
        self._analyze_syscalls(trace, profile)
        
        # Parse network log
        self._analyze_network(trace, profile)
        
        # Parse file access log
        self._analyze_file_access(trace, profile)
        
        # Parse process log
        self._analyze_processes(trace, profile)
        
        # Parse resource log
        self._analyze_resources(trace, profile)
        
        # Temporal features
        profile.execution_duration = trace.duration()
        if len(trace.syscall_log) > 0:
            profile.api_call_frequency = len(trace.syscall_log) / max(trace.duration(), 0.1)
        
        return profile
    
    def _analyze_syscalls(self, trace: ExecutionTrace, profile: AgentBehaviorProfile):
        """Extract system call features"""
        for syscall_entry in trace.syscall_log:
            syscall_name = syscall_entry.get("name", "")
            profile.system_call_types.add(syscall_name)
            
            if syscall_name in self.PRIVILEGED_SYSCALLS:
                profile.privileged_syscalls += 1
    
    def _analyze_network(self, trace: ExecutionTrace, profile: AgentBehaviorProfile):
        """Extract network activity features"""
        external_ips = set()
        
        for net_entry in trace.network_log:
            profile.network_connections += 1
            
            # Check for external IPs
            remote_ip = net_entry.get("remote_ip", "")
            if not self._is_internal_ip(remote_ip):
                external_ips.add(remote_ip)
            
            # Check for sensitive ports
            remote_port = net_entry.get("remote_port", 0)
            if remote_port in self.SENSITIVE_PORTS:
                profile.sensitive_ports.add(remote_port)
        
        profile.external_ips_accessed = len(external_ips)
    
    def _analyze_file_access(self, trace: ExecutionTrace, profile: AgentBehaviorProfile):
        """Extract file access patterns"""
        for file_entry in trace.file_access_log:
            path = file_entry.get("path", "")
            operation = file_entry.get("operation", "read")
            
            if path not in profile.file_access_pattern:
                profile.file_access_pattern[path] = 0
            profile.file_access_pattern[path] += 1
    
    def _analyze_processes(self, trace: ExecutionTrace, profile: AgentBehaviorProfile):
        """Extract process creation patterns"""
        for proc_entry in trace.process_log:
            event_type = proc_entry.get("type", "")
            
            if event_type == "fork" or event_type == "clone":
                profile.child_processes_spawned += 1
            elif event_type == "setuid" or event_type == "setgid":
                profile.privilege_escalation_attempts += 1
    
    def _analyze_resources(self, trace: ExecutionTrace, profile: AgentBehaviorProfile):
        """Extract resource usage patterns"""
        max_memory = 0
        total_cpu_time = 0
        data_accessed = 0
        
        for resource_entry in trace.resource_log:
            memory = resource_entry.get("memory_mb", 0)
            cpu_time = resource_entry.get("cpu_time_ms", 0)
            data = resource_entry.get("data_bytes", 0)
            
            max_memory = max(max_memory, memory)
            total_cpu_time += cpu_time
            data_accessed += data
            
            # Check if memory access is suspicious
            access_pattern = resource_entry.get("memory_access_pattern", "unknown")
            if access_pattern == "random" or access_pattern == "suspicious":
                profile.memory_access_patterns = access_pattern
        
        profile.data_size_accessed = data_accessed
        profile.cpu_intensive = total_cpu_time > 5000  # > 5 seconds CPU time
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private"""
        internal_ranges = [
            "10.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.",
            "127.",
            "localhost"
        ]
        return any(ip.startswith(range_) for range_ in internal_ranges)
