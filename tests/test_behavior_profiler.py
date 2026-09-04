"""Test behavior profiling and characterization"""

import pytest
from src.models import ExecutionTrace, AgentBehaviorProfile
from src.behavior_profiler import AgentBehaviorProfiler
from datetime import datetime


class TestAgentBehaviorProfiler:
    """Test agent behavior profiling"""
    
    def test_profile_syscalls(self):
        """Test syscall analysis"""
        profiler = AgentBehaviorProfiler()
        
        trace = ExecutionTrace(
            agent_id="agent-001",
            syscall_log=[
                {"name": "open", "timestamp": 0},
                {"name": "read", "timestamp": 1},
                {"name": "ptrace", "timestamp": 2},  # Privileged
            ]
        )
        
        profile = profiler.profile_from_trace(trace)
        
        assert "open" in profile.system_call_types
        assert "ptrace" in profile.system_call_types
        assert profile.privileged_syscalls == 1
    
    def test_profile_network_activity(self):
        """Test network activity analysis"""
        profiler = AgentBehaviorProfiler()
        
        trace = ExecutionTrace(
            agent_id="agent-001",
            network_log=[
                {"remote_ip": "8.8.8.8", "remote_port": 443},
                {"remote_ip": "192.168.1.1", "remote_port": 3306},  # Internal
                {"remote_ip": "1.2.3.4", "remote_port": 22},  # Sensitive port
            ]
        )
        
        profile = profiler.profile_from_trace(trace)
        
        assert profile.network_connections == 3
        assert profile.external_ips_accessed == 2  # Only external
        assert 22 in profile.sensitive_ports
    
    def test_profile_file_access(self):
        """Test file access pattern analysis"""
        profiler = AgentBehaviorProfiler()
        
        trace = ExecutionTrace(
            agent_id="agent-001",
            file_access_log=[
                {"path": "/usr/bin/ls", "operation": "exec"},
                {"path": "/etc/passwd", "operation": "read"},
                {"path": "/etc/passwd", "operation": "read"},  # Repeated
            ]
        )
        
        profile = profiler.profile_from_trace(trace)
        
        assert len(profile.file_access_pattern) == 2
        assert profile.file_access_pattern["/etc/passwd"] == 2
    
    def test_profile_processes(self):
        """Test process creation analysis"""
        profiler = AgentBehaviorProfiler()
        
        trace = ExecutionTrace(
            agent_id="agent-001",
            process_log=[
                {"type": "fork", "pid": 1001},
                {"type": "clone", "pid": 1002},
                {"type": "setuid", "uid": 0},  # Privilege escalation
            ]
        )
        
        profile = profiler.profile_from_trace(trace)
        
        assert profile.child_processes_spawned == 2
        assert profile.privilege_escalation_attempts == 1
    
    def test_profile_resource_usage(self):
        """Test resource usage analysis"""
        profiler = AgentBehaviorProfiler()
        
        trace = ExecutionTrace(
            agent_id="agent-001",
            resource_log=[
                {"memory_mb": 256, "cpu_time_ms": 1000, "data_bytes": 1_000_000},
                {"memory_mb": 512, "cpu_time_ms": 5000, "data_bytes": 500_000_000},  # Large data
            ]
        )
        
        profile = profiler.profile_from_trace(trace)
        
        assert profile.data_size_accessed == 501_000_000
        assert profile.cpu_intensive  # > 5 seconds CPU time
    
    def test_is_internal_ip(self):
        """Test internal IP detection"""
        profiler = AgentBehaviorProfiler()
        
        assert profiler._is_internal_ip("192.168.1.1")
        assert profiler._is_internal_ip("10.0.0.1")
        assert profiler._is_internal_ip("172.16.0.1")
        assert profiler._is_internal_ip("127.0.0.1")
        
        assert not profiler._is_internal_ip("8.8.8.8")
        assert not profiler._is_internal_ip("1.2.3.4")
    
    def test_behavior_checks(self):
        """Test behavior check methods"""
        profile = AgentBehaviorProfile(
            privileged_syscalls=10,
            privilege_escalation_attempts=1,
            file_access_pattern={"/etc/passwd": 1},
            network_connections=15,
            external_ips_accessed=6,
            child_processes_spawned=5,
            data_size_accessed=2_000_000_000,
            cpu_intensive=True
        )
        
        assert profile.has_high_privilege_risk()
        assert profile.has_file_access_risk({"/etc"})
        assert profile.has_network_risk()
        assert profile.has_process_risk()
        assert profile.has_resource_risk()
