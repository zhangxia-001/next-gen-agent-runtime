"""Test isolation selector and capability matrix"""

import pytest
from src.models import AgentBehaviorProfile
from src.isolation_selector import BehaviorToCapabilityMapper, AdaptiveIsolationSelector
from src.config import CapabilityLevel


class TestBehaviorToCapabilityMapper:
    """Test behavior to capability mapping"""
    
    def test_high_privilege_risk(self):
        """Test detection of high privilege risk"""
        mapper = BehaviorToCapabilityMapper()
        
        profile = AgentBehaviorProfile(
            privileged_syscalls=10,
            system_call_types={"ptrace", "prctl", "ioctl"}
        )
        
        requirements = mapper.analyze_behavior(profile)
        
        assert requirements["syscall_filtering"] >= CapabilityLevel.MEDIUM.value
        assert requirements["privilege_escalation_prevention"] >= CapabilityLevel.MEDIUM.value
    
    def test_sensitive_file_access(self):
        """Test detection of sensitive file access"""
        mapper = BehaviorToCapabilityMapper()
        
        profile = AgentBehaviorProfile(
            file_access_pattern={"/etc/passwd": 1, "/root/.ssh/key": 1}
        )
        
        requirements = mapper.analyze_behavior(profile)
        
        assert requirements["file_access_control"] == CapabilityLevel.STRONG.value
    
    def test_network_activity(self):
        """Test detection of network activity"""
        mapper = BehaviorToCapabilityMapper()
        
        profile = AgentBehaviorProfile(
            network_connections=15,
            external_ips_accessed=10
        )
        
        requirements = mapper.analyze_behavior(profile)
        
        assert requirements["network_isolation"] >= CapabilityLevel.MEDIUM.value
    
    def test_process_creation(self):
        """Test detection of process creation"""
        mapper = BehaviorToCapabilityMapper()
        
        profile = AgentBehaviorProfile(
            child_processes_spawned=5
        )
        
        requirements = mapper.analyze_behavior(profile)
        
        assert requirements["child_process_control"] >= CapabilityLevel.MEDIUM.value
    
    def test_find_minimum_isolation_ebpf(self):
        """Test finding eBPF as sufficient isolation"""
        mapper = BehaviorToCapabilityMapper()
        
        requirements = {
            "syscall_filtering": CapabilityLevel.WEAK.value,
            "file_access_control": CapabilityLevel.NONE.value,
            "network_isolation": CapabilityLevel.NONE.value,
            "child_process_control": CapabilityLevel.NONE.value,
            "privilege_escalation_prevention": CapabilityLevel.NONE.value,
            "resource_limits": CapabilityLevel.NONE.value,
            "memory_isolation": CapabilityLevel.NONE.value,
            "kernel_module_execution": CapabilityLevel.NONE.value,
        }
        
        isolation = mapper.find_minimum_isolation(requirements)
        assert isolation == "eBPF"
    
    def test_find_minimum_isolation_container(self):
        """Test finding container as minimum isolation"""
        mapper = BehaviorToCapabilityMapper()
        
        requirements = {
            "syscall_filtering": CapabilityLevel.NONE.value,
            "file_access_control": CapabilityLevel.STRONG.value,
            "network_isolation": CapabilityLevel.NONE.value,
            "child_process_control": CapabilityLevel.NONE.value,
            "privilege_escalation_prevention": CapabilityLevel.NONE.value,
            "resource_limits": CapabilityLevel.NONE.value,
            "memory_isolation": CapabilityLevel.NONE.value,
            "kernel_module_execution": CapabilityLevel.NONE.value,
        }
        
        isolation = mapper.find_minimum_isolation(requirements)
        assert isolation == "CONTAINER"
    
    def test_find_minimum_isolation_vm(self):
        """Test finding VM as required isolation"""
        mapper = BehaviorToCapabilityMapper()
        
        requirements = {
            "syscall_filtering": CapabilityLevel.NONE.value,
            "file_access_control": CapabilityLevel.NONE.value,
            "network_isolation": CapabilityLevel.NONE.value,
            "child_process_control": CapabilityLevel.NONE.value,
            "privilege_escalation_prevention": CapabilityLevel.STRONG.value,
            "resource_limits": CapabilityLevel.NONE.value,
            "memory_isolation": CapabilityLevel.NONE.value,
            "kernel_module_execution": CapabilityLevel.NONE.value,
        }
        
        isolation = mapper.find_minimum_isolation(requirements)
        assert isolation == "VM"


class TestAdaptiveIsolationSelector:
    """Test adaptive isolation selection"""
    
    def test_select_isolation_low_risk(self):
        """Test isolation selection for low-risk behavior"""
        selector = AdaptiveIsolationSelector()
        
        profile = AgentBehaviorProfile(
            privileged_syscalls=0,
            network_connections=2,
            child_processes_spawned=0
        )
        
        decision = selector.select_isolation(profile, "LOW")
        
        assert decision.isolation_mode == "eBPF"
        assert decision.confidence > 0.7
    
    def test_select_isolation_high_risk(self):
        """Test isolation selection for high-risk behavior"""
        selector = AdaptiveIsolationSelector()
        
        profile = AgentBehaviorProfile(
            privileged_syscalls=10,
            file_access_pattern={"/etc/passwd": 1},
            network_connections=20,
            child_processes_spawned=5
        )
        
        decision = selector.select_isolation(profile, "HIGH")
        
        assert decision.isolation_mode in ["CONTAINER", "VM"]
        assert decision.confidence > 0.5
    
    def test_sensitivity_level_override(self):
        """Test sensitivity level forcing stronger isolation"""
        selector = AdaptiveIsolationSelector()
        
        profile = AgentBehaviorProfile()  # Clean profile
        
        # CRITICAL sensitivity should force at least CONTAINER
        decision = selector.select_isolation(profile, "CRITICAL")
        
        assert decision.isolation_mode in ["CONTAINER", "VM"]
    
    def test_manual_override(self):
        """Test manual isolation override"""
        selector = AdaptiveIsolationSelector()
        
        profile = AgentBehaviorProfile()
        
        decision = selector.select_isolation(
            profile,
            "LOW",
            override_level="VM"
        )
        
        assert decision.isolation_mode == "VM"
    
    def test_decision_includes_reasoning(self):
        """Test that decision includes human-readable reasoning"""
        selector = AdaptiveIsolationSelector()
        
        profile = AgentBehaviorProfile(
            privileged_syscalls=5,
            network_connections=3
        )
        
        decision = selector.select_isolation(profile, "MEDIUM")
        
        assert len(decision.reasoning) > 0
        assert "privilege" in decision.reasoning.lower() or "network" in decision.reasoning.lower()
