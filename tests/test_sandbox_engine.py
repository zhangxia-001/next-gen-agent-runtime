"""Test sandbox execution engine"""

import pytest
from src.sandbox_engine import SandboxEngine
from src.credential_manager import CredentialManager


class TestSandboxEngine:
    """Test sandbox execution"""
    
    def test_execute_ebpf_isolation(self):
        """Test task execution with eBPF isolation"""
        engine = SandboxEngine()
        
        result = engine.execute(
            task_intent="Execute a simple query",
            isolation_mode="eBPF",
            allowed_tools=["query_db"],
            timeout_seconds=10
        )
        
        assert result.status in ["success", "timeout"]
        assert result.isolation_mode == "eBPF"
        assert len(result.audit_log) > 0
    
    def test_execute_container_isolation(self):
        """Test task execution with container isolation"""
        engine = SandboxEngine()
        
        result = engine.execute(
            task_intent="Execute in container",
            isolation_mode="CONTAINER",
            allowed_tools=["read_file", "compute"],
            timeout_seconds=10
        )
        
        assert result.status in ["success", "timeout"]
        assert result.isolation_mode == "CONTAINER"
        assert result.execution_time >= 0
    
    def test_execute_vm_isolation(self):
        """Test task execution with VM isolation"""
        engine = SandboxEngine()
        
        result = engine.execute(
            task_intent="Execute in VM",
            isolation_mode="VM",
            allowed_tools=["*"],
            timeout_seconds=10
        )
        
        assert result.status in ["success", "timeout"]
        assert result.isolation_mode == "VM"
    
    def test_execution_result_contains_metadata(self):
        """Test that execution result contains all metadata"""
        engine = SandboxEngine()
        
        result = engine.execute(
            task_intent="Test task",
            isolation_mode="eBPF",
            allowed_tools=["compute"],
            timeout_seconds=5
        )
        
        assert hasattr(result, 'status')
        assert hasattr(result, 'isolation_mode')
        assert hasattr(result, 'execution_time')
        assert hasattr(result, 'audit_log')
    
    def test_invalid_isolation_mode(self):
        """Test error handling for invalid isolation mode"""
        engine = SandboxEngine()
        
        with pytest.raises(ValueError):
            engine.execute(
                task_intent="Test",
                isolation_mode="INVALID_MODE",
                timeout_seconds=5
            )
    
    def test_credential_injection(self):
        """Test credential injection into sandbox"""
        engine = SandboxEngine()
        
        result = engine.execute(
            task_intent="Test with credentials",
            isolation_mode="eBPF",
            allowed_tools=["query_db", "read_file"],
            timeout_seconds=5
        )
        
        # Should have credential-related audit logs
        audit_text = " ".join(result.audit_log)
        assert "credential" in audit_text.lower()
