"""Integration tests for complete runtime"""

import pytest
from src.runtime import AgentRuntime
from src.models import ExecutionTrace


class TestAgentRuntime:
    """Test complete agent runtime integration"""
    
    def test_execute_simple_task(self):
        """Test execution of simple low-risk task"""
        runtime = AgentRuntime()
        
        result = runtime.execute(
            tenant_id="tenant-001",
            agent_id="agent-001",
            task_intent="Execute a simple computation",
            sensitivity_level="LOW",
            timeout_seconds=10
        )
        
        assert result["status"] in ["success", "timeout"]
        assert "intent" in result
        assert "isolation_mode" in result
        assert "execution_time" in result
    
    def test_execute_high_risk_task(self):
        """Test execution of high-risk task with proper isolation"""
        runtime = AgentRuntime()
        
        # Create trace with high-risk behavior
        trace = ExecutionTrace(
            agent_id="agent-001",
            syscall_log=[
                {"name": "ptrace"},
                {"name": "setuid"},
            ],
            file_access_log=[
                {"path": "/etc/passwd", "operation": "read"},
            ]
        )
        
        result = runtime.execute(
            tenant_id="tenant-001",
            agent_id="agent-001",
            task_intent="Query sensitive database",
            sensitivity_level="HIGH",
            execution_trace=trace,
            timeout_seconds=10
        )
        
        assert result["status"] in ["success", "timeout"]
        # Should select stronger isolation for high risk
        assert result["isolation_mode"] in ["CONTAINER", "VM"]
    
    def test_execute_critical_sensitivity(self):
        """Test that critical sensitivity forces strong isolation"""
        runtime = AgentRuntime()
        
        result = runtime.execute(
            tenant_id="tenant-001",
            agent_id="agent-001",
            task_intent="Process critical data",
            sensitivity_level="CRITICAL",
            timeout_seconds=10
        )
        
        assert result["status"] in ["success", "timeout"]
        # CRITICAL should force at least CONTAINER
        assert result["isolation_mode"] in ["CONTAINER", "VM"]
    
    def test_isolation_override(self):
        """Test manual isolation override"""
        runtime = AgentRuntime()
        
        result = runtime.execute(
            tenant_id="tenant-001",
            agent_id="agent-001",
            task_intent="Test task",
            sensitivity_level="LOW",
            override_isolation="VM",
            timeout_seconds=10
        )
        
        assert result["isolation_mode"] == "VM"
    
    def test_result_contains_all_metadata(self):
        """Test that result contains complete metadata"""
        runtime = AgentRuntime()
        
        result = runtime.execute(
            tenant_id="tenant-001",
            agent_id="agent-001",
            task_intent="Test comprehensive metadata",
            sensitivity_level="MEDIUM",
            timeout_seconds=10
        )
        
        # Check intent recognition results
        assert "intent" in result
        assert "intent_confidence" in result
        assert "intent_method" in result
        
        # Check behavior analysis results
        assert "behavior_summary" in result
        assert "privileged_syscalls" in result
        
        # Check isolation decision results
        assert "isolation_mode" in result
        assert "isolation_confidence" in result
        assert "isolation_reasoning" in result
        assert "required_capabilities" in result
        
        # Check execution results
        assert "execution_time" in result
        assert "selected_node" in result
        assert "audit_log" in result
    
    def test_audit_logging(self):
        """Test audit logging throughout execution"""
        runtime = AgentRuntime()
        
        result = runtime.execute(
            tenant_id="tenant-001",
            agent_id="agent-001",
            task_intent="Test audit logging",
            sensitivity_level="MEDIUM",
            timeout_seconds=10
        )
        
        # Get audit logs
        logs = runtime.get_audit_logs()
        
        assert len(logs) > 0
        
        # Check for specific log events
        log_events = [log["event"] for log in logs]
        assert any("intent" in event.lower() for event in log_events)
    
    def test_multiple_executions(self):
        """Test multiple sequential executions"""
        runtime = AgentRuntime()
        
        # Execute multiple times
        for i in range(3):
            result = runtime.execute(
                tenant_id="tenant-001",
                agent_id=f"agent-{i}",
                task_intent=f"Task {i}",
                sensitivity_level="LOW",
                timeout_seconds=5
            )
            
            assert result["status"] in ["success", "timeout"]
        
        # All executions should be logged
        logs = runtime.get_audit_logs()
        assert len(logs) >= 3
