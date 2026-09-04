"""Main runtime orchestrator for agent execution"""

from typing import Optional, Dict, List
import time

from .config import RuntimeConfig, SensitivityLevel
from .models import (
    ExecutionTrace, ExecutionResult, IsolationDecision
)
from .intent_gateway import HybridIntentGateway
from .behavior_profiler import AgentBehaviorProfiler
from .isolation_selector import AdaptiveIsolationSelector
from .scheduler import SimpleScheduler
from .sandbox_engine import SandboxEngine
from .credential_manager import CredentialManager
from .state_manager import StateManager
from .audit_logger import AuditLogger


class AgentRuntime:
    """Main runtime system orchestrating all components"""
    
    def __init__(self,
                 intent_gateway: Optional[HybridIntentGateway] = None,
                 behavior_profiler: Optional[AgentBehaviorProfiler] = None,
                 isolation_selector: Optional[AdaptiveIsolationSelector] = None,
                 scheduler: Optional[SimpleScheduler] = None,
                 sandbox_engine: Optional[SandboxEngine] = None):
        """
        Initialize the agent runtime
        
        Args:
            intent_gateway: Custom intent recognition gateway
            behavior_profiler: Custom behavior profiler
            isolation_selector: Custom isolation selector
            scheduler: Custom scheduler
            sandbox_engine: Custom sandbox engine
        """
        # Initialize components
        self.intent_gateway = intent_gateway or HybridIntentGateway()
        self.behavior_profiler = behavior_profiler or AgentBehaviorProfiler()
        self.isolation_selector = isolation_selector or AdaptiveIsolationSelector()
        self.scheduler = scheduler or SimpleScheduler()
        self.sandbox_engine = sandbox_engine or SandboxEngine()
        
        # Supporting services
        self.credential_manager = CredentialManager()
        self.state_manager = StateManager()
        self.audit_logger = AuditLogger("agent-runtime")
    
    def execute(self,
                tenant_id: str,
                agent_id: str,
                task_intent: str,
                sensitivity_level: str = "MEDIUM",
                execution_trace: Optional[ExecutionTrace] = None,
                override_isolation: Optional[str] = None,
                timeout_seconds: int = 30) -> Dict:
        """
        Execute an agent task through the complete pipeline
        
        Args:
            tenant_id: Tenant identifier
            agent_id: Agent identifier
            task_intent: Task description/intent
            sensitivity_level: Data sensitivity (LOW/MEDIUM/HIGH/CRITICAL)
            execution_trace: Optional pre-recorded execution trace
            override_isolation: Optional manual isolation override
            timeout_seconds: Execution timeout
        
        Returns:
            Execution result dict with all metadata
        """
        self.audit_logger.log(
            "INFO",
            f"Starting agent execution pipeline",
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "sensitivity_level": sensitivity_level
            }
        )
        
        try:
            # ==========================================
            # Step 1: Intent Recognition
            # ==========================================
            intent_result = self.intent_gateway.recognize(
                task_intent,
                {"tenant_id": tenant_id, "agent_id": agent_id}
            )
            
            self.audit_logger.log_intent_recognition(
                intent_result.intent,
                intent_result.confidence
            )
            
            # ==========================================
            # Step 2: Behavior Analysis
            # ==========================================
            # If no trace provided, create default
            if execution_trace is None:
                execution_trace = ExecutionTrace(agent_id=agent_id)
            
            # Profile behavior from trace
            behavior_profile = self.behavior_profiler.profile_from_trace(
                execution_trace
            )
            
            profile_summary = f"syscalls={len(behavior_profile.system_call_types)}, " \
                            f"network={behavior_profile.network_connections}, " \
                            f"processes={behavior_profile.child_processes_spawned}"
            
            self.audit_logger.log_behavior_analysis(profile_summary)
            
            # ==========================================
            # Step 3: Dynamic Isolation Decision
            # ==========================================
            isolation_decision = self.isolation_selector.select_isolation(
                behavior_profile,
                sensitivity_level,
                override_isolation
            )
            
            self.audit_logger.log_isolation_decision(
                isolation_decision.isolation_mode,
                isolation_decision.confidence
            )
            
            # ==========================================
            # Step 4: Task Scheduling
            # ==========================================
            # Estimate tokens and select node
            token_estimate = self.scheduler.estimate_token_cost(task_intent)
            
            selected_node = self.scheduler.select_node(
                isolation_decision.isolation_mode,
                token_estimate,
                priority="normal"
            )
            
            if not selected_node:
                raise RuntimeError("No suitable node found for execution")
            
            self.audit_logger.log(
                "INFO",
                f"Node selected for execution: {selected_node.name}",
                {
                    "node": selected_node.name,
                    "region": selected_node.region,
                    "token_estimate": token_estimate
                }
            )
            
            # ==========================================
            # Step 5: Credential Injection
            # ==========================================
            # Create temporary credential with minimal privileges
            allowed_tools = self._infer_tools_from_intent(intent_result.intent)
            credential = self.credential_manager.create_credential(
                sandbox_id=f"sandbox-{tenant_id}-{agent_id}",
                allowed_tools=allowed_tools,
                ttl_seconds=timeout_seconds
            )
            
            self.audit_logger.log_credential_created(
                credential.token[:8],
                allowed_tools
            )
            
            # ==========================================
            # Step 6: Sandbox Execution
            # ==========================================
            self.audit_logger.log_execution_start(
                isolation_decision.isolation_mode,
                timeout_seconds
            )
            
            execution_result = self.sandbox_engine.execute(
                task_intent=task_intent,
                isolation_mode=isolation_decision.isolation_mode,
                allowed_tools=allowed_tools,
                timeout_seconds=timeout_seconds
            )
            
            self.audit_logger.log_execution_end(
                execution_result.status,
                execution_result.execution_time
            )
            
            # ==========================================
            # Step 7: Result Compilation
            # ==========================================
            result = {
                "status": execution_result.status,
                "output": execution_result.output,
                "error": execution_result.error,
                
                # Intent recognition
                "intent": intent_result.intent,
                "intent_confidence": intent_result.confidence,
                "intent_method": intent_result.method,
                
                # Behavior analysis
                "behavior_summary": profile_summary,
                "privileged_syscalls": behavior_profile.privileged_syscalls,
                "network_connections": behavior_profile.network_connections,
                "child_processes": behavior_profile.child_processes_spawned,
                
                # Isolation decision
                "isolation_mode": isolation_decision.isolation_mode,
                "isolation_confidence": isolation_decision.confidence,
                "isolation_reasoning": isolation_decision.reasoning,
                "required_capabilities": isolation_decision.required_capabilities,
                
                # Execution metadata
                "execution_time": execution_result.execution_time,
                "selected_node": selected_node.name,
                "token_estimate": token_estimate,
                "audit_log": execution_result.audit_log
            }
            
            self.audit_logger.log(
                "INFO",
                "Execution pipeline completed successfully",
                {"status": execution_result.status}
            )
            
            return result
        
        except Exception as e:
            self.audit_logger.log(
                "ERROR",
                f"Execution pipeline failed: {str(e)}",
                {"error": str(e)}
            )
            raise
    
    def _infer_tools_from_intent(self, intent: str) -> List[str]:
        """
        Infer allowed tools based on detected intent
        
        Args:
            intent: Detected intent
        
        Returns:
            List of allowed tools
        """
        tool_mapping = {
            "database_query": ["query_db", "read_table"],
            "file_access": ["read_file", "write_file", "list_dir"],
            "network_operation": ["http_request", "socket"],
            "process_management": ["spawn_process", "manage_proc"],
            "system_configuration": ["read_config", "check_system"],
            "normal_operation": ["basic_compute", "analyze"]
        }
        
        return tool_mapping.get(intent, ["basic_compute"])
    
    def get_audit_logs(self, tags: List[str] = None) -> List[Dict]:
        """Get audit logs, optionally filtered by tags"""
        return self.audit_logger.get_logs(tags)
    
    def export_audit_logs(self, filepath: str):
        """Export audit logs to JSON file"""
        self.audit_logger.export_logs(filepath)
