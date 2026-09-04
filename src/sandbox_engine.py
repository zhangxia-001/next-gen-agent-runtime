"""Sandbox execution engine with multiple isolation backends"""

import subprocess
import json
import os
from typing import Dict, Optional, List, Any
from datetime import datetime
import tempfile
import time

from .models import ExecutionResult, Credential
from .config import RuntimeConfig
from .credential_manager import CredentialManager


class SandboxEngine:
    """Executes agent tasks in isolated environments"""
    
    def __init__(self):
        self.credential_manager = CredentialManager()
        self.execution_logs = {}
    
    def execute(self,
                task_intent: str,
                isolation_mode: str,
                agent_code: str = None,
                allowed_tools: List[str] = None,
                timeout_seconds: int = 30) -> ExecutionResult:
        """
        Execute agent task in isolated environment
        
        Args:
            task_intent: Task description/intent
            isolation_mode: Isolation type (eBPF/CONTAINER/VM)
            agent_code: Optional agent code to execute
            allowed_tools: List of allowed tools/permissions
            timeout_seconds: Execution timeout
        
        Returns:
            ExecutionResult with status and output
        """
        allowed_tools = allowed_tools or []
        start_time = datetime.now()
        audit_log = []
        
        try:
            # Step 1: Create temporary credential
            credential = self.credential_manager.create_credential(
                sandbox_id=f"sandbox-{int(time.time())}",
                allowed_tools=allowed_tools,
                ttl_seconds=timeout_seconds
            )
            audit_log.append(f"Created credential: {credential.token[:8]}...")
            
            # Step 2: Execute based on isolation mode
            if isolation_mode == "eBPF":
                output = self._execute_ebpf(
                    task_intent, agent_code, credential, audit_log, timeout_seconds
                )
            elif isolation_mode == "CONTAINER":
                output = self._execute_container(
                    task_intent, agent_code, credential, audit_log, timeout_seconds
                )
            elif isolation_mode == "VM":
                output = self._execute_vm(
                    task_intent, agent_code, credential, audit_log, timeout_seconds
                )
            else:
                raise ValueError(f"Unknown isolation mode: {isolation_mode}")
            
            audit_log.append("Task completed successfully")
            
            # Step 3: Cleanup credential
            self.credential_manager.revoke_credential(credential.token)
            audit_log.append("Revoked credential")
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ExecutionResult(
                status="success",
                output=output,
                isolation_mode=isolation_mode,
                execution_time=execution_time,
                audit_log=audit_log
            )
        
        except subprocess.TimeoutExpired:
            audit_log.append("Execution timeout")
            return ExecutionResult(
                status="timeout",
                error="Task execution exceeded timeout",
                isolation_mode=isolation_mode,
                execution_time=(datetime.now() - start_time).total_seconds(),
                audit_log=audit_log
            )
        
        except Exception as e:
            audit_log.append(f"Error: {str(e)}")
            return ExecutionResult(
                status="failure",
                error=str(e),
                isolation_mode=isolation_mode,
                execution_time=(datetime.now() - start_time).total_seconds(),
                audit_log=audit_log
            )
    
    def _execute_ebpf(self,
                      task_intent: str,
                      agent_code: str,
                      credential: Credential,
                      audit_log: List[str],
                      timeout_seconds: int) -> str:
        """
        Execute task with eBPF isolation (lightweight)
        
        In production: Would use actual eBPF rules via Cilium/Falco
        For now: Simulated direct process execution with logging
        
        Args:
            task_intent: Task description
            agent_code: Code to execute
            credential: Credentials for execution
            audit_log: Audit log list
            timeout_seconds: Timeout
        
        Returns:
            Task output
        """
        audit_log.append("Starting eBPF isolation mode")
        audit_log.append(f"Allowed tools: {', '.join(credential.scope)}")
        
        # Simulate task execution
        # In production: Load eBPF programs, enforce syscall filtering, etc.
        result_output = self._simulate_agent_execution(
            task_intent, credential, audit_log
        )
        
        audit_log.append("eBPF isolation completed")
        return result_output
    
    def _execute_container(self,
                           task_intent: str,
                           agent_code: str,
                           credential: Credential,
                           audit_log: List[str],
                           timeout_seconds: int) -> str:
        """
        Execute task in Docker container
        
        Args:
            task_intent: Task description
            agent_code: Code to execute
            credential: Credentials for execution
            audit_log: Audit log list
            timeout_seconds: Timeout
        
        Returns:
            Task output
        """
        audit_log.append("Starting container isolation mode")
        
        try:
            import docker
            client = docker.from_env()
            
            # Prepare container environment
            env_vars = {
                "AGENT_CREDENTIAL_TOKEN": credential.token,
                "AGENT_CREDENTIAL_SCOPE": ":".join(credential.scope),
                "AGENT_CREDENTIAL_TTL": str(credential.ttl_seconds)
            }
            
            audit_log.append(f"Injected credential with scope: {credential.scope}")
            
            # Run container
            container = client.containers.run(
                "ubuntu:latest",
                f"echo '{task_intent}' && python3 -c 'print(\"Task executed\")'" if not agent_code else agent_code,
                environment=env_vars,
                mem_limit=f"{RuntimeConfig.DEFAULT_MEMORY_LIMIT_MB}m",
                cpus=RuntimeConfig.DEFAULT_CPU_LIMIT,
                timeout=timeout_seconds,
                remove=True,
                detach=False
            )
            
            audit_log.append("Container execution completed")
            return f"Container output: {container}"
        
        except ImportError:
            audit_log.append("Docker not available, simulating container execution")
            return self._simulate_agent_execution(task_intent, credential, audit_log)
    
    def _execute_vm(self,
                    task_intent: str,
                    agent_code: str,
                    credential: Credential,
                    audit_log: List[str],
                    timeout_seconds: int) -> str:
        """
        Execute task in VM (strong isolation)
        
        In production: Would use Firecracker/KVM for microVM
        For now: Simulated VM execution
        
        Args:
            task_intent: Task description
            agent_code: Code to execute
            credential: Credentials for execution
            audit_log: Audit log list
            timeout_seconds: Timeout
        
        Returns:
            Task output
        """
        audit_log.append("Starting VM isolation mode (TEE/hardware isolation)")
        audit_log.append(f"Allocated VM resources: {RuntimeConfig.DEFAULT_MEMORY_LIMIT_MB}MB RAM")
        audit_log.append(f"Injected credential with scope: {credential.scope}")
        
        # Simulate VM execution
        # In production: Boot Firecracker microVM, execute, shutdown
        result_output = self._simulate_agent_execution(
            task_intent, credential, audit_log
        )
        
        audit_log.append("VM execution completed, cleaning up resources")
        return result_output
    
    def _simulate_agent_execution(self,
                                  task_intent: str,
                                  credential: Credential,
                                  audit_log: List[str]) -> str:
        """
        Simulate agent task execution
        
        In real implementation: Execute actual agent code
        For testing: Return mock result
        
        Args:
            task_intent: Task description
            credential: Execution credential
            audit_log: Audit log
        
        Returns:
            Simulated output
        """
        audit_log.append(f"Executing task: {task_intent}")
        audit_log.append(f"Using credential: {credential.token[:8]}...")
        
        # Simulate some work
        time.sleep(0.1)
        
        # Check credential validity
        if credential.is_expired():
            audit_log.append("ERROR: Credential expired during execution")
            raise Exception("Credential expired")
        
        # Simulate task completion
        audit_log.append("Task executed successfully")
        
        return f"""
Task Execution Summary:
- Intent: {task_intent}
- Credential Scope: {', '.join(credential.scope)}
- Status: Completed
- Output: Agent task processed successfully
        """
