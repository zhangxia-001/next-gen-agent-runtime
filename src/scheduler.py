"""Token-aware scheduler for agent task execution"""

from typing import Dict, List, Optional
from dataclasses import dataclass
import json

from .config import RuntimeConfig


@dataclass
class Node:
    """Compute node for task execution"""
    name: str
    region: str
    available_cpu: float
    available_memory_mb: int
    isolation_modes: List[str]
    token_cost_per_second: Dict[str, float]  # Cost per isolation mode


class SimpleScheduler:
    """Token and cost-aware task scheduler"""
    
    def __init__(self, nodes: Optional[List[Node]] = None):
        """
        Initialize scheduler
        
        Args:
            nodes: List of available nodes
        """
        self.nodes = nodes or self._initialize_default_nodes()
        self.token_cost_per_node = {}  # Cache for token costs
    
    def _initialize_default_nodes(self) -> List[Node]:
        """Initialize default nodes from configuration"""
        nodes = []
        
        for region, pool_config in RuntimeConfig.TRUSTED_NODE_POOLS.items():
            for node_name in pool_config["nodes"]:
                node = Node(
                    name=node_name,
                    region=region,
                    available_cpu=4.0,
                    available_memory_mb=8192,
                    isolation_modes=pool_config["supported_runtimes"],
                    token_cost_per_second={
                        "eBPF": 0.001,
                        "CONTAINER": 0.005,
                        "VM": 0.01
                    }
                )
                nodes.append(node)
        
        return nodes
    
    def estimate_token_cost(self, task_intent: str) -> int:
        """
        Estimate tokens needed for task execution
        
        Simplified: Based on task intent length
        In production: Use proper tokenizer (e.g., tiktoken)
        
        Args:
            task_intent: Task description
        
        Returns:
            Estimated token count
        """
        # Simple estimation: ~1.3 tokens per word
        words = len(task_intent.split())
        return int(words * 1.3)
    
    def select_node(self,
                    isolation_mode: str,
                    token_estimate: int,
                    priority: str = "normal") -> Optional[Node]:
        """
        Select best node for task execution
        
        Optimization criteria (in order):
        1. Support required isolation mode
        2. Has sufficient resources
        3. Minimum token cost
        4. Priority/SLA considerations
        
        Args:
            isolation_mode: Required isolation (eBPF/CONTAINER/VM)
            token_estimate: Estimated tokens for execution
            priority: Priority level (low/normal/high)
        
        Returns:
            Selected node or None if no suitable node found
        """
        eligible_nodes = []
        
        for node in self.nodes:
            # Check if node supports required isolation mode
            if isolation_mode not in node.isolation_modes:
                continue
            
            # Check if node has sufficient resources
            if not self._has_sufficient_resources(node, isolation_mode):
                continue
            
            # Estimate cost for this node
            estimated_cost = self._estimate_execution_cost(
                node,
                isolation_mode,
                token_estimate
            )
            
            eligible_nodes.append({
                "node": node,
                "cost": estimated_cost,
                "sla_satisfied": self._check_sla(node, priority)
            })
        
        if not eligible_nodes:
            return None
        
        # Sort by: SLA satisfaction first, then by cost
        eligible_nodes.sort(
            key=lambda x: (not x["sla_satisfied"], x["cost"])
        )
        
        return eligible_nodes[0]["node"]
    
    def _has_sufficient_resources(self, node: Node,
                                   isolation_mode: str) -> bool:
        """
        Check if node has sufficient resources for execution
        
        Args:
            node: Target node
            isolation_mode: Required isolation mode
        
        Returns:
            True if resources sufficient
        """
        # Minimum requirements based on isolation mode
        min_cpu_required = {
            "eBPF": 0.5,
            "CONTAINER": 1.0,
            "VM": 2.0
        }
        
        min_memory_required = {
            "eBPF": 256,
            "CONTAINER": 512,
            "VM": 2048
        }
        
        cpu_ok = node.available_cpu >= min_cpu_required.get(isolation_mode, 1.0)
        memory_ok = node.available_memory_mb >= min_memory_required.get(isolation_mode, 256)
        
        return cpu_ok and memory_ok
    
    def _estimate_execution_cost(self,
                                 node: Node,
                                 isolation_mode: str,
                                 token_count: int) -> float:
        """
        Estimate execution cost in tokens
        
        Args:
            node: Target node
            isolation_mode: Isolation mode
            token_count: Task token count
        
        Returns:
            Estimated cost
        """
        # Base cost per token for this isolation mode
        cost_per_token = node.token_cost_per_second[isolation_mode]
        
        # Estimate execution time (simplified)
        # Assume ~10 tokens per second base throughput
        estimated_seconds = token_count / 10.0
        
        total_cost = cost_per_token * estimated_seconds * token_count
        
        return total_cost
    
    def _check_sla(self, node: Node, priority: str) -> bool:
        """
        Check if node satisfies SLA for priority level
        
        Args:
            node: Target node
            priority: Priority level
        
        Returns:
            True if SLA satisfied
        """
        # Simplified SLA check
        # In production: Check node load, region, compliance tags, etc.
        return True
    
    def get_node_by_name(self, node_name: str) -> Optional[Node]:
        """Get node by name"""
        for node in self.nodes:
            if node.name == node_name:
                return node
        return None
    
    def get_nodes_by_region(self, region: str) -> List[Node]:
        """Get all nodes in a region"""
        return [node for node in self.nodes if node.region == region]
