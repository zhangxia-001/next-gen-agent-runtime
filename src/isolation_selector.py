"""Isolation capability matrix and behavior-to-capability mapping"""

from typing import Dict, Set, List
from .config import (
    ISOLATION_CAPABILITY_MATRIX,
    BEHAVIOR_CAPABILITY_MAPPING,
    CapabilityLevel,
    IsolationMode,
    SENSITIVITY_ISOLATION_MAP
)
from .models import AgentBehaviorProfile, IsolationDecision


class BehaviorToCapabilityMapper:
    """Maps agent behavior to isolation capability requirements"""
    
    SENSITIVE_DIRS = {"/etc", "/root", "/sys", "/proc", "/dev", "/boot"}
    
    def __init__(self):
        self.capability_matrix = ISOLATION_CAPABILITY_MATRIX
        self.behavior_mapping = BEHAVIOR_CAPABILITY_MAPPING
    
    def analyze_behavior(self, profile: AgentBehaviorProfile) -> Dict[str, int]:
        """
        Analyze agent behavior and return required isolation capabilities
        
        Args:
            profile: AgentBehaviorProfile
        
        Returns:
            Dict mapping capability names to required levels (0-3)
        """
        capability_requirements = {
            "syscall_filtering": CapabilityLevel.NONE.value,
            "file_access_control": CapabilityLevel.NONE.value,
            "network_isolation": CapabilityLevel.NONE.value,
            "child_process_control": CapabilityLevel.NONE.value,
            "privilege_escalation_prevention": CapabilityLevel.NONE.value,
            "resource_limits": CapabilityLevel.NONE.value,
            "memory_isolation": CapabilityLevel.NONE.value,
            "kernel_module_execution": CapabilityLevel.NONE.value,
        }
        
        # Check privileged syscalls
        if profile.has_high_privilege_risk():
            capability_requirements["syscall_filtering"] = max(
                capability_requirements["syscall_filtering"],
                CapabilityLevel.MEDIUM.value
            )
            capability_requirements["privilege_escalation_prevention"] = max(
                capability_requirements["privilege_escalation_prevention"],
                CapabilityLevel.MEDIUM.value
            )
        
        # Check file access
        if profile.has_file_access_risk(self.SENSITIVE_DIRS):
            capability_requirements["file_access_control"] = CapabilityLevel.STRONG.value
        
        # Check network activity
        if profile.has_network_risk():
            capability_requirements["network_isolation"] = max(
                capability_requirements["network_isolation"],
                CapabilityLevel.MEDIUM.value
            )
        
        # Check process creation
        if profile.has_process_risk():
            capability_requirements["child_process_control"] = max(
                capability_requirements["child_process_control"],
                CapabilityLevel.MEDIUM.value
            )
        
        # Check resource usage
        if profile.has_resource_risk():
            capability_requirements["resource_limits"] = CapabilityLevel.STRONG.value
        
        # Check memory patterns
        if profile.memory_access_patterns in ["suspicious", "random"]:
            capability_requirements["memory_isolation"] = CapabilityLevel.MEDIUM.value
        
        return capability_requirements
    
    def find_minimum_isolation(self, 
                               capability_requirements: Dict[str, int]) -> str:
        """
        Find minimum isolation level that satisfies all capability requirements
        
        Args:
            capability_requirements: Dict of required capabilities
        
        Returns:
            Isolation mode: "eBPF" | "CONTAINER" | "VM"
        """
        # Try from lightest to heaviest isolation
        for isolation_mode in ["eBPF", "CONTAINER", "VM"]:
            if self._satisfies_requirements(
                self.capability_matrix[isolation_mode],
                capability_requirements
            ):
                return isolation_mode
        
        # If nothing satisfies, return strongest
        return "VM"
    
    def _satisfies_requirements(self,
                                capabilities: Dict[str, int],
                                requirements: Dict[str, int]) -> bool:
        """
        Check if isolation mechanism satisfies all requirements
        
        Args:
            capabilities: Available capabilities of an isolation mode
            requirements: Required capability levels
        
        Returns:
            True if all requirements satisfied
        """
        for cap_name, required_level in requirements.items():
            if required_level == CapabilityLevel.NONE.value:
                continue  # No requirement
            
            actual_level = capabilities.get(cap_name, CapabilityLevel.NONE.value)
            if actual_level < required_level:
                return False
        
        return True


class AdaptiveIsolationSelector:
    """Selects appropriate isolation mechanism based on behavior and policies"""
    
    def __init__(self):
        self.mapper = BehaviorToCapabilityMapper()
        self.capability_matrix = ISOLATION_CAPABILITY_MATRIX
    
    def select_isolation(self,
                         profile: AgentBehaviorProfile,
                         sensitivity_level: str,
                         override_level: str = None) -> IsolationDecision:
        """
        Select isolation mechanism through capability matrix mapping
        
        Args:
            profile: AgentBehaviorProfile from behavior analysis
            sensitivity_level: Data sensitivity (LOW/MEDIUM/HIGH/CRITICAL)
            override_level: Manual override isolation level (optional)
        
        Returns:
            IsolationDecision with reasoning and confidence
        """
        # Step 1: Map behavior to capability requirements
        capability_requirements = self.mapper.analyze_behavior(profile)
        
        # Step 2: Auto-select based on capability requirements
        auto_selected = self.mapper.find_minimum_isolation(capability_requirements)
        
        # Step 3: Consider sensitivity level constraints
        min_required_isolation = SENSITIVITY_ISOLATION_MAP.get(sensitivity_level)
        if min_required_isolation:
            auto_selected = self._apply_minimum_isolation(
                auto_selected,
                min_required_isolation
            )
        
        # Step 4: Apply manual override if provided
        final_isolation = override_level or auto_selected
        
        # Step 5: Generate decision
        decision = IsolationDecision(
            isolation_mode=final_isolation,
            required_capabilities=capability_requirements,
            behavior_profile=profile,
            reasoning=self._generate_reasoning(
                profile,
                capability_requirements,
                auto_selected,
                final_isolation
            ),
            confidence=self._calculate_confidence(
                capability_requirements,
                final_isolation
            )
        )
        
        return decision
    
    def _apply_minimum_isolation(self, auto_selected: str,
                                 min_required: str) -> str:
        """
        Ensure isolation meets minimum requirements
        
        Args:
            auto_selected: Auto-selected isolation mode
            min_required: Minimum required isolation mode
        
        Returns:
            The stronger of the two
        """
        hierarchy = ["eBPF", "CONTAINER", "VM"]
        auto_idx = hierarchy.index(auto_selected)
        min_idx = hierarchy.index(min_required)
        
        if auto_idx < min_idx:
            return min_required
        return auto_selected
    
    def _generate_reasoning(self,
                            profile: AgentBehaviorProfile,
                            requirements: Dict[str, int],
                            auto_selected: str,
                            final_selected: str) -> str:
        """
        Generate human-readable reasoning for the decision
        
        Args:
            profile: Behavior profile
            requirements: Capability requirements
            auto_selected: Auto-selected isolation
            final_selected: Final isolation decision
        
        Returns:
            Reasoning string
        """
        reasons = []
        
        # Behavioral observations
        if profile.privileged_syscalls > 0:
            reasons.append(f"Detected {profile.privileged_syscalls} privileged syscalls")
        
        if profile.network_connections > 5:
            reasons.append(f"Made {profile.network_connections} network connections")
        
        if profile.child_processes_spawned > 0:
            reasons.append(f"Spawned {profile.child_processes_spawned} child processes")
        
        if profile.has_file_access_risk({"etc", "root", "sys"}):
            reasons.append("Accessed sensitive system directories")
        
        # Capability analysis
        required_caps = [cap for cap, level in requirements.items() if level > 0]
        if required_caps:
            reasons.append(f"Requires isolation for: {', '.join(required_caps)}")
        
        # Decision
        reasons.append(f"Auto-selected: {auto_selected}")
        if final_selected != auto_selected:
            reasons.append(f"Overridden to: {final_selected}")
        
        return " → ".join(reasons)
    
    def _calculate_confidence(self,
                              requirements: Dict[str, int],
                              isolation_mode: str) -> float:
        """
        Calculate confidence of the isolation decision
        
        Args:
            requirements: Capability requirements
            isolation_mode: Selected isolation mode
        
        Returns:
            Confidence score (0.0-1.0)
        """
        capabilities = self.capability_matrix[isolation_mode]
        satisfied = 0
        
        for cap_name, required_level in requirements.items():
            if required_level == CapabilityLevel.NONE.value:
                satisfied += 1
            else:
                actual_level = capabilities.get(cap_name, CapabilityLevel.NONE.value)
                if actual_level >= required_level:
                    satisfied += 1
        
        total = len(requirements)
        return satisfied / total if total > 0 else 0.5
