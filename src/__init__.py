"""Next-Gen AI Agent Runtime Framework

A runtime system featuring dynamic trust scheduling, adaptive isolation,
and behavior-based capability mapping for AI agents.
"""

__version__ = "0.1.0"
__author__ = "zhangxia-001"

from .models import (
    AgentBehaviorProfile,
    IsolationDecision,
    IntentResult,
    ExecutionTrace,
    Credential
)
from .runtime import AgentRuntime

__all__ = [
    "AgentRuntime",
    "AgentBehaviorProfile",
    "IsolationDecision",
    "IntentResult",
    "ExecutionTrace",
    "Credential"
]
