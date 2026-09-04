"""Intent recognition gateway with multiple NLU approaches"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import re

from .models import IntentResult


class KeywordIntentRecognizer:
    """Simple keyword-based intent recognition"""
    
    INTENT_KEYWORDS = {
        "database_query": ["database", "query", "select", "table", "data"],
        "file_access": ["file", "read", "write", "open", "path"],
        "network_operation": ["network", "connect", "socket", "port", "http"],
        "privilege_escalation": ["sudo", "chmod", "chown", "privilege", "escalate"],
        "system_configuration": ["system", "config", "setting", "kernel", "module"],
        "process_management": ["process", "spawn", "fork", "exec", "kill"],
        "normal_operation": ["compute", "calculate", "process", "analyze"]
    }
    
    def recognize(self, task_intent: str) -> IntentResult:
        """Recognize intent using keyword matching"""
        task_lower = task_intent.lower()
        scores = {}
        
        for intent_type, keywords in self.INTENT_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in task_lower)
            if score > 0:
                scores[intent_type] = score
        
        if not scores:
            return IntentResult(
                intent="unknown",
                confidence=0.0,
                method="keyword"
            )
        
        # Find best match
        best_intent = max(scores, key=scores.get)
        max_score = scores[best_intent]
        confidence = min(max_score / len(self.INTENT_KEYWORDS[best_intent]), 1.0)
        
        # Get alternatives
        alternatives = [(intent, score / len(self.INTENT_KEYWORDS[intent]))
                       for intent, score in sorted(scores.items(), key=lambda x: x[1], reverse=True)]
        
        return IntentResult(
            intent=best_intent,
            confidence=confidence,
            alternatives=alternatives,
            method="keyword"
        )


class BehaviorBasedIntentRecognizer:
    """Intent recognition based on behavioral patterns"""
    
    # Behavioral patterns for each intent type
    BEHAVIOR_PATTERNS = {
        "database_query": {
            "syscall_keywords": ["open", "read", "mmap"],
            "network_activity": "low",
            "process_creation": "none",
            "file_access_scope": "data_dirs"
        },
        "file_access": {
            "syscall_keywords": ["open", "stat", "chmod"],
            "network_activity": "none",
            "process_creation": "none",
            "file_access_scope": "mixed"
        },
        "network_operation": {
            "syscall_keywords": ["socket", "connect", "send"],
            "network_activity": "high",
            "process_creation": "none",
            "file_access_scope": "minimal"
        },
        "privilege_escalation": {
            "syscall_keywords": ["prctl", "setuid", "setgid", "ioctl"],
            "network_activity": "low",
            "process_creation": "none",
            "file_access_scope": "system_dirs"
        },
        "process_management": {
            "syscall_keywords": ["fork", "exec", "clone", "kill"],
            "network_activity": "none",
            "process_creation": "high",
            "file_access_scope": "minimal"
        }
    }
    
    def recognize(self, task_intent: str, context: Dict) -> IntentResult:
        """Recognize intent based on behavioral patterns"""
        scores = {}
        
        for intent_type, pattern in self.BEHAVIOR_PATTERNS.items():
            score = 0.0
            total_checks = 0
            
            # Check if keywords appear in task intent
            for keyword in pattern.get("syscall_keywords", []):
                total_checks += 1
                if keyword in task_intent.lower():
                    score += 1
            
            if total_checks > 0:
                scores[intent_type] = score / total_checks
        
        if not scores or max(scores.values()) == 0:
            return IntentResult(
                intent="unknown",
                confidence=0.0,
                method="behavior"
            )
        
        best_intent = max(scores, key=scores.get)
        confidence = scores[best_intent]
        
        alternatives = [(intent, score)
                       for intent, score in sorted(scores.items(), key=lambda x: x[1], reverse=True)]
        
        return IntentResult(
            intent=best_intent,
            confidence=confidence,
            alternatives=alternatives,
            method="behavior"
        )


class HybridIntentGateway:
    """Hybrid intent recognition combining multiple approaches"""
    
    def __init__(self):
        self.keyword_recognizer = KeywordIntentRecognizer()
        self.behavior_recognizer = BehaviorBasedIntentRecognizer()
        self.history_cache: Dict[str, IntentResult] = {}
    
    def recognize(self, task_intent: str, context: Optional[Dict] = None) -> IntentResult:
        """
        Recognize intent using multiple methods and ensemble results
        
        Args:
            task_intent: The task description
            context: Optional execution context with behavioral data
        
        Returns:
            IntentResult with ensembled confidence
        """
        if context is None:
            context = {}
        
        # Method 1: Check history cache
        cached = self._check_history(task_intent)
        if cached:
            return cached
        
        # Method 2: Keyword-based recognition
        keyword_result = self.keyword_recognizer.recognize(task_intent)
        
        # Method 3: Behavior-based recognition
        behavior_result = self.behavior_recognizer.recognize(task_intent, context)
        
        # Method 4: Ensemble results
        final_result = self._ensemble_results(
            keyword_result,
            behavior_result,
            context
        )
        
        # Cache result
        self.history_cache[task_intent] = final_result
        
        return final_result
    
    def _check_history(self, task_intent: str) -> Optional[IntentResult]:
        """Check if similar intent was seen before"""
        # Simple exact match in history
        return self.history_cache.get(task_intent)
    
    def _ensemble_results(self, keyword_result: IntentResult,
                         behavior_result: IntentResult,
                         context: Dict) -> IntentResult:
        """
        Ensemble multiple recognition results
        
        Weighted voting:
        - If both methods agree, confidence increases
        - If they disagree, use weighted average
        """
        # If both methods agree
        if keyword_result.intent == behavior_result.intent:
            # Increase confidence when methods agree
            ensemble_confidence = min(
                (keyword_result.confidence + behavior_result.confidence) / 2 * 1.2,
                1.0
            )
            return IntentResult(
                intent=keyword_result.intent,
                confidence=ensemble_confidence,
                entities=keyword_result.entities,
                alternatives=keyword_result.alternatives,
                method="hybrid_agreed"
            )
        
        # Methods disagree - use higher confidence result
        if keyword_result.confidence > behavior_result.confidence:
            best_result = keyword_result
        else:
            best_result = behavior_result
        
        # Slightly reduce confidence when methods disagree
        ensemble_confidence = best_result.confidence * 0.9
        
        return IntentResult(
            intent=best_result.intent,
            confidence=ensemble_confidence,
            entities=best_result.entities,
            alternatives=best_result.alternatives + keyword_result.alternatives,
            method="hybrid_disagreed"
        )
    
    def clear_cache(self):
        """Clear history cache"""
        self.history_cache.clear()
