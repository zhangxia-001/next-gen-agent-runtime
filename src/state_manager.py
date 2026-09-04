"""State management with content-addressed storage (CAS)"""

import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime


class ContentAddressedStorage:
    """Simplified content-addressed storage backend"""
    
    def __init__(self):
        self.store: Dict[str, Any] = {}  # hash -> content
        self.history: List[str] = []  # List of hashes in order
    
    def store_state(self, state: Dict[str, Any]) -> str:
        """
        Store state and return its content hash
        
        Args:
            state: State dict to store
        
        Returns:
            Content hash (SHA256)
        """
        # Serialize to JSON for consistent hashing
        state_json = json.dumps(state, sort_keys=True)
        state_hash = hashlib.sha256(state_json.encode()).hexdigest()
        
        # Store if not already present
        if state_hash not in self.store:
            self.store[state_hash] = state
            self.history.append(state_hash)
        
        return state_hash
    
    def get_state(self, state_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve state by its hash
        
        Args:
            state_hash: Content hash
        
        Returns:
            State dict or None if not found
        """
        return self.store.get(state_hash)
    
    def compare_and_swap(self,
                         expected_hash: str,
                         new_state: Dict[str, Any]) -> bool:
        """
        Atomic compare-and-swap operation
        
        Only succeeds if the expected hash exists and is current
        
        Args:
            expected_hash: Expected current state hash
            new_state: New state to store
        
        Returns:
            True if swap succeeded, False otherwise
        """
        # Check if expected hash exists
        if expected_hash not in self.store:
            return False
        
        # Store new state
        self.store_state(new_state)
        return True
    
    def get_history(self, limit: int = None) -> List[str]:
        """
        Get state history
        
        Args:
            limit: Max number of hashes to return
        
        Returns:
            List of content hashes in chronological order
        """
        if limit:
            return self.history[-limit:]
        return self.history.copy()


class StateManager:
    """Manages agent state with snapshots and recovery"""
    
    def __init__(self):
        self.cas = ContentAddressedStorage()
        self.snapshots: Dict[str, Dict[str, Any]] = {}  # Named snapshots
        self.current_state_hash: Optional[str] = None
    
    def create_snapshot(self, name: str, state: Dict[str, Any]) -> str:
        """
        Create a named snapshot of state
        
        Args:
            name: Snapshot name
            state: State to snapshot
        
        Returns:
            State hash
        """
        state_hash = self.cas.store_state(state)
        self.snapshots[name] = {
            "hash": state_hash,
            "created_at": datetime.now().isoformat(),
            "state": state
        }
        return state_hash
    
    def restore_snapshot(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Restore state from named snapshot
        
        Args:
            name: Snapshot name
        
        Returns:
            Restored state or None if not found
        """
        if name not in self.snapshots:
            return None
        
        return self.snapshots[name]["state"]
    
    def transfer_state(self, from_hash: str, to_state: Dict[str, Any]) -> bool:
        """
        Transfer state using CAS with compare-and-swap
        
        Args:
            from_hash: Current state hash
            to_state: New state
        
        Returns:
            True if transfer succeeded
        """
        success = self.cas.compare_and_swap(from_hash, to_state)
        if success:
            self.current_state_hash = self.cas.store_state(to_state)
        return success
    
    def get_state_history(self, limit: int = 10) -> List[str]:
        """
        Get state change history
        
        Args:
            limit: Max entries to return
        
        Returns:
            List of state hashes
        """
        return self.cas.get_history(limit)
    
    def list_snapshots(self) -> List[str]:
        """List all available snapshots"""
        return list(self.snapshots.keys())
