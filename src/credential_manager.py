"""Credential management for sandboxed execution"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import secrets

from .models import Credential


class CredentialManager:
    """Manages temporary credentials with TTL and scope"""
    
    def __init__(self):
        self.credentials: Dict[str, Credential] = {}
    
    def create_credential(self,
                          sandbox_id: str,
                          allowed_tools: List[str],
                          ttl_seconds: int = 30) -> Credential:
        """
        Create temporary credential for sandbox
        
        Args:
            sandbox_id: Sandbox identifier
            allowed_tools: List of allowed tools/resources
            ttl_seconds: Time-to-live in seconds (default 30)
        
        Returns:
            Credential object
        """
        # Generate secure token
        token = secrets.token_hex(32)
        
        credential = Credential(
            token=token,
            scope=allowed_tools,
            ttl_seconds=ttl_seconds,
            created_at=datetime.now()
        )
        
        self.credentials[token] = credential
        return credential
    
    def verify_credential(self, token: str, resource: str) -> bool:
        """
        Verify if credential has access to resource
        
        Args:
            token: Credential token
            resource: Resource to access
        
        Returns:
            True if credential grants access
        """
        if token not in self.credentials:
            return False
        
        credential = self.credentials[token]
        
        # Check expiration
        if credential.is_expired():
            del self.credentials[token]
            return False
        
        # Check resource access
        return credential.can_access(resource)
    
    def revoke_credential(self, token: str):
        """
        Revoke a credential
        
        Args:
            token: Credential token to revoke
        """
        if token in self.credentials:
            del self.credentials[token]
    
    def cleanup_expired(self):
        """
        Remove all expired credentials
        """
        expired_tokens = [
            token for token, cred in self.credentials.items()
            if cred.is_expired()
        ]
        
        for token in expired_tokens:
            del self.credentials[token]
    
    def get_credential_info(self, token: str) -> Optional[Dict]:
        """
        Get credential information (for logging/auditing)
        
        Args:
            token: Credential token
        
        Returns:
            Credential info dict or None
        """
        if token not in self.credentials:
            return None
        
        cred = self.credentials[token]
        return {
            "token": token,
            "scope": cred.scope,
            "created_at": cred.created_at.isoformat(),
            "expires_at": (cred.created_at + timedelta(seconds=cred.ttl_seconds)).isoformat(),
            "is_expired": cred.is_expired()
        }
