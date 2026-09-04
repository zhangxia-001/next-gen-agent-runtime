"""Test credential management"""

import pytest
import time
from src.credential_manager import CredentialManager


class TestCredentialManager:
    """Test credential lifecycle management"""
    
    def test_create_credential(self):
        """Test credential creation"""
        manager = CredentialManager()
        
        cred = manager.create_credential(
            sandbox_id="sandbox-001",
            allowed_tools=["query_db", "read_file"],
            ttl_seconds=30
        )
        
        assert len(cred.token) > 0
        assert "query_db" in cred.scope
        assert cred.ttl_seconds == 30
        assert not cred.is_expired()
    
    def test_verify_credential_valid(self):
        """Test credential verification for valid access"""
        manager = CredentialManager()
        
        cred = manager.create_credential(
            sandbox_id="sandbox-001",
            allowed_tools=["query_db", "read_file"],
            ttl_seconds=30
        )
        
        # Should allow access to permitted tools
        assert manager.verify_credential(cred.token, "query_db")
        assert manager.verify_credential(cred.token, "read_file")
    
    def test_verify_credential_denied(self):
        """Test credential verification for denied access"""
        manager = CredentialManager()
        
        cred = manager.create_credential(
            sandbox_id="sandbox-001",
            allowed_tools=["query_db"],
            ttl_seconds=30
        )
        
        # Should deny access to non-permitted tools
        assert not manager.verify_credential(cred.token, "delete_db")
    
    def test_credential_expiration(self):
        """Test credential TTL expiration"""
        manager = CredentialManager()
        
        cred = manager.create_credential(
            sandbox_id="sandbox-001",
            allowed_tools=["query_db"],
            ttl_seconds=1  # 1 second TTL
        )
        
        assert not cred.is_expired()
        
        # Wait for expiration
        time.sleep(1.1)
        
        assert cred.is_expired()
        assert not manager.verify_credential(cred.token, "query_db")
    
    def test_revoke_credential(self):
        """Test credential revocation"""
        manager = CredentialManager()
        
        cred = manager.create_credential(
            sandbox_id="sandbox-001",
            allowed_tools=["query_db"],
            ttl_seconds=30
        )
        
        # Should work before revoke
        assert manager.verify_credential(cred.token, "query_db")
        
        # Revoke credential
        manager.revoke_credential(cred.token)
        
        # Should fail after revoke
        assert not manager.verify_credential(cred.token, "query_db")
    
    def test_wildcard_scope(self):
        """Test wildcard scope for credential"""
        manager = CredentialManager()
        
        cred = manager.create_credential(
            sandbox_id="sandbox-001",
            allowed_tools=["*"],  # Wildcard
            ttl_seconds=30
        )
        
        # Should allow access to any tool
        assert manager.verify_credential(cred.token, "query_db")
        assert manager.verify_credential(cred.token, "any_tool")
    
    def test_cleanup_expired(self):
        """Test cleanup of expired credentials"""
        manager = CredentialManager()
        
        # Create multiple credentials
        cred1 = manager.create_credential(
            sandbox_id="sandbox-001",
            allowed_tools=["tool1"],
            ttl_seconds=1
        )
        
        cred2 = manager.create_credential(
            sandbox_id="sandbox-002",
            allowed_tools=["tool2"],
            ttl_seconds=60
        )
        
        # Wait for first to expire
        time.sleep(1.1)
        
        # Cleanup
        manager.cleanup_expired()
        
        # First should be removed, second should remain
        assert not manager.verify_credential(cred1.token, "tool1")
        assert manager.verify_credential(cred2.token, "tool2")
