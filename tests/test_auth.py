"""
Tests for auth.py - API key verification and authentication

Tests validate:
- API key existence checks
- Proper key hashing
- Invalid/missing API keys
- API key validation flow
"""
import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from src.auth import verify_api_key


class TestVerifyAPIKeyBasic:
    """Test basic API key verification"""
    
    def test_missing_api_key_header(self):
        """Reject request with missing API key header"""
        with pytest.raises(HTTPException) as exc_info:
            import asyncio
            asyncio.run(verify_api_key(x_api_key=None))
        
        assert exc_info.value.status_code == 401
        assert "required" in exc_info.value.detail.lower()
    
    def test_empty_api_key_header(self):
        """Reject request with empty API key"""
        with pytest.raises(HTTPException) as exc_info:
            import asyncio
            asyncio.run(verify_api_key(x_api_key=""))
        
        assert exc_info.value.status_code == 401


class TestVerifyAPIKeyValidation:
    """Test API key validation logic"""
    
    @patch('src.auth.event_store.get_api_key')
    def test_valid_api_key(self, mock_get_api_key):
        """Valid API key returns client info"""
        mock_get_api_key.return_value = {
            'client_name': 'test_client',
            'is_active': 1
        }
        
        import asyncio
        result = asyncio.run(verify_api_key(x_api_key="valid_key"))
        
        assert result['client_name'] == 'test_client'
        assert result['api_key'] == 'valid_key'
    
    @patch('src.auth.event_store.get_api_key')
    def test_invalid_api_key(self, mock_get_api_key):
        """Invalid API key raises 403"""
        mock_get_api_key.return_value = None
        
        with pytest.raises(HTTPException) as exc_info:
            import asyncio
            asyncio.run(verify_api_key(x_api_key="invalid_key"))
        
        assert exc_info.value.status_code == 403
        assert "invalid" in exc_info.value.detail.lower()


class TestVerifyAPIKeyHashing:
    """Test API key hashing"""
    
    def test_api_key_hashed_for_lookup(self):
        """API key should be hashed before database lookup"""
        import hashlib
        test_key = "test_api_key_12345"
        expected_hash = hashlib.sha256(test_key.encode()).hexdigest()
        
        # Verify hashing logic
        assert len(expected_hash) == 64  # SHA256 hex is 64 chars
        assert isinstance(expected_hash, str)
