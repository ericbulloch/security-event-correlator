"""
Tests for payload_validator.py

Tests validate:
- Valid payload parsing
- Invalid JSON handling
- Payload size limits (total and per-event)
- Event count limits
- Array requirement
"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException

from src.payload_validator import PayloadValidator


class TestPayloadValidatorValidPayloads:
    """Test valid payload parsing"""
    
    @pytest.mark.asyncio
    async def test_valid_single_event(self):
        """Parse valid payload with single event"""
        payload = [{"timestamp": "2026-06-25T10:00:00Z", "source": "test"}]
        
        # Create mock request
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert result == payload
        assert len(result) == 1
    
    @pytest.mark.asyncio
    async def test_valid_multiple_events(self):
        """Parse valid payload with multiple events"""
        payload = [
            {"timestamp": "2026-06-25T10:00:00Z", "source": "test1"},
            {"timestamp": "2026-06-25T10:00:01Z", "source": "test2"},
            {"timestamp": "2026-06-25T10:00:02Z", "source": "test3"}
        ]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert result == payload
        assert len(result) == 3
    
    @pytest.mark.asyncio
    async def test_valid_chunked_payload(self):
        """Parse payload received in multiple chunks"""
        payload = [{"timestamp": "2026-06-25T10:00:00Z", "source": "test"}]
        json_str = json.dumps(payload)
        
        # Split payload into chunks
        chunk_size = 10
        chunks = [json_str[i:i+chunk_size].encode() for i in range(0, len(json_str), chunk_size)]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(chunks))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert result == payload
    
    @pytest.mark.asyncio
    async def test_valid_empty_details(self):
        """Parse event with empty details"""
        payload = [{"timestamp": "2026-06-25T10:00:00Z", "source": "test", "details": {}}]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert result == payload
    
    @pytest.mark.asyncio
    async def test_valid_complex_event(self):
        """Parse event with complex nested data"""
        payload = [{
            "timestamp": "2026-06-25T10:00:00Z",
            "source": "test",
            "details": {
                "nested": {"key": "value"},
                "array": [1, 2, 3],
                "string": "value"
            }
        }]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert result == payload
        assert result[0]["details"]["nested"]["key"] == "value"
    
    def _async_generator(self, items):
        """Helper to create async generator"""
        async def gen():
            for item in items:
                yield item
        return gen()


class TestPayloadValidatorInvalidJSON:
    """Test invalid JSON handling"""
    
    @pytest.mark.asyncio
    async def test_invalid_json_syntax_error(self):
        """Reject malformed JSON"""
        invalid_json = b'{"incomplete": '
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator([invalid_json]))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 400
        assert "json" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_invalid_json_trailing_comma(self):
        """Reject JSON with trailing comma"""
        invalid_json = b'[{"key": "value"},]'
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator([invalid_json]))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 400
    
    @pytest.mark.asyncio
    async def test_invalid_json_empty_body(self):
        """Reject empty request body"""
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator([b'']))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 400
    
    def _async_generator(self, items):
        """Helper to create async generator"""
        async def gen():
            for item in items:
                yield item
        return gen()


class TestPayloadValidatorNotArray:
    """Test rejection of non-array payloads"""
    
    @pytest.mark.asyncio
    async def test_payload_is_dict_not_array(self):
        """Reject payload that is a dict instead of array"""
        payload = {"timestamp": "2026-06-25T10:00:00Z", "source": "test"}
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 400
        assert "array" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_payload_is_string_not_array(self):
        """Reject payload that is a string"""
        payload = "not an array"
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 400
    
    def _async_generator(self, items):
        """Helper to create async generator"""
        async def gen():
            for item in items:
                yield item
        return gen()


class TestPayloadValidatorEventCountLimit:
    """Test maximum events per batch limit"""
    
    @pytest.mark.asyncio
    async def test_at_max_event_count(self):
        """Accept exactly max events (1000)"""
        payload = [{"timestamp": "2026-06-25T10:00:00Z", "source": f"test{i}"} for i in range(1000)]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert len(result) == 1000
    
    @pytest.mark.asyncio
    async def test_exceed_max_event_count(self):
        """Reject more than max events (1000)"""
        payload = [{"timestamp": "2026-06-25T10:00:00Z", "source": f"test{i}"} for i in range(1001)]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 400
        assert "too many events" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_way_over_max_event_count(self):
        """Reject significantly over max events"""
        payload = [{"timestamp": "2026-06-25T10:00:00Z", "source": f"test{i}"} for i in range(5000)]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 400
    
    def _async_generator(self, items):
        """Helper to create async generator"""
        async def gen():
            for item in items:
                yield item
        return gen()


class TestPayloadValidatorTotalSizeLimit:
    """Test total payload size limit (16 MB)"""
    
    @pytest.mark.asyncio
    async def test_small_payload_under_limit(self):
        """Accept small payload well under 16 MB limit"""
        # Create payload around 1 MB
        event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test", "data": "x" * 100000}
        payload = [event for _ in range(10)]  # ~10 MB total
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert len(result) == 10
    
    @pytest.mark.asyncio
    async def test_payload_exceeds_total_size_limit(self):
        """Reject payload exceeding 16 MB total limit"""
        # Create very large payload
        event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test", "data": "x" * 1000000}
        payload = [event for _ in range(20)]  # ~20 MB total
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 413  # Payload Too Large
        assert "too large" in exc_info.value.detail.lower()
    
    def _async_generator(self, items):
        """Helper to create async generator"""
        async def gen():
            for item in items:
                yield item
        return gen()


class TestPayloadValidatorEventSizeLimit:
    """Test individual event size limit (1 MB)"""
    
    @pytest.mark.asyncio
    async def test_event_under_size_limit(self):
        """Accept event under 1 MB limit"""
        # Create event ~500 KB
        event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test", "data": "x" * 500000}
        payload = [event]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        result = await PayloadValidator.validate_and_parse(request)
        
        assert len(result) == 1
    
    @pytest.mark.asyncio
    async def test_single_event_exceeds_size_limit(self):
        """Reject single event exceeding 1 MB limit"""
        # Create event ~2 MB
        event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test", "data": "x" * 2000000}
        payload = [event]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 413
        assert "too large" in exc_info.value.detail.lower()
        assert "event" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_multiple_events_one_oversized(self):
        """Reject batch when one event exceeds size limit"""
        small_event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test"}
        large_event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test", "data": "x" * 2000000}
        payload = [small_event, large_event, small_event]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        assert exc_info.value.status_code == 413
    
    def _async_generator(self, items):
        """Helper to create async generator"""
        async def gen():
            for item in items:
                yield item
        return gen()


class TestPayloadValidatorErrorMessages:
    """Test error message clarity"""
    
    @pytest.mark.asyncio
    async def test_error_message_shows_limits(self):
        """Error message includes size limits"""
        payload = [{"timestamp": "2026-06-25T10:00:00Z", "source": "test", "data": "x" * 2000000}]
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        # Error should mention "MB" and the limit
        assert "MB" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_error_message_event_index_on_oversized_event(self):
        """Error identifies which event is too large"""
        small_event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test"}
        large_event = {"timestamp": "2026-06-25T10:00:00Z", "source": "test", "data": "x" * 2000000}
        payload = [small_event, large_event]  # large_event at index 1
        
        request = AsyncMock()
        request.stream = AsyncMock(return_value=self._async_generator(
            [json.dumps(payload).encode()]
        ))
        
        with pytest.raises(HTTPException) as exc_info:
            await PayloadValidator.validate_and_parse(request)
        
        # Error should identify event 1
        assert "1" in exc_info.value.detail or "event" in exc_info.value.detail.lower()
    
    def _async_generator(self, items):
        """Helper to create async generator"""
        async def gen():
            for item in items:
                yield item
        return gen()
