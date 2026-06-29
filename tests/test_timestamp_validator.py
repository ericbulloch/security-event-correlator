"""
Tests for timestamp_validator.py

Tests validate:
- UTC timestamp enforcement
- No future timestamps
- No timestamps older than 7 days
- Multiple timestamp format support
- Timezone handling
"""
import pytest
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

from src.timestamp_validator import TimestampValidator


class TestTimestampValidatorValidFormats:
    """Test valid timestamp formats"""
    
    def test_iso8601_with_z_suffix(self):
        """Valid ISO 8601 with Z suffix (Zulu/UTC)"""
        result = TimestampValidator.validate("2026-06-25T10:00:00Z")
        assert result is not None
        assert result.tzinfo == timezone.utc
        assert isinstance(result, datetime)
    
    def test_iso8601_with_milliseconds(self):
        """Valid ISO 8601 with milliseconds"""
        result = TimestampValidator.validate("2026-06-25T10:00:00.123456Z")
        assert result is not None
        assert result.tzinfo == timezone.utc
    
    def test_iso8601_with_utc_offset(self):
        """Valid ISO 8601 with +00:00 UTC offset"""
        result = TimestampValidator.validate("2026-06-25T10:00:00+00:00")
        assert result is not None
        assert result.tzinfo == timezone.utc
    
    def test_iso8601_with_milliseconds_and_offset(self):
        """Valid ISO 8601 with milliseconds and UTC offset"""
        result = TimestampValidator.validate("2026-06-25T10:00:00.123456+00:00")
        assert result is not None
        assert result.tzinfo == timezone.utc
    
    def test_unix_timestamp(self):
        """Valid Unix timestamp (5 days ago)"""
        five_days_ago = int((datetime.now(timezone.utc) - timedelta(days=5)).timestamp())
        result = TimestampValidator.validate(five_days_ago)
        assert result is not None
        assert result.tzinfo == timezone.utc
    
    def test_unix_timestamp_float(self):
        """Valid Unix timestamp as float"""
        five_days_ago = (datetime.now(timezone.utc) - timedelta(days=5)).timestamp()
        result = TimestampValidator.validate(five_days_ago)
        assert result is not None
        assert result.tzinfo == timezone.utc
    
    def test_datetime_object(self):
        """Valid datetime object"""
        ts = datetime.now(timezone.utc)
        result = TimestampValidator.validate(ts)
        assert result is not None
        assert result.tzinfo == timezone.utc


class TestTimestampValidatorInvalidFormats:
    """Test invalid timestamp formats"""
    
    def test_invalid_format_random_string(self):
        """Invalid format: random string"""
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate("not a timestamp")
        assert exc_info.value.status_code == 400
    
    def test_invalid_format_bad_iso(self):
        """Invalid format: malformed ISO date"""
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate("2026-13-32T25:61:61Z")
        assert exc_info.value.status_code == 400
    
    def test_invalid_type_list(self):
        """Invalid type: list instead of timestamp"""
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate([1, 2, 3])
        assert exc_info.value.status_code == 400
    
    def test_invalid_type_dict(self):
        """Invalid type: dict instead of timestamp"""
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate({"timestamp": "2026-06-25T10:00:00Z"})
        assert exc_info.value.status_code == 400
    
    def test_invalid_type_none(self):
        """Invalid type: None"""
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(None)
        assert exc_info.value.status_code == 400


class TestTimestampValidatorFutureTimestamps:
    """Test rejection of future timestamps"""
    
    def test_future_timestamp_5_minutes(self):
        """Reject timestamp 5 minutes in the future"""
        future = datetime.now(timezone.utc) + timedelta(minutes=5)
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(future)
        assert exc_info.value.status_code == 400
        assert "future" in exc_info.value.detail.lower()
    
    def test_future_timestamp_1_second(self):
        """Reject timestamp 1 second in the future"""
        future = datetime.now(timezone.utc) + timedelta(seconds=1)
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(future)
        assert exc_info.value.status_code == 400
    
    def test_future_timestamp_string(self):
        """Reject future timestamp as string"""
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(future)
        assert exc_info.value.status_code == 400


class TestTimestampValidatorAgeLimit:
    """Test rejection of old timestamps (> 7 days)"""
    
    def test_timestamp_exactly_7_days_old(self):
        """Accept timestamp exactly 7 days old (boundary)"""
        exactly_7_days_ago = datetime.now(timezone.utc) - timedelta(days=7, seconds=1)
        result = TimestampValidator.validate(exactly_7_days_ago)
        assert result is not None
    
    def test_timestamp_8_days_old(self):
        """Reject timestamp 8 days old"""
        too_old = datetime.now(timezone.utc) - timedelta(days=8)
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(too_old)
        assert exc_info.value.status_code == 400
        assert "too old" in exc_info.value.detail.lower()
    
    def test_timestamp_30_days_old(self):
        """Reject timestamp 30 days old"""
        too_old = datetime.now(timezone.utc) - timedelta(days=30)
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(too_old)
        assert exc_info.value.status_code == 400
    
    def test_timestamp_1_day_old(self):
        """Accept timestamp 1 day old"""
        one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
        result = TimestampValidator.validate(one_day_ago)
        assert result is not None


class TestTimestampValidatorTimezones:
    """Test timezone handling"""
    
    def test_datetime_without_timezone(self):
        """Reject datetime object without timezone info"""
        naive_dt = datetime(2026, 6, 25, 10, 0, 0)  # No timezone
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(naive_dt)
        assert exc_info.value.status_code == 400
    
    def test_convert_non_utc_to_utc(self):
        """Convert non-UTC timezone to UTC"""
        # Create a timestamp with a different timezone offset
        from datetime import timezone as tz
        eastern = tz(timedelta(hours=-5))
        ts_eastern = datetime(2026, 6, 25, 10, 0, 0, tzinfo=eastern)
        
        # Should convert to UTC successfully
        result = TimestampValidator.validate(ts_eastern)
        assert result.tzinfo == timezone.utc
        # The UTC hour should be 5 hours ahead
        assert result.hour == 15  # 10 AM -5:00 = 3 PM UTC


class TestTimestampValidatorReturnType:
    """Test return value type and properties"""
    
    def test_returns_datetime_object(self):
        """Validate returns datetime object"""
        result = TimestampValidator.validate("2026-06-25T10:00:00Z")
        assert isinstance(result, datetime)
    
    def test_returns_timezone_aware(self):
        """Returned datetime is timezone aware"""
        result = TimestampValidator.validate("2026-06-25T10:00:00Z")
        assert result.tzinfo is not None
    
    def test_returns_utc_timezone(self):
        """Returned datetime has UTC timezone"""
        result = TimestampValidator.validate("2026-06-25T10:00:00Z")
        assert result.tzinfo == timezone.utc


class TestTimestampValidatorEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_timestamp_with_leading_trailing_whitespace(self):
        """Handle timestamp strings with leading/trailing whitespace"""
        result = TimestampValidator.validate("  2026-06-25T10:00:00Z  ")
        assert result is not None
        assert result.tzinfo == timezone.utc
    
    def test_very_small_unix_timestamp(self):
        """Handle very small Unix timestamp (1970-01-01)"""
        with pytest.raises(HTTPException):
            # 0 = 1970-01-01, definitely older than 7 days
            TimestampValidator.validate(0)
    
    def test_zero_timestamp(self):
        """Zero Unix timestamp is too old"""
        with pytest.raises(HTTPException) as exc_info:
            TimestampValidator.validate(0)
        assert exc_info.value.status_code == 400


class TestTimestampValidatorConsistency:
    """Test consistency across multiple validations"""
    
    def test_same_timestamp_different_formats(self):
        """Same timestamp in different formats should match"""
        iso_format = "2026-06-25T10:00:00Z"
        iso_format_with_ms = "2026-06-25T10:00:00.000000Z"
        
        result1 = TimestampValidator.validate(iso_format)
        result2 = TimestampValidator.validate(iso_format_with_ms)
        
        # Both should be valid and represent the same time
        assert result1 is not None
        assert result2 is not None
        # Allow 1 second difference due to microseconds
        assert abs((result1 - result2).total_seconds()) < 1
