from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

class TimestampValidator:
    MAX_AGE_DAYS = 7
    ALLOWED_FORMATS = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
    ]
    
    @staticmethod
    def validate(timestamp_input) -> datetime:
        if isinstance(timestamp_input, datetime):
            parsed_ts = timestamp_input
        elif isinstance(timestamp_input, (int, float)):
            # Unix timestamp - assume UTC
            parsed_ts = datetime.fromtimestamp(timestamp_input, tz=timezone.utc)
        elif isinstance(timestamp_input, str):
            parsed_ts = TimestampValidator._parse_string_timestamp(timestamp_input)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid timestamp type: {type(timestamp_input)}. "
                       f"Expected string, integer (unix), or datetime object"
            )
        if parsed_ts.tzinfo is None:
            raise HTTPException(
                status_code=400,
                detail="Timestamp must include timezone information (UTC). "
                       f"Received: {timestamp_input}"
            )
        if parsed_ts.tzinfo != timezone.utc:
            try:
                parsed_ts = parsed_ts.astimezone(timezone.utc)
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to convert timestamp to UTC: {str(e)}"
                )
        now_utc = datetime.now(timezone.utc)
        if parsed_ts > now_utc:
            time_diff = (parsed_ts - now_utc).total_seconds()
            raise HTTPException(
                status_code=400,
                detail=f"Timestamp cannot be in the future. "
                       f"Event timestamp is {time_diff:.1f} seconds in the future"
            )
        age = now_utc - parsed_ts
        max_age = timedelta(days=TimestampValidator.MAX_AGE_DAYS)
        if age > max_age:
            age_days = age.days
            raise HTTPException(
                status_code=400,
                detail=f"Timestamp too old. Events must be from the last {TimestampValidator.MAX_AGE_DAYS} days. "
                       f"Received event from {age_days} days ago"
            )
        
        return parsed_ts
    
    @staticmethod
    def _parse_string_timestamp(timestamp_str: str) -> datetime:
        timestamp_str = timestamp_str.strip()
        for fmt in TimestampValidator.ALLOWED_FORMATS:
            try:
                parsed = datetime.strptime(timestamp_str, fmt)
                parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue
        raise HTTPException(
            status_code=400,
            detail=f"Invalid timestamp format: {timestamp_str}. "
                   f"Accepted formats: {', '.join(TimestampValidator.ALLOWED_FORMATS)}"
        )
