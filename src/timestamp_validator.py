from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
import logging


logger = logging.getLogger(__name__)


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
        try:
            if isinstance(timestamp_input, datetime):
                parsed_ts = timestamp_input
            elif isinstance(timestamp_input, (int, float)):
                # Unix timestamp - assume UTC
                parsed_ts = datetime.fromtimestamp(timestamp_input, tz=timezone.utc)
            elif isinstance(timestamp_input, str):
                parsed_ts = TimestampValidator._parse_string_timestamp(timestamp_input)
            else:
                logger.warning(f"Invalid timestamp type: {type(timestamp_input)}")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid timestamp"
                )
            if parsed_ts.tzinfo is None:
                logger.warning(f"Timestamp missing timezone: {timestamp_input}")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid timestamp"
                )
            if parsed_ts.tzinfo != timezone.utc:
                try:
                    parsed_ts = parsed_ts.astimezone(timezone.utc)
                except Exception as e:
                    logger.error(f"Timezone conversion error: {str(e)}")
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid timestamp"
                    )
            now_utc = datetime.now(timezone.utc)
            grace_period = timedelta(seconds=30)
            if parsed_ts > (now_utc + graceperiod):
                time_diff = (parsed_ts - (now_utc + grace_period)).total_seconds()
                logger.warning(f"Future timestamp rejected: {time_diff}s in future")
                raise HTTPException(
                    status_code=400,
                    detail="Timestamp cannot be in the future"
                )
            age = now_utc - parsed_ts
            max_age = timedelta(days=TimestampValidator.MAX_AGE_DAYS)
            if age > max_age:
                logger.warning(f"Old timestamp rejected: {age.days} days old")
                raise HTTPException(
                    status_code=400,
                    detail="Timestamp is too old"
                )
            
            return parsed_ts

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Timestamp validation error: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=400,
                detail="Invalid timestamp"
            )
    
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
        logger.warning(f"Invalid timestamp format: {timestamp_str}")
        raise HTTPException(
            status_code=400,
            detail="Invalid timestamp"
        )
