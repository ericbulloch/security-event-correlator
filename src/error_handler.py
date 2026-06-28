import logging
from fastapi import HTTPException
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    filename='app.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


class ErrorHandler:
    @staticmethod
    def handle_validation_error(
        error: Exception,
        user_facing_message: str = "Invalid request format"
    ) -> HTTPException:
        logger.warning(
            f"Validation error: {type(error).__name__}: {str(error)}",
            exc_info=True
        )
        
        raise HTTPException(
            status_code=422,
            detail=user_facing_message
        )
    
    @staticmethod
    def handle_processing_error(
        error: Exception,
        request_id: Optional[str] = None,
        user_facing_message: str = "Failed to process request"
    ) -> HTTPException:
        error_type = type(error).__name__
        logger.error(
            f"Processing error (request_id={request_id}): {error_type}: {str(error)}",
            exc_info=True
        )
        
        raise HTTPException(
            status_code=500,
            detail=user_facing_message,
            headers={"X-Request-ID": request_id or "unknown"}
        )
    
    @staticmethod
    def handle_database_error(
        error: Exception,
        request_id: Optional[str] = None
    ) -> HTTPException:
        logger.error(
            f"Database error (request_id={request_id}): {str(error)}",
            exc_info=True
        )
        
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing your request. Please try again later.",
            headers={"X-Request-ID": request_id or "unknown"}
        )
    
    @staticmethod
    def handle_external_api_error(
        error: Exception,
        service_name: str,
        request_id: Optional[str] = None
    ) -> HTTPException:
        logger.error(
            f"External API error ({service_name}, request_id={request_id}): {str(error)}",
            exc_info=True
        )
        
        raise HTTPException(
            status_code=503,
            detail="An external service is temporarily unavailable. Please try again later.",
            headers={"X-Request-ID": request_id or "unknown"}
        )
    
    @staticmethod
    def log_security_event(
        event_type: str,
        client_name: str,
        details: str = ""
    ):
        logger.warning(
            f"Security event - {event_type} (client={client_name}): {details}"
        )
