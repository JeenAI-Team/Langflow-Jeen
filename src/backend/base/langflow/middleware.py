from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger
import os

from langflow.services.deps import get_settings_service


class MaxFileSizeException(HTTPException):
    def __init__(self, detail: str = "File size is larger than the maximum file size {}MB"):
        super().__init__(status_code=413, detail=detail)


# Adapted from https://github.com/steinnes/content-size-limit-asgi/blob/master/content_size_limit_asgi/middleware.py#L26
class ContentSizeLimitMiddleware:
    """Content size limiting middleware for ASGI applications.

    Args:
      app (ASGI application): ASGI application
      max_content_size (optional): the maximum content size allowed in bytes, None for no limit
      exception_cls (optional): the class of exception to raise (ContentSizeExceeded is the default)
    """

    def __init__(
        self,
        app,
    ):
        self.app = app
        self.logger = logger

    @staticmethod
    def receive_wrapper(receive):
        received = 0

        async def inner():
            max_file_size_upload = get_settings_service().settings.max_file_size_upload
            nonlocal received
            message = await receive()
            if message["type"] != "http.request" or max_file_size_upload is None:
                return message
            body_len = len(message.get("body", b""))
            received += body_len
            if received > max_file_size_upload * 1024 * 1024:
                # max_content_size is in bytes, convert to MB
                received_in_mb = round(received / (1024 * 1024), 3)
                msg = (
                    f"Content size limit exceeded. Maximum allowed is {max_file_size_upload}MB"
                    f" and got {received_in_mb}MB."
                )
                raise MaxFileSizeException(msg)
            return message

        return inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        wrapper = self.receive_wrapper(receive)
        await self.app(scope, wrapper, send)


class OriginValidationMiddleware(BaseHTTPMiddleware):
    """Simple middleware to validate request origins - prevents direct access"""
    
    def __init__(self, app):
        super().__init__(app)
        # Get allowed origins from environment
        allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
        self.allowed_origins = [origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()]
        
        # Paths that bypass validation
        self.bypass_paths = ["/health", "/docs", "/openapi.json"]
        
        if self.allowed_origins:
            logger.info(f"🔒 Origin validation enabled for: {self.allowed_origins}")
        else:
            logger.info("ℹ️ Origin validation disabled (no ALLOWED_ORIGINS set)")
    
    async def dispatch(self, request: Request, call_next):
        # Skip if no origins configured (disabled mode)
        if not self.allowed_origins:
            return await call_next(request)
            
        # Skip validation for bypass paths
        if any(request.url.path.startswith(path) for path in self.bypass_paths):
            return await call_next(request)
        
        # Get origin from headers (works for both direct requests and iframes)
        origin = request.headers.get("origin") or request.headers.get("referer", "")
        
        # Validate origin
        if not self._is_origin_allowed(origin):
            logger.warning(f"🚫 Blocked direct access from: {origin or 'unknown origin'}")
            return JSONResponse(
                status_code=401,
                content={"detail": "Direct access not allowed"}
            )
        
        # Origin is valid, proceed
        return await call_next(request)
    
    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is in allowed list"""
        if not origin:
            return False
        return any(origin.startswith(allowed) for allowed in self.allowed_origins)
