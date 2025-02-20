import logging
from typing import Any, Dict, Self

from decouple import config
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .token_error import TokenError

logger = logging.getLogger(__name__)


class LimitedTimeTokenDecoder:
    SECRET_KEY = config("SECRET_KEY", default=None)

    def __init__(self: Self, token: str, token_expiry_minutes: int = 60) -> None:
        self.token = token
        self.token_expiry_seconds = token_expiry_minutes * 60

        if not self.SECRET_KEY:
            raise TokenError("SECRET_KEY is not set in environment variables.")

    def __validate(
        self: Self, token: str | None
    ) -> tuple[str, str] | tuple[None, None]:
        if not token:
            return None, None

        try:
            token_part, salt_token = token.rsplit("|", 1)
            return token_part, salt_token
        except ValueError:
            return None, None

    def _create_serializer(self: Self, salt_token: str) -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(self.SECRET_KEY, salt=salt_token)

    def _handle_token_error(
        self: Self, error_type: str, raise_exception: bool
    ) -> bool | Dict[str, Any]:
        error_messages = {
            "expired": "Token has expired. Please request a new token to continue.",
            "invalid": "Invalid Token provided. Please request a new token.",
            "format": "Invalid token format. Token must be properly formatted.",
        }
        if raise_exception:
            raise TokenError(error_messages[error_type])
        return False if error_type != "format" else {}

    def _process_token(
        self: Self, raise_exception: bool = False, decode: bool = False
    ) -> bool | Dict[str, Any]:
        token, salt_token = self.__validate(self.token)

        if not token or not salt_token:
            return (
                False
                if not decode
                else self._handle_token_error("format", raise_exception)
            )

        serializer = self._create_serializer(salt_token)
        try:
            result = serializer.loads(token, max_age=self.token_expiry_seconds)
            logger.debug(
                "Token validation successful"
                if not decode
                else "Token successfully decoded and payload extracted"
            )
            return True if not decode else result
        except SignatureExpired:
            logger.warning(
                "Token has expired - validation failed"
                if not decode
                else "Token decoding failed - token has expired"
            )
            return self._handle_token_error("expired", raise_exception)
        except BadSignature:
            logger.error(
                "Invalid token signature detected during validation"
                if not decode
                else "Token decoding failed - invalid signature detected"
            )
            return self._handle_token_error("invalid", raise_exception)

    def is_valid(self: Self, raise_exception: bool = False) -> bool:
        return self._process_token(raise_exception)

    def decode(self: Self, raise_exception: bool = False) -> Dict[str, Any]:
        return self._process_token(raise_exception, decode=True)
