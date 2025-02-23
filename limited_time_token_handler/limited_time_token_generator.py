import logging
from typing import Any, Dict, Self
from uuid import uuid4

from decouple import config
from itsdangerous import URLSafeTimedSerializer

from .token_error import TokenError

logger = logging.getLogger(__name__)


class LimitedTimeTokenGenerator:
    SECRET_KEY = config("SECRET_KEY", default=None)

    def __init__(
        self: Self,
        payload: Dict[str, Any],
        max_age_seconds: int = 60 * 20,
    ) -> None:
        # Validate the secret key
        self._validate_secret_key()
        self.payload = payload

        # Validate the payload
        self._validate_payload()

        # Validate the max_age_seconds
        self.max_age_seconds = max_age_seconds
        self._validate_max_age_seconds()

        # Update the payload with max_age_seconds
        self.payload.update({"max_age_seconds": self.max_age_seconds})

    def _validate_secret_key(self) -> None:
        if not self.SECRET_KEY:
            logger.error(
                "SECRET_KEY missing or not properly configured in environment variables"
            )
            raise TokenError(
                "SECRET_KEY is missing or not properly configured in environment variables."
            )

    def _validate_payload(self) -> None:
        if not isinstance(self.payload, dict):
            logger.error(
                f"Invalid payload type provided: {
                    type(self.payload)
                }. Expected dictionary"
            )
            raise TokenError("Invalid payload type. Expected dictionary.")

    def _validate_max_age_seconds(self) -> None:
        if not isinstance(self.max_age_seconds, int):
            logger.error(
                f"Invalid max_age_seconds type provided: {type(self.max_age_seconds)}. Expected Integer Number."
            )
            raise TokenError("Invalid max_age_seconds type. Expected Integer Number.")

    def _create_token(self, salt_token: str) -> str:
        serializer = URLSafeTimedSerializer(str(self.SECRET_KEY), salt=salt_token)
        token = serializer.dumps(self.payload)
        return f"{token}|{salt_token}"

    def generate(
        self: Self, raise_exception: bool = False, default: Any = None
    ) -> str | None:
        try:
            salt_token = uuid4().hex
            return self._create_token(salt_token)
        except Exception as error:
            logger.error(f"Failed to generate token due to error: {str(error)}")
            if raise_exception:
                raise TokenError(f"Token generation failed: {str(error)}")
            return default
