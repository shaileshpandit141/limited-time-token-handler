# Limited Time Token Handler

A Python package designed to handle secure, time-limited token generation and validation.
It provides functionality for creating and decoding tokens with built-in expiration functionality.

## Table of Contents
- [Installation](#installation)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Installation

```bash
pip install limited-time-token-handler
```

## Features

- Secure token generation using cryptographic signatures and salting
- Built-in token expiration management
- Payload validation and type checking
- Customizable expiration times
- Comprehensive error handling with logging
- Environment variable configuration
- Extensive debug and error logging

## Requirements

- Python 3.7+
- python-decouple
- itsdangerous
- logging

## Usage

### Basic Token Generation

```python
from limited_time_token_handler import LimitedTimeTokenGenerator

# Create a payload
payload = {
    "user_id": 123,
    "user_name": "username"
}

# Generate a token
generator = LimitedTimeTokenGenerator(payload)
token = generator.generate()  # Returns str or None if failed
```

### Token Validation and Decoding

```python
from limited_time_token_handler import LimitedTimeTokenDecoder

# Create a decoder instance (default expiry: 60 seconds)
decoder = LimitedTimeTokenDecoder(token, max_age_seconds=60)

# Validate token
is_valid = decoder.is_valid()  # Returns bool

# Decode token to get payload
payload = decoder.decode()  # Returns Dict[str, Any] or None if invalid
```

## API Reference

### LimitedTimeTokenGenerator

#### `__init__(payload: Dict[str, Any])`
Initializes the token generator with a payload dictionary. Validates that a SECRET_KEY is configured and payload is a valid dictionary. Raises TokenError if validation fails.

#### `generate(raise_exception: bool = False, default: Any = None) -> str | None`
Generates a secure token containing the payload with a unique salt. Returns:
- str: Valid token if successful
- None: If token generation fails and raise_exception=False
- Raises TokenError: If token generation fails and raise_exception=True
- default: Custom value if specified and generation fails

### LimitedTimeTokenDecoder

#### `__init__(token: str, max_age_seconds: int = 60)`
Initializes the token decoder with a token string and optional expiry time in seconds. Validates SECRET_KEY configuration. Raises TokenError if SECRET_KEY is not set.

#### `is_valid(raise_exception: bool = False) -> bool`
Validates if the token is valid and not expired. Returns:
- True: Token is valid and not expired
- False: If token is invalid/expired and raise_exception=False
- Raises TokenError: If token validation fails and raise_exception=True

#### `decode(raise_exception: bool = False, default: Dict[str, Any] = {}) -> Dict[str, Any]`
Decodes the token and returns the original payload. Returns:
- Dict[str, Any]: Original payload if token is valid
- None: If token is invalid and raise_exception=False
- default: Custom value if specified and token is invalid
- Raises TokenError: If token is invalid and raise_exception=True

## Examples

### Advanced Usage with Error Handling

```python
try:
    # Generate token
    generator = LimitedTimeTokenGenerator({
        "user_id": 123,
        "user_name": "username"
    })
    token = generator.generate(raise_exception=True)

    # Decode token
    decoder = LimitedTimeTokenDecoder(token, max_age_seconds=30)
    if decoder.is_valid():
        payload = decoder.decode(default={})
        print(f"Decoded payload: {payload}")
    else:
        print("Token is invalid or expired")
except TokenError as error:
    print(f"Token error occurred: {str(error)}")
```

## Configuration

The package requires a `SECRET_KEY` environment variable. Set it in your `.env` file:

```
SECRET_KEY=your-secure-secret-key
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
