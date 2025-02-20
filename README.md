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

- Secure token generation using cryptographic signatures
- Built-in token expiration management
- Payload validation and type checking
- Customizable expiration times
- Comprehensive error handling
- Environment variable configuration
- Extensive logging

## Requirements

- Python 3.7+
- python-decouple
- itsdangerous

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
token = generator.generate()
```

### Token Validation and Decoding

```python
from limited_time_token_handler import LimitedTimeTokenDecoder

# Create a decoder instance (default expiry: 60 minutes)
decoder = LimitedTimeTokenDecoder(token)

# Validate token
is_valid = decoder.is_valid()

# Decode token to get payload
payload = decoder.decode()
```

## API Reference

### LimitedTimeTokenGenerator

#### `__init__(payload: Dict[str, Any])`
Initializes the token generator with a payload dictionary.

#### `generate(default: Any = None, raise_exception: bool = False) -> str | None`
Generates a secure token containing the payload.

### LimitedTimeTokenDecoder

#### `__init__(token: str, max_age_secs: int = 60)`
Initializes the token decoder with a token string and optional expiry time.

#### `is_valid(raise_exception: bool = False) -> bool`
Validates if the token is valid and not expired.

#### `decode(raise_exception: bool = False) -> Dict[str, Any]`
Decodes the token and returns the original payload.

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
    decoder = LimitedTimeTokenDecoder(token, max_age_secs=30)
    if decoder.is_valid():
        payload = decoder.decode()
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
