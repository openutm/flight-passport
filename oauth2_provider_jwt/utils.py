import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from jwcrypto import jwk
from oauth2_provider.settings import oauth2_settings


def generate_payload(issuer, expires_in, **extra_data):
    """
    Generate a JWT payload with standard claims and optional extra data.

    :param issuer: Identifies the principal that issued the token.
    :type issuer: str
    :param expires_in: Number of seconds that the token will be valid.
    :type expires_in: int
    :param extra_data: Additional data to include in the payload.
    :type extra_data: dict
    :return: A dictionary representing the JWT payload.
    :rtype: dict
    """
    now = datetime.now(timezone.utc)
    expiration_time = now + timedelta(seconds=expires_in)
    payload = {
        "iss": issuer,
        "exp": expiration_time,
        "iat": now,
        **extra_data,
    }
    return payload


def encode_jwt(payload, headers=None):
    """
    Encode a JWT with the given payload and optional headers.

    :param payload: The payload to encode in the JWT.
    :type payload: dict
    :param headers: Optional headers to include in the JWT.
    :type headers: dict, None
    :return: The encoded JWT as a string.
    :rtype: str
    """
    algorithm = getattr(settings, "JWT_ENC_ALGORITHM", "RS256")
    issuer_shortname = settings.JWT_ISSUER

    private_key_name = f"JWT_PRIVATE_KEY_{issuer_shortname.upper()}"
    private_key = getattr(settings, private_key_name, None)
    if not private_key:
        raise ImproperlyConfigured(f"Missing setting {private_key_name}")

    return jwt.encode(payload, private_key, algorithm=algorithm, headers=headers)


def decode_jwt(jwt_value):
    """
    Decode a JWT and return its payload.

    :param jwt_value: The JWT to decode.
    :type jwt_value: str
    :return: The decoded payload.
    :rtype: dict
    :raises jwt.InvalidTokenError: If the JWT is invalid.
    :raises ImproperlyConfigured: If required settings are missing.
    """
    try:
        # Split the JWT into its components
        headers_enc, payload_enc, verify_signature = jwt_value.split(".")
    except ValueError:
        raise jwt.InvalidTokenError("Invalid JWT structure")

    # Add padding to the payload if necessary and decode it
    payload_enc = payload_enc + "=" * (-len(payload_enc) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_enc).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as e:
        raise jwt.InvalidTokenError("Invalid JWT payload") from e

    # Retrieve algorithms and RSA private key from settings
    algorithms = getattr(settings, "JWT_JWS_ALGORITHMS", ["HS256", "RS256"])
    private_key_pem = getattr(oauth2_settings, "OIDC_RSA_PRIVATE_KEY", None)
    if not private_key_pem:
        raise ImproperlyConfigured("Missing OIDC_RSA_PRIVATE_KEY in settings")

    # Generate the public key from the private key
    try:
        private_key = jwk.JWK.from_pem(private_key_pem.encode("utf-8"))
        public_key = private_key.export_to_pem(private_key=False)
    except Exception as e:
        raise ImproperlyConfigured("Failed to generate public key from private key") from e

    # Decode the JWT using the public key and algorithms
    try:
        decoded = jwt.decode(jwt_value, public_key, algorithms=algorithms)
    except jwt.PyJWTError as e:
        raise jwt.InvalidTokenError("Failed to decode JWT") from e

    return decoded

def decode_jwt_user_info(jwt_value):
    """
    Decode a JWT and return its payload.

    :param jwt_value: The JWT to decode.
    :type jwt_value: str
    :return: The decoded payload.
    :rtype: dict
    :raises jwt.InvalidTokenError: If the JWT is invalid.
    :raises ImproperlyConfigured: If required settings are missing.
    """
    try:
        # Split the JWT into its components
        headers_enc, payload_enc, verify_signature = jwt_value.split(".")
    except ValueError:
        raise jwt.InvalidTokenError("Invalid JWT structure")

    # Retrieve algorithms and RSA private key from settings
    algorithms = getattr(settings, "JWT_JWS_ALGORITHMS", ["HS256", "RS256"])
    private_key_pem = getattr(oauth2_settings, "OIDC_RSA_PRIVATE_KEY", None)
    if not private_key_pem:
        raise ImproperlyConfigured("Missing OIDC_RSA_PRIVATE_KEY in settings")

    # Generate the public key from the private key
    try:
        private_key = jwk.JWK.from_pem(private_key_pem.encode("utf-8"))
        public_key_pem = private_key.export_to_pem(private_key=False)
    except Exception as e:
        raise ImproperlyConfigured("Failed to generate public key from private key") from e

    # Decode the JWT using the public key and algorithms
    try:
        decoded = jwt.decode(jwt_value, public_key_pem, algorithms=algorithms)
    except jwt.PyJWTError as e:
        raise jwt.InvalidTokenError("Failed to decode JWT") from e

    return decoded
