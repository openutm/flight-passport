import base64
import json
from datetime import datetime, timedelta

import jwt
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from jwcrypto import jwk
from oauth2_provider.settings import oauth2_settings


def generate_payload(issuer, expires_in, **extra_data):
    """
    :param issuer: identifies the principal that issued the token.
    :type issuer: str
    :param expires_in: number of seconds that the token will be valid.
    :type expires_in: int
    :param extra_data: extra data to be added to the payload.
    :type extra_data: dict
    :rtype: dict
    """
    now = datetime.utcnow()
    issued_at = now
    expiration = now + timedelta(seconds=expires_in)
    payload = {
        "iss": issuer,
        "exp": expiration,
        "iat": issued_at,
    }

    if extra_data:
        payload.update(**extra_data)

    return payload


def encode_jwt(payload, headers=None):
    """
    :type payload: dict
    :type headers: dict, None
    :rtype: str
    """
    # RS256 in default, because hardcoded legacy
    algorithm = getattr(settings, "JWT_ENC_ALGORITHM", "RS256")
    issuer_shortname = settings.JWT_ISSUER

    private_key_name = f"JWT_PRIVATE_KEY_{issuer_shortname.upper()}"
    private_key = getattr(settings, private_key_name, None)
    if not private_key:
        raise ImproperlyConfigured(f"Missing setting {private_key_name}")
    encoded = jwt.encode(payload, private_key, algorithm=algorithm, headers=headers)

    # return encoded.decode("utf-8")
    return encoded


def decode_jwt(jwt_value):
    """
    :type jwt_value: str
    """
    try:
        headers_enc, payload_enc, verify_signature = jwt_value.split(".")
    except ValueError:
        raise jwt.InvalidTokenError()

    payload_enc += "=" * (-len(payload_enc) % 4)  # add padding
    payload = json.loads(base64.b64decode(payload_enc).decode("utf-8"))

    algorithms = getattr(settings, "JWT_JWS_ALGORITHMS", ["HS256", "RS256"])
    if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
        key = jwk.JWK.from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))
        public_key = key.export_public()
    else:
        raise ImproperlyConfigured("Missing following parameter in settings file: {}".format("OIDC_RSA_PRIVATE_KEY"))

    decoded = jwt.decode(jwt_value, public_key, algorithms=algorithms)
    return decoded


def decode_jwt_user_info(jwt_value):
    """
    :type jwt_value: str
    """
    try:
        headers_enc, payload_enc, verify_signature = jwt_value.split(".")
    except ValueError:
        raise jwt.InvalidTokenError()

    # payload_enc += '=' * (-len(payload_enc) % 4)  # add padding
    # payload = json.loads(base64.b64decode(payload_enc).decode("utf-8"))

    algorithms = getattr(settings, "JWT_JWS_ALGORITHMS", ["HS256", "RS256"])

    if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
        private_key = jwk.JWK.from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))
        public_key_pem = private_key.export_to_pem(private_key=False)

    decoded = jwt.decode(jwt_value, public_key_pem, algorithms=algorithms)
    return decoded
