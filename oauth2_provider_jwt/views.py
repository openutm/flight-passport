import json
import logging

try:
    from urllib.parse import parse_qs, urlparse
except ImportError:
    from urlparse import parse_qs, urlparse

from django.conf import settings
from django.utils.module_loading import import_string
from jwcrypto import jwk
from oauth2_provider import views
from oauth2_provider.http import OAuth2ResponseRedirect
from oauth2_provider.models import get_access_token_model
from oauth2_provider.settings import oauth2_settings

from .utils import encode_jwt, generate_payload

# Create your views here.
logger = logging.getLogger(__name__)


class MissingIdAttribute(Exception):
    pass


class IncorrectAudience(Exception):
    pass


class JWTAuthorizationView(views.AuthorizationView):
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)

        if request.GET.get("response_type", None) == "token" and response.status_code == 302:
            url = urlparse(response.url)
            params = parse_qs(url.fragment)

            if params:
                content = {
                    "access_token": params["access_token"][0],
                    "expires_in": int(params["expires_in"][0]),
                    "scope": params["scope"][0],
                }
                jwt = TokenView()._get_access_token_jwt(request, content)

                response = OAuth2ResponseRedirect(f"{response.url}&access_token_jwt={jwt}", response.allowed_schemes)
        return response


class TokenView(views.TokenView):
    def _get_access_token_jwt(self, request, content):
        issuer = settings.JWT_ISSUER_DOMAIN
        payload_enricher = getattr(settings, "JWT_PAYLOAD_ENRICHER", None)
        request_params = request.POST.keys()

        token = get_access_token_model().objects.get(token=content["access_token"])
        extra_data = self._enrich_payload(request, payload_enricher, content, token, request_params)

        payload = generate_payload(issuer, content["expires_in"], **extra_data)

        headers = self._get_jwt_headers()
        token = encode_jwt(payload, headers=headers)

        return token

    def _enrich_payload(self, request, payload_enricher, content, token, request_params):
        extra_data = {}

        if payload_enricher:
            fn = import_string(payload_enricher)
            extra_data.update(fn(request))

        if "scope" in content:
            extra_data.update({"scope": content["scope"], "typ": "Bearer"})

        if "audience" in request_params:
            self._validate_audience(request, token, extra_data)

        return extra_data

    def _validate_audience(self, request, token, extra_data):
        requested_audience = request.POST["audience"]
        audience_query = token.application.audience.all().only("identifier")
        all_audience = [audience.identifier for audience in audience_query]

        if requested_audience not in all_audience:
            raise IncorrectAudience()

        extra_data["aud"] = requested_audience

    def _get_id_value(self, token, id_attribute):
        if not id_attribute:
            return None

        token_user = token.user
        if token_user:
            id_value = getattr(token_user, id_attribute, None)
            if id_value:
                return id_value

        if not token_user:
            return token.application.client_id + "@clients"

        raise MissingIdAttribute()

    def _get_jwt_headers(self):
        if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            key = jwk.JWK.from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))
            return {"kid": key.thumbprint()}

        return {"kid": "e28163ce-b86d-4145-8df3-c8dad2e0b601"}

    @staticmethod
    def _is_jwt_config_set():
        issuer = getattr(settings, "JWT_ISSUER", "")
        private_key_name = f"JWT_PRIVATE_KEY_{issuer.upper()}"
        private_key = getattr(settings, private_key_name, None)
        id_attribute = getattr(settings, "JWT_ID_ATTRIBUTE", None)
        if issuer and private_key and id_attribute:
            return True
        else:
            return False

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code != 200:
            return response

        try:
            content = json.loads(response.content.decode("utf-8"))
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to decode response content: {e}")
            return response

        if "access_token" not in content:
            return response

        if not TokenView._is_jwt_config_set():
            logger.warning("Missing JWT configuration, skipping token build")
            return response

        try:
            token_raw = self._get_access_token_jwt(request, content)
            content["access_token"] = token_raw if isinstance(token_raw, str) else token_raw.decode("utf-8")
        except MissingIdAttribute:
            return self._build_error_response(
                "invalid_request",
                "App not configured correctly. Please set JWT_ID_ATTRIBUTE.",
                status_code=400,
            )
        except IncorrectAudience:
            return self._build_error_response(
                "invalid_request",
                "Incorrect Audience. Please set the appropriate audience in the request.",
                status_code=400,
            )
        except Exception as e:
            logger.error(f"Unexpected error while generating JWT: {e}")
            return response

        response.content = json.dumps(content)
        return response

    @staticmethod
    def _build_error_response(error, error_description, status_code=400):
        return OAuth2ResponseRedirect(
            json.dumps({"error": error, "error_description": error_description}),
            status_code=status_code,
        )
