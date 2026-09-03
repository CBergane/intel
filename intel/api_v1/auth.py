import secrets

from django.conf import settings
from django.http import HttpRequest, JsonResponse

from .responses import error_response


def authenticate_bearer(request: HttpRequest) -> JsonResponse | None:
    configured_token = settings.INTEGRATION_API_TOKEN
    if not configured_token:
        return error_response(
            status=503,
            code="service_unavailable",
            message="API service unavailable.",
        )

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")
    malformed = (
        not separator
        or scheme.casefold() != "bearer"
        or not supplied_token
        or any(character.isspace() for character in supplied_token)
    )
    if malformed or not secrets.compare_digest(
        supplied_token.encode("utf-8"),
        configured_token.encode("utf-8"),
    ):
        return error_response(
            status=401,
            code="unauthorized",
            message="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return None
