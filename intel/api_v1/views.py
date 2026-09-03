from django.http import HttpRequest, JsonResponse
from django.views.decorators.common import no_append_slash
from django.views.decorators.csrf import csrf_exempt

from .auth import authenticate_bearer
from .responses import api_response, error_response


@csrf_exempt
@no_append_slash
def health(request: HttpRequest) -> JsonResponse:
    auth_failure = authenticate_bearer(request)
    if auth_failure is not None:
        return auth_failure

    if request.method != "GET":
        return error_response(
            status=405,
            code="method_not_allowed",
            message="Method not allowed.",
            headers={"Allow": "GET"},
        )

    return api_response(
        {
            "status": "ok",
            "service": "borealsec-intel",
        }
    )


@csrf_exempt
@no_append_slash
def not_found(request: HttpRequest, path: str = "") -> JsonResponse:
    del request, path
    return error_response(
        status=404,
        code="not_found",
        message="API resource not found.",
    )
