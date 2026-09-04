from django.http import JsonResponse


API_VERSION = "1"


def api_response(
    payload: dict,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> JsonResponse:
    body = {"api_version": API_VERSION, **payload}
    body["api_version"] = API_VERSION
    response = JsonResponse(
        body,
        status=status,
        content_type="application/json; charset=utf-8",
    )
    response["Cache-Control"] = "no-store"
    for name, value in (headers or {}).items():
        response[name] = value
    return response


def error_response(
    *,
    status: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JsonResponse:
    return api_response(
        {"error": {"code": code, "message": message}},
        status=status,
        headers=headers,
    )


def invalid_request_response() -> JsonResponse:
    return error_response(
        status=400,
        code="invalid_request",
        message="Invalid request.",
    )
