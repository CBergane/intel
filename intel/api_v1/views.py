from django.db.models import Q
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.common import no_append_slash
from django.views.decorators.csrf import csrf_exempt

from intel.models import Item

from .auth import authenticate_bearer
from .contracts import build_publishable_signal, format_utc_datetime
from .cursors import (
    CursorError,
    decode_snapshot_cursor,
    encode_snapshot_cursor,
)
from .responses import api_response, error_response, invalid_request_response


SIGNALS_DEFAULT_LIMIT = 50
SIGNALS_MAX_LIMIT = 100
SIGNALS_QUERY_PARAMETERS = frozenset({"cursor", "limit"})


def _signals_limit(request: HttpRequest) -> int:
    raw_limit = request.GET.get("limit")
    if raw_limit is None:
        return SIGNALS_DEFAULT_LIMIT
    if not raw_limit or not raw_limit.isascii() or not raw_limit.isdigit():
        raise ValueError("Invalid limit.")
    limit = int(raw_limit)
    if limit < 1:
        raise ValueError("Invalid limit.")
    return min(limit, SIGNALS_MAX_LIMIT)


def _signals_parameters_are_valid(request: HttpRequest) -> bool:
    if set(request.GET) - SIGNALS_QUERY_PARAMETERS:
        return False
    return all(
        len(request.GET.getlist(name)) == 1
        for name in SIGNALS_QUERY_PARAMETERS
        if name in request.GET
    )


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
def signals(request: HttpRequest) -> JsonResponse:
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

    if not _signals_parameters_are_valid(request):
        return invalid_request_response()
    try:
        limit = _signals_limit(request)
        cursor = (
            decode_snapshot_cursor(request.GET["cursor"])
            if "cursor" in request.GET
            else None
        )
    except (CursorError, ValueError):
        return invalid_request_response()

    classified_at = timezone.now()
    queryset = Item.objects.select_related("source", "feed")
    if cursor is not None:
        queryset = queryset.filter(
            Q(published_at__lt=cursor.published_at)
            | Q(
                published_at=cursor.published_at,
                id__lt=cursor.item_id,
            )
        )
    rows = list(queryset.order_by("-published_at", "-id")[: limit + 1])
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    next_cursor = None
    if has_more and page_rows:
        last_item = page_rows[-1]
        next_cursor = encode_snapshot_cursor(
            published_at=last_item.published_at,
            item_id=last_item.id,
        )

    return api_response(
        {
            "classified_at": format_utc_datetime(classified_at),
            "results": [
                build_publishable_signal(item, classified_at=classified_at)
                for item in page_rows
            ],
            "next_cursor": next_cursor,
            "has_more": has_more,
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
