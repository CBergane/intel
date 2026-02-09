from datetime import timedelta

from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import render
from django.utils import timezone

from .models import Feed, FetchRun, Item, Source

TIME_RANGES = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}
TIME_OPTIONS = [
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
    ("90d", "Last 90 days"),
]
NOW_MAX_PER_SOURCE = 10


def _filtered_items(request, section=None, *, balance_per_source=False):
    queryset = Item.objects.select_related("source", "feed").all()
    if section is not None:
        queryset = queryset.filter(feed__section=section)

    query = (request.GET.get("q") or "").strip()
    source_slug = (request.GET.get("source") or "").strip()
    selected_time = (request.GET.get("time") or "7d").strip()
    if selected_time not in TIME_RANGES:
        selected_time = "7d"

    if query:
        queryset = queryset.filter(Q(title__icontains=query) | Q(summary__icontains=query))

    if source_slug:
        queryset = queryset.filter(source__slug=source_slug)

    since = timezone.now() - TIME_RANGES[selected_time]
    queryset = queryset.filter(published_at__gte=since)
    ordered = queryset.order_by("-published_at", "-id")

    if balance_per_source and not source_slug:
        source_counts = {}
        balanced_items = []
        for item in ordered:
            count = source_counts.get(item.source_id, 0)
            if count >= NOW_MAX_PER_SOURCE:
                continue
            balanced_items.append(item)
            source_counts[item.source_id] = count + 1
        paginator = Paginator(balanced_items, 25)
    else:
        paginator = Paginator(ordered, 25)
    page_obj = paginator.get_page(request.GET.get("page"))

    return {
        "page_obj": page_obj,
        "query": query,
        "selected_source": source_slug,
        "selected_time": selected_time,
        "sources": Source.objects.filter(enabled=True).order_by("name"),
        "time_options": TIME_OPTIONS,
    }


def _render_items_page(request, *, title, nav_key, section=None):
    context = _filtered_items(request, section=section)
    context.update(
        {
            "page_title": title,
            "current_page": nav_key,
        }
    )
    return render(request, "intel/item_list.html", context)


def now_view(request):
    context = _filtered_items(request, section=None, balance_per_source=True)
    context.update({"page_title": "Now", "current_page": "now"})
    return render(request, "intel/item_list.html", context)


def active_view(request):
    return _render_items_page(
        request,
        title="Active Exploitation",
        nav_key="active",
        section=Feed.Section.ACTIVE,
    )


def advisories_view(request):
    return _render_items_page(
        request,
        title="Vendor Advisories",
        nav_key="advisories",
        section=Feed.Section.ADVISORIES,
    )


def research_view(request):
    return _render_items_page(
        request,
        title="Research & Writeups",
        nav_key="research",
        section=Feed.Section.RESEARCH,
    )


def sweden_view(request):
    return _render_items_page(
        request,
        title="Sweden / Nordics",
        nav_key="sweden",
        section=Feed.Section.SWEDEN,
    )


def feed_health_view(request):
    feeds = (
        Feed.objects.select_related("source")
        .prefetch_related("fetch_runs")
        .order_by("source__name", "name")
    )

    latest_by_feed = {}
    for run in FetchRun.objects.order_by("-started_at"):
        if run.feed_id not in latest_by_feed:
            latest_by_feed[run.feed_id] = run

    return render(
        request,
        "intel/feed_health.html",
        {
            "feeds": feeds,
            "latest_by_feed": latest_by_feed,
            "current_page": "feed-health",
            "page_title": "Feed Health",
        },
    )


def sources_view(request):
    sources = (
        Source.objects.annotate(feed_count=Count("feeds"), item_count=Count("items"))
        .order_by("name")
        .all()
    )
    return render(
        request,
        "intel/sources.html",
        {
            "sources": sources,
            "current_page": "sources",
            "page_title": "Sources",
        },
    )


def about_view(request):
    return render(
        request,
        "intel/about.html",
        {
            "current_page": "about",
            "page_title": "About",
        },
    )
