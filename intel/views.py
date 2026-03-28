import json
import re
from collections import Counter
from datetime import timedelta
from urllib.parse import urlencode

import feedparser
from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.forms import AuthenticationForm
from django.core.paginator import Paginator
from django.db.models import Count, Max, Q
from django.db.models.functions import Coalesce
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import NoReverseMatch, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.text import slugify
from django.utils import timezone
from django.views.decorators.http import require_POST

from .dark_utils import (
    dark_source_suitability_warning,
    extract_links,
    normalize_dark_country,
    resolve_group_name,
    summarize_profile_content,
)
from .forms import (
    DarkSourceCreateForm,
    DarkSourceEditForm,
    FeedCreateForm,
    FeedEditForm,
    SourceCreateForm,
    SourceEditForm,
)
from .models import (
    DarkFetchRun,
    DarkHit,
    DarkSource,
    Feed,
    FetchRun,
    Item,
    OpsJob,
    Source,
)
from .ops_jobs import OPS_ACTIONS, launch_ops_job_subprocess, queue_ops_job

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
CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
HIGH_SIGNAL_KEYWORDS = (
    "actively exploited",
    "zero-day",
    "0day",
    "kev",
    "rce",
    "critical",
    "remote code",
    "authentication bypass",
)

DARK_SOURCE_PRESETS = (
    {
        "key": "cisa-alerts-index",
        "label": "CISA Alerts Index (safe test)",
        "description": "Index page crawl on an official public site (same-host links only).",
        "initial": {
            "name": "CISA Alerts Index",
            "slug": "cisa-alerts-index",
            "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
            "source_type": DarkSource.SourceType.INDEX_PAGE,
            "extractor_profile": DarkSource.ExtractorProfile.GENERIC_PAGE,
            "watch_keywords": "actively exploited, zero-day, cve",
            "watch_regex": r"CVE-\d{4}-\d+",
            "use_tor": False,
            "enabled": True,
        },
    },
    {
        "key": "krebs-feed",
        "label": "Krebs Feed (safe test)",
        "description": "RSS/Atom feed mode for passive allowlisted link ingestion.",
        "initial": {
            "name": "Krebs Feed",
            "slug": "krebs-feed",
            "url": "https://krebsonsecurity.com/feed/",
            "source_type": DarkSource.SourceType.FEED,
            "extractor_profile": DarkSource.ExtractorProfile.GENERIC_PAGE,
            "watch_keywords": "ransomware, exploit, breach",
            "watch_regex": r"CVE-\d{4}-\d+",
            "use_tor": False,
            "enabled": True,
        },
    },
    {
        "key": "single-page-watch",
        "label": "Single Page Watch (safe test)",
        "description": "Single-page mode for one URL only.",
        "initial": {
            "name": "Example Single Page",
            "slug": "example-single-page",
            "url": "https://www.cisa.gov/news-events/alerts",
            "source_type": DarkSource.SourceType.SINGLE_PAGE,
            "extractor_profile": DarkSource.ExtractorProfile.GENERIC_PAGE,
            "watch_keywords": "alert, vulnerability",
            "watch_regex": r"CVE-\d{4}-\d+",
            "use_tor": False,
            "enabled": True,
        },
    },
)

DARK_SOURCE_FORM_SECTIONS = (
    {
        "title": "Basic",
        "description": "Core identity, fetch target, and how discovered pages should be extracted.",
        "fields": ("name", "slug", "url", "source_type", "extractor_profile"),
    },
    {
        "title": "Fetch Config",
        "description": "Operational controls for enablement, network path, limits, and retries.",
        "fields": ("enabled", "use_tor", "timeout_seconds", "max_bytes", "fetch_retries"),
    },
    {
        "title": "Matching / Watches",
        "description": "Passive matching rules applied to discovered content.",
        "fields": ("watch_keywords", "watch_regex"),
    },
    {
        "title": "Notes / Tags / Suitability",
        "description": "Operator context, grouping tags, and collection guidance.",
        "fields": ("homepage", "tags"),
    },
)


def _is_superuser(user):
    return user.is_active and user.is_superuser


def superuser_required(view_func):
    return user_passes_test(_is_superuser, login_url="intel_admin:login")(view_func)


def _validated_next_url(request) -> str:
    raw = (request.POST.get("next") or request.GET.get("next") or "").strip()
    default_target = reverse("intel_admin:ops")
    if not raw:
        return default_target

    # Only allow safe relative paths.
    if not raw.startswith("/"):
        return default_target
    if raw.startswith("//") or raw.startswith("/\\") or "\\" in raw:
        return default_target

    if url_has_allowed_host_and_scheme(
        raw,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return raw

    return default_target


def extract_cve_ids(text: str) -> list[str]:
    seen = set()
    cves = []
    for match in CVE_RE.findall(text or ""):
        cve = match.upper()
        if cve in seen:
            continue
        seen.add(cve)
        cves.append(cve)
    return cves


def _validated_redirect_target(request, default_target: str) -> str:
    raw = (request.POST.get("next") or request.GET.get("next") or "").strip()
    if not raw:
        return default_target
    if url_has_allowed_host_and_scheme(
        raw,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ) and raw.startswith("/"):
        return raw
    return default_target


def _item_text(item) -> str:
    return f"{item.title or ''}\n{item.summary or ''}"


def _item_cves(item) -> list[str]:
    return extract_cve_ids(_item_text(item))


def score_dashboard_item(item, *, cves=None) -> int:
    if cves is None:
        cves = _item_cves(item)

    score = 0
    if cves:
        score += 20

    lowered_text = _item_text(item).lower()
    if any(keyword in lowered_text for keyword in HIGH_SIGNAL_KEYWORDS):
        score += 10

    if item.feed.section in {Feed.Section.ADVISORIES, Feed.Section.SWEDEN}:
        score += 5

    return score


def _attach_item_meta(items):
    for item in items:
        item.cves = _item_cves(item)
        item.activity_at = getattr(item, "activity_at", None) or item.published_at or item.created_at
    return items


def _balanced_items(queryset, *, limit: int, per_source_max: int):
    source_counts = {}
    balanced = []
    for item in queryset:
        count = source_counts.get(item.source_id, 0)
        if count >= per_source_max:
            continue
        balanced.append(item)
        source_counts[item.source_id] = count + 1
        if len(balanced) >= limit:
            break
    return _attach_item_meta(balanced)


def build_trending_cves(items, *, limit: int = 10):
    counts = Counter()
    for item in items:
        for cve in _item_cves(item):
            counts[cve] += 1
    return counts.most_common(limit)


def _filtered_items(request, section=None, *, balance_per_source=False):
    queryset = Item.objects.select_related("source", "feed").annotate(
        activity_at=Coalesce("published_at", "created_at")
    )
    if section is not None:
        queryset = queryset.filter(feed__section=section)

    query = (request.GET.get("q") or "").strip()
    source_slug = (request.GET.get("source") or "").strip()
    selected_time = (request.GET.get("time") or "7d").strip()
    if selected_time not in TIME_RANGES:
        selected_time = "7d"

    since = timezone.now() - TIME_RANGES[selected_time]
    window_queryset = queryset.filter(activity_at__gte=since)
    window_total = window_queryset.count()

    if query:
        window_queryset = window_queryset.filter(
            Q(title__icontains=query)
            | Q(summary__icontains=query)
            | Q(source__name__icontains=query)
        )

    if source_slug:
        window_queryset = window_queryset.filter(source__slug=source_slug)
    filtered_total = window_queryset.count()
    hidden_by_filters = max(0, window_total - filtered_total)

    ordered = window_queryset.order_by("-activity_at", "-id")

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
    page_obj.object_list = _attach_item_meta(list(page_obj.object_list))

    return {
        "page_obj": page_obj,
        "query": query,
        "selected_source": source_slug,
        "selected_time": selected_time,
        "window_total": window_total,
        "filtered_total": filtered_total,
        "hidden_by_filters": hidden_by_filters,
        "balance_applied": balance_per_source and not source_slug,
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
    if request.headers.get("HX-Request"):
        count = context["filtered_total"]
        response = render(request, "intel/partials/items_list.html", context)
        response["HX-Trigger"] = json.dumps({"showToast": f"{count} results"})
        return response
    return render(request, "intel/item_list.html", context)


def now_view(request):
    now = timezone.now()
    # Item.created_at is our ingestion-time fallback when feeds lack publish timestamps.
    item_base = Item.objects.select_related("source", "feed").annotate(
        activity_at=Coalesce("published_at", "created_at")
    )
    ordered_by_activity = item_base.order_by("-activity_at", "-id")

    high_candidates = list(
        ordered_by_activity.filter(activity_at__gte=now - timedelta(days=7))[:400]
    )
    for item in high_candidates:
        item.cves = _item_cves(item)
        item.activity_at = item.activity_at or item.published_at or item.created_at
        item.dashboard_score = score_dashboard_item(item, cves=item.cves)
    high_candidates.sort(
        key=lambda item: (item.dashboard_score, item.activity_at, item.id),
        reverse=True,
    )
    high_signal_items = high_candidates[:15]

    advisories_items = _balanced_items(
        ordered_by_activity.filter(feed__section=Feed.Section.ADVISORIES),
        limit=20,
        per_source_max=8,
    )
    research_items = _balanced_items(
        ordered_by_activity.filter(
            feed__section=Feed.Section.RESEARCH,
            activity_at__gte=now - timedelta(days=30),
        ),
        limit=15,
        per_source_max=6,
    )

    sweden_source_ids = []
    for source in Source.objects.only("id", "tags"):
        tags = {str(tag).strip().lower() for tag in (source.tags or [])}
        if "sweden" in tags:
            sweden_source_ids.append(source.id)
    sweden_items = _attach_item_meta(
        list(
            item_base.filter(
                Q(feed__section=Feed.Section.SWEDEN) | Q(source_id__in=sweden_source_ids)
            ).order_by("-activity_at", "-id")[:10]
        )
    )

    trending_sources = list(
        Item.objects.annotate(activity_at=Coalesce("published_at", "created_at"))
        .filter(activity_at__gte=now - timedelta(hours=48))
        .values("source__name", "source__slug")
        .annotate(item_count=Count("id"))
        .order_by("-item_count", "source__name")[:8]
    )
    trending_cves = build_trending_cves(
        list(ordered_by_activity.filter(activity_at__gte=now - timedelta(days=7))[:400]),
        limit=10,
    )

    enabled_feeds = list(Feed.objects.filter(enabled=True).only("id"))
    latest_by_feed = {}
    for run in FetchRun.objects.filter(feed__enabled=True).order_by("-started_at"):
        if run.feed_id not in latest_by_feed:
            latest_by_feed[run.feed_id] = run
    feed_status_counts = {"ok": 0, "error": 0, "never": 0}
    for feed in enabled_feeds:
        latest = latest_by_feed.get(feed.id)
        if latest is None:
            feed_status_counts["never"] += 1
        elif latest.ok:
            feed_status_counts["ok"] += 1
        else:
            feed_status_counts["error"] += 1

    last_ingest_finished_at = (
        FetchRun.objects.filter(finished_at__isnull=False)
        .order_by("-finished_at")
        .values_list("finished_at", flat=True)
        .first()
    )

    # Dashboard stat widgets
    today = now.date()
    week_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)
    items_today_count = Item.objects.filter(published_at__date=today).count()
    items_week_count = Item.objects.filter(published_at__gte=week_ago).count()
    active_feeds_count = Feed.objects.filter(enabled=True).count()
    dark_hits_30d_count = DarkHit.objects.filter(detected_at__gte=thirty_days_ago).count()

    context = {
        "page_title": "Now",
        "current_page": "now",
        "items_today_count": items_today_count,
        "items_week_count": items_week_count,
        "active_feeds_count": active_feeds_count,
        "dark_hits_30d_count": dark_hits_30d_count,
        "high_signal_items": high_signal_items,
        "advisories_items": advisories_items,
        "research_items": research_items,
        "sweden_items": sweden_items,
        "trending_sources": trending_sources,
        "trending_cves": trending_cves,
        "feed_status_counts": feed_status_counts,
        "enabled_feed_count": len(enabled_feeds),
        "last_ingest_finished_at": last_ingest_finished_at,
    }
    return render(request, "intel/dashboard.html", context)


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
    now = timezone.now()
    since_24h = now - timedelta(hours=24)
    since_7d = now - timedelta(days=7)

    sources = list(Source.objects.order_by("name"))

    item_stats_by_source = {}
    for row in (
        Item.objects.annotate(activity_at=Coalesce("published_at", "created_at"))
        .values("source_id")
        .annotate(
            item_count=Count("id"),
            new_24h=Count("id", filter=Q(activity_at__gte=since_24h)),
            new_7d=Count("id", filter=Q(activity_at__gte=since_7d)),
            last_item_at=Max("activity_at"),
        )
    ):
        item_stats_by_source[row["source_id"]] = row

    enabled_feeds = list(
        Feed.objects.filter(enabled=True)
        .select_related("source")
        .only("id", "source_id", "last_error")
    )
    latest_run_by_feed = {}
    enabled_feed_ids = [feed.id for feed in enabled_feeds]
    if enabled_feed_ids:
        for run in (
            FetchRun.objects.filter(feed_id__in=enabled_feed_ids)
            .only("feed_id", "ok", "error", "started_at")
            .order_by("feed_id", "-started_at")
        ):
            if run.feed_id not in latest_run_by_feed:
                latest_run_by_feed[run.feed_id] = run

    feed_health_by_source = {}
    for feed in enabled_feeds:
        source_health = feed_health_by_source.setdefault(
            feed.source_id,
            {"feeds_total": 0, "feeds_ok": 0, "feeds_error": 0, "feeds_never": 0},
        )
        source_health["feeds_total"] += 1

        latest_run = latest_run_by_feed.get(feed.id)
        if latest_run is None:
            source_health["feeds_never"] += 1
        elif latest_run.ok:
            source_health["feeds_ok"] += 1
        elif (latest_run.error or "").strip() or (feed.last_error or "").strip():
            source_health["feeds_error"] += 1
        else:
            source_health["feeds_error"] += 1

    source_cards = []
    for source in sources:
        item_stats = item_stats_by_source.get(
            source.id,
            {"item_count": 0, "new_24h": 0, "new_7d": 0, "last_item_at": None},
        )
        feed_health = feed_health_by_source.get(
            source.id,
            {"feeds_total": 0, "feeds_ok": 0, "feeds_error": 0, "feeds_never": 0},
        )

        feeds_total = feed_health["feeds_total"]
        feeds_error = feed_health["feeds_error"]
        feeds_never = feed_health["feeds_never"]
        total_items = item_stats["item_count"]

        if feeds_total == 0 or (feeds_never == feeds_total and total_items == 0):
            source_status = "Never"
        elif feeds_error == 0 and feeds_total > 0:
            source_status = "OK"
        elif 0 < feeds_error < feeds_total:
            source_status = "Degraded"
        elif feeds_error == feeds_total and feeds_total > 0:
            source_status = "Down"
        else:
            source_status = "Degraded"

        source_cards.append(
            {
                "source": source,
                "status": source_status,
                "new_24h": item_stats["new_24h"],
                "new_7d": item_stats["new_7d"],
                "item_count": item_stats["item_count"],
                "last_item_at": item_stats["last_item_at"],
                "feeds_total": feed_health["feeds_total"],
                "feeds_ok": feed_health["feeds_ok"],
                "feeds_error": feed_health["feeds_error"],
                "feeds_never": feed_health["feeds_never"],
                "open_url": f"{reverse('advisories')}?source={source.slug}",
            }
        )

    return render(
        request,
        "intel/sources.html",
        {
            "source_cards": source_cards,
            "current_page": "sources",
            "page_title": "Sources",
        },
    )


DARK_WINDOW_RANGES = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
DARK_WINDOW_OPTIONS = [("24h", "24h"), ("7d", "7d"), ("30d", "30d")]
DARK_MATCH_OPTIONS = [("all", "All records"), ("matched", "Watch matches")]
DARK_MAP_TILE_SIZE = {"width": 56, "height": 38}
DARK_MAP_REGION_LABELS = (
    {"label": "Americas", "x": 88, "y": 52},
    {"label": "Europe", "x": 430, "y": 52},
    {"label": "MENA", "x": 706, "y": 238},
    {"label": "APAC", "x": 864, "y": 120},
    {"label": "Africa", "x": 636, "y": 426},
)
DARK_MAP_TILE_LAYOUT = (
    {"key": "canada", "label": "Canada", "short_label": "Canada", "x": 86, "y": 102},
    {"key": "united states", "label": "United States", "short_label": "US", "x": 122, "y": 156},
    {"key": "mexico", "label": "Mexico", "short_label": "Mexico", "x": 150, "y": 214},
    {"key": "brazil", "label": "Brazil", "short_label": "Brazil", "x": 240, "y": 314},
    {"key": "argentina", "label": "Argentina", "short_label": "Argentina", "x": 246, "y": 384},
    {"key": "iceland", "label": "Iceland", "short_label": "Iceland", "x": 352, "y": 88},
    {"key": "ireland", "label": "Ireland", "short_label": "Ireland", "x": 374, "y": 126},
    {"key": "united kingdom", "label": "United Kingdom", "short_label": "UK", "x": 418, "y": 122},
    {"key": "portugal", "label": "Portugal", "short_label": "Portugal", "x": 400, "y": 196},
    {"key": "spain", "label": "Spain", "short_label": "Spain", "x": 452, "y": 196},
    {"key": "france", "label": "France", "short_label": "France", "x": 468, "y": 160},
    {"key": "belgium", "label": "Belgium", "short_label": "Belgium", "x": 522, "y": 140},
    {"key": "netherlands", "label": "Netherlands", "short_label": "NL", "x": 542, "y": 108},
    {"key": "switzerland", "label": "Switzerland", "short_label": "CH", "x": 520, "y": 212},
    {"key": "germany", "label": "Germany", "short_label": "Germany", "x": 562, "y": 158},
    {"key": "denmark", "label": "Denmark", "short_label": "Denmark", "x": 566, "y": 102},
    {"key": "norway", "label": "Norway", "short_label": "Norway", "x": 548, "y": 44},
    {"key": "sweden", "label": "Sweden", "short_label": "Sweden", "x": 614, "y": 56},
    {"key": "finland", "label": "Finland", "short_label": "Finland", "x": 680, "y": 56},
    {"key": "estonia", "label": "Estonia", "short_label": "Estonia", "x": 702, "y": 108},
    {"key": "latvia", "label": "Latvia", "short_label": "Latvia", "x": 706, "y": 146},
    {"key": "lithuania", "label": "Lithuania", "short_label": "Lithuania", "x": 694, "y": 184},
    {"key": "poland", "label": "Poland", "short_label": "Poland", "x": 632, "y": 158},
    {"key": "czechia", "label": "Czechia", "short_label": "Czechia", "x": 610, "y": 204},
    {"key": "austria", "label": "Austria", "short_label": "Austria", "x": 658, "y": 212},
    {"key": "italy", "label": "Italy", "short_label": "Italy", "x": 548, "y": 270},
    {"key": "romania", "label": "Romania", "short_label": "Romania", "x": 724, "y": 214},
    {"key": "ukraine", "label": "Ukraine", "short_label": "Ukraine", "x": 770, "y": 162},
    {"key": "greece", "label": "Greece", "short_label": "Greece", "x": 696, "y": 286},
    {"key": "turkey", "label": "Turkey", "short_label": "Turkey", "x": 790, "y": 256},
    {"key": "israel", "label": "Israel", "short_label": "Israel", "x": 786, "y": 318},
    {"key": "saudi arabia", "label": "Saudi Arabia", "short_label": "Saudi", "x": 834, "y": 338},
    {"key": "united arab emirates", "label": "United Arab Emirates", "short_label": "UAE", "x": 900, "y": 344},
    {"key": "south africa", "label": "South Africa", "short_label": "S. Africa", "x": 690, "y": 454},
    {"key": "india", "label": "India", "short_label": "India", "x": 876, "y": 262},
    {"key": "china", "label": "China", "short_label": "China", "x": 940, "y": 204},
    {"key": "korea, republic of", "label": "South Korea", "short_label": "S. Korea", "x": 992, "y": 188},
    {"key": "japan", "label": "Japan", "short_label": "Japan", "x": 1008, "y": 132},
    {"key": "australia", "label": "Australia", "short_label": "Australia", "x": 946, "y": 418},
    {"key": "new zealand", "label": "New Zealand", "short_label": "NZ", "x": 1010, "y": 474},
)
DARK_MAP_LAYOUT_KEYS = {tile["key"] for tile in DARK_MAP_TILE_LAYOUT}


def _dark_filtered_hits_queryset(request):
    query = (request.GET.get("q") or "").strip()
    selected_source = (request.GET.get("source") or "").strip()
    match_filter = (request.GET.get("match") or "all").strip()
    if match_filter not in {"all", "matched"}:
        match_filter = "all"
    legacy_window_map = {"7": "7d", "30": "30d", "90": "30d"}
    window = (request.GET.get("window") or "").strip()
    if not window:
        window = legacy_window_map.get((request.GET.get("days") or "").strip(), "7d")
    if window not in DARK_WINDOW_RANGES:
        window = "7d"
    since = timezone.now() - DARK_WINDOW_RANGES[window]

    base_hits = DarkHit.objects.select_related("dark_source", "dark_document")
    if match_filter == "matched":
        base_hits = base_hits.filter(is_watch_match=True)
    if selected_source:
        base_hits = base_hits.filter(dark_source__slug=selected_source)
    if query:
        base_hits = base_hits.filter(
            Q(group_name__icontains=query)
            | Q(victim_name__icontains=query)
            | Q(country__icontains=query)
            | Q(industry__icontains=query)
            | Q(website_url__icontains=query)
            | Q(last_activity_text__icontains=query)
            | Q(record_type__icontains=query)
            | Q(title__icontains=query)
            | Q(excerpt__icontains=query)
            | Q(url__icontains=query)
            | Q(raw__icontains=query)
            | Q(matched_keywords__icontains=query)
            | Q(matched_regex__icontains=query)
        )
    selected_hits = base_hits.filter(detected_at__gte=since).order_by("-detected_at", "-id")
    return base_hits, selected_hits, {
        "query": query,
        "selected_source": selected_source,
        "match_filter": match_filter,
        "match_options": DARK_MATCH_OPTIONS,
        "window": window,
        "since": since,
    }


def _dark_source_health_context():
    sources = list(
        DarkSource.objects.filter(enabled=True)
        .annotate(
            hit_count=Count("hits", distinct=True),
            document_count=Count("documents", distinct=True),
            last_hit_at=Max("hits__last_seen_at"),
        )
        .order_by("name")
    )
    latest_run_by_source = {}
    source_ids = [source.id for source in sources]
    if source_ids:
        for run in (
            DarkFetchRun.objects.filter(dark_source_id__in=source_ids)
            .only("dark_source_id", "ok", "error", "started_at", "finished_at")
            .order_by("dark_source_id", "-started_at")
        ):
            if run.dark_source_id not in latest_run_by_source:
                latest_run_by_source[run.dark_source_id] = run

    source_rows = []
    for source in sources:
        latest_run = latest_run_by_source.get(source.id)
        if latest_run is None:
            status = "never"
            last_run_at = None
        else:
            status = "ok" if latest_run.ok else "error"
            last_run_at = latest_run.finished_at or latest_run.started_at
        source_rows.append(
            {
                "source": source,
                "latest_run": latest_run,
                "status": status,
                "last_run_at": last_run_at,
            }
        )
    return {"sources": sources, "source_rows": source_rows}


def _preferred_group_display(current_name: str, candidate_name: str) -> str:
    if not candidate_name:
        return current_name
    if not current_name:
        return candidate_name
    if current_name == current_name.lower() and candidate_name != candidate_name.lower():
        return candidate_name
    if current_name == current_name.upper() and candidate_name != candidate_name.upper():
        return candidate_name
    return current_name


def _active_group_rows(hits):
    grouped = {}
    for hit in hits:
        group_name = resolve_group_name(
            record_type=hit.record_type,
            group_name=hit.group_name,
            title=hit.title,
            victim_name=hit.victim_name,
        )
        if not group_name:
            continue
        country_display, _country_code = normalize_dark_country(hit.country)
        group_key = group_name.lower()
        activity_at = hit.last_seen_at or hit.detected_at
        row = grouped.get(group_key)
        if row is None:
            row = {
                "group_name": group_name,
                "incident_count": 0,
                "latest_activity_at": activity_at,
                "latest_detected_at": hit.detected_at,
                "latest_victim_name": "",
                "latest_country": "",
                "latest_activity_text": "",
                "victim_count": None,
                "watch_match_count": 0,
                "source_names": [],
                "source_ids": set(),
            }
            grouped[group_key] = row

        row["incident_count"] += 1
        if hit.is_watch_match:
            row["watch_match_count"] += 1
        row["group_name"] = _preferred_group_display(row["group_name"], group_name)
        if hit.dark_source_id not in row["source_ids"]:
            row["source_ids"].add(hit.dark_source_id)
            row["source_names"].append(hit.dark_source.name)
        if row["victim_count"] is None and hit.victim_count is not None:
            row["victim_count"] = hit.victim_count

        if activity_at >= row["latest_activity_at"]:
            row["latest_activity_at"] = activity_at
            row["latest_detected_at"] = hit.detected_at
            row["latest_victim_name"] = hit.victim_name or row["latest_victim_name"]
            row["latest_country"] = country_display or row["latest_country"]
            row["latest_activity_text"] = hit.last_activity_text or row["latest_activity_text"]

    rows = []
    for row in grouped.values():
        row["source_count"] = len(row["source_ids"])
        del row["source_ids"]
        rows.append(row)
    rows.sort(
        key=lambda row: (
            row["latest_activity_at"],
            row["incident_count"],
            row["group_name"].lower(),
        ),
        reverse=True,
    )
    return rows


def _dark_dashboard_summary(base_hits, selected_hits):
    hits_24h = base_hits.filter(detected_at__gte=timezone.now() - DARK_WINDOW_RANGES["24h"])
    hits_7d = base_hits.filter(detected_at__gte=timezone.now() - DARK_WINDOW_RANGES["7d"])
    selected_hits_list = list(selected_hits)
    countries = {
        country_display
        for hit in selected_hits_list
        for country_display, _country_code in [normalize_dark_country(hit.country)]
        if country_display
    }
    source_ids = {hit.dark_source_id for hit in selected_hits_list}

    return {
        "active_groups_24h": len(_active_group_rows(hits_24h)),
        "active_groups_7d": len(_active_group_rows(hits_7d)),
        "incident_count_24h": hits_24h.filter(record_type="incident").count(),
        "incident_count_7d": hits_7d.filter(record_type="incident").count(),
        "affected_country_count": len(countries),
        "source_hit_count": len(source_ids),
    }


def _live_incident_hits(hits):
    return [hit for hit in hits if hit.record_type == "incident"][:6]


def _normalized_country_key(value: str) -> str:
    country_display, _country_code = normalize_dark_country(value)
    if country_display:
        return country_display.lower()
    return (value or "").strip().lower()


def _dark_map_tile_palette(*, intensity_level: int, is_selected: bool, has_activity: bool):
    if not has_activity:
        return {
            "fill": "#0f172a",
            "stroke": "#1e293b",
            "text": "#475569",
            "badge": "#0f172a",
        }

    palette = {
        1: {"fill": "#10263c", "stroke": "#1d4ed8", "text": "#dbeafe", "badge": "#38bdf8"},
        2: {"fill": "#10334a", "stroke": "#0ea5e9", "text": "#e0f2fe", "badge": "#22d3ee"},
        3: {"fill": "#11485d", "stroke": "#14b8a6", "text": "#ecfeff", "badge": "#2dd4bf"},
        4: {"fill": "#0f766e", "stroke": "#5eead4", "text": "#f0fdfa", "badge": "#67e8f9"},
    }.get(max(1, min(intensity_level, 4)))
    if is_selected:
        return {
            "fill": palette["fill"],
            "stroke": "#a5f3fc",
            "text": "#f0fdfa",
            "badge": "#67e8f9",
        }
    return palette


def _dark_map_intensity_level(record_count: int, max_record_count: int) -> int:
    if record_count <= 0:
        return 0
    if max_record_count <= 1:
        return 4
    ratio = record_count / max_record_count
    if ratio >= 0.8:
        return 4
    if ratio >= 0.55:
        return 3
    if ratio >= 0.3:
        return 2
    return 1


def _dark_map_country_url(*, window: str, selected_source: str, match_filter: str, country: str = "") -> str:
    params = {"window": window}
    if selected_source:
        params["source"] = selected_source
    if match_filter != "all":
        params["match"] = match_filter
    if country:
        params["country"] = country
    return f"{reverse('dark-map')}?{urlencode(params)}"


def _dark_map_tiles(country_rows, *, selected_country: str, window: str, selected_source: str, match_filter: str):
    row_by_layout_key = {}
    unmapped_rows = []
    for row in country_rows:
        map_key = row["country_key"]
        row["map_country_key"] = map_key
        if map_key not in DARK_MAP_LAYOUT_KEYS:
            unmapped_rows.append(row)
            continue
        row_by_layout_key[map_key] = row

    max_record_count = max((row["record_count"] for row in country_rows), default=0)
    width = DARK_MAP_TILE_SIZE["width"]
    height = DARK_MAP_TILE_SIZE["height"]
    tiles = []
    for tile in DARK_MAP_TILE_LAYOUT:
        row = row_by_layout_key.get(tile["key"])
        has_activity = row is not None
        is_selected = has_activity and row["country_key"] == _normalized_country_key(selected_country)
        intensity_level = _dark_map_intensity_level(
            row["record_count"] if row else 0,
            max_record_count,
        )
        palette = _dark_map_tile_palette(
            intensity_level=intensity_level,
            is_selected=is_selected,
            has_activity=has_activity,
        )
        display_count = row["incident_count"] if row and row["incident_count"] else (row["record_count"] if row else "")
        tiles.append(
            {
                "country_key": tile["key"],
                "label": tile["label"],
                "short_label": tile["short_label"],
                "x": tile["x"],
                "y": tile["y"],
                "width": width,
                "height": height,
                "label_x": tile["x"] + 8,
                "label_y": tile["y"] + 15,
                "count_x": tile["x"] + width - 10,
                "count_y": tile["y"] + 26,
                "badge_x": tile["x"] + width - 8,
                "badge_y": tile["y"] + 9,
                "has_activity": has_activity,
                "is_selected": is_selected,
                "fill_color": palette["fill"],
                "stroke_color": palette["stroke"],
                "text_color": palette["text"],
                "badge_color": palette["badge"],
                "record_count": row["record_count"] if row else 0,
                "incident_count": row["incident_count"] if row else 0,
                "watch_match_count": row["watch_match_count"] if row else 0,
                "country": row["country"] if row else tile["label"],
                "url": (
                    _dark_map_country_url(
                        window=window,
                        selected_source=selected_source,
                        match_filter=match_filter,
                        country="" if is_selected else row["country"],
                    )
                    if has_activity
                    else ""
                ),
                "tooltip": (
                    f"{row['country']}: {row['record_count']} records, "
                    f"{row['incident_count']} incidents, {row['watch_match_count']} watch-matched"
                    if row
                    else f"{tile['label']}: no activity in current filters"
                ),
                "display_count": display_count,
            }
        )

    unmapped_rows.sort(
        key=lambda row: (
            row["incident_count"],
            row["record_count"],
            row["country"].lower(),
        ),
        reverse=True,
    )
    return tiles, unmapped_rows


def _dark_map_empty_state(hits, country_rows, *, selected_source_name: str = ""):
    if country_rows:
        return {}
    if not hits:
        return {
            "title": "No records in current window",
            "message": "No dark records matched the current window, source, and record filters.",
        }
    incident_hits = [hit for hit in hits if hit.record_type == "incident"]
    if not incident_hits:
        source_phrase = (
            f"{selected_source_name} is" if selected_source_name else "The current selection is"
        )
        return {
            "title": "No incident data to map",
            "message": (
                f"{source_phrase} currently contributing only group/context records. "
                "The map activates when incident-style records carry normalized country data."
            ),
        }
    raw_country_values = [(hit.country or "").strip() for hit in incident_hits if (hit.country or "").strip()]
    if not raw_country_values:
        return {
            "title": "Incident country data missing",
            "message": (
                "Incident-style records matched the current filters, but they do not yet carry "
                "country values for plotting."
            ),
        }
    return {
        "title": "Country data missing",
        "message": (
            "Incident-style records matched the current filters, but their country values still "
            "need cleaner normalization before they can be plotted reliably."
        ),
    }


def _dark_map_latest_incident_empty_message(*, selected_country: str, map_empty_state: dict):
    if selected_country:
        return f"No incident-style records are currently mapped to {selected_country} in this view."
    if map_empty_state:
        return map_empty_state["message"]
    return "No incident-style records matched the current map filters."


def _dark_country_activity_rows(hits):
    grouped = {}
    max_record_count = 0
    for hit in hits:
        country_display, country_code = normalize_dark_country(hit.country)
        if not country_display:
            continue
        country_key = country_display.lower()
        activity_at = hit.last_seen_at or hit.detected_at
        row = grouped.get(country_key)
        if row is None:
            row = {
                "country": country_display,
                "country_code": country_code,
                "record_count": 0,
                "incident_count": 0,
                "latest_activity_at": activity_at,
                "latest_detected_at": hit.detected_at,
                "group_names": [],
                "group_keys": set(),
                "source_ids": set(),
                "watch_match_count": 0,
            }
            grouped[country_key] = row

        row["record_count"] += 1
        if hit.record_type == "incident":
            row["incident_count"] += 1
        if hit.is_watch_match:
            row["watch_match_count"] += 1
        if hit.dark_source_id not in row["source_ids"]:
            row["source_ids"].add(hit.dark_source_id)

        group_name = resolve_group_name(
            record_type=hit.record_type,
            group_name=hit.group_name,
            title=hit.title,
            victim_name=hit.victim_name,
        )
        if group_name and group_name.lower() not in row["group_keys"]:
            row["group_keys"].add(group_name.lower())
            row["group_names"].append(group_name)

        if activity_at >= row["latest_activity_at"]:
            row["latest_activity_at"] = activity_at
            row["latest_detected_at"] = hit.detected_at

        max_record_count = max(max_record_count, row["record_count"])

    rows = []
    for country_key, row in grouped.items():
        row["country_key"] = country_key
        row["source_count"] = len(row["source_ids"])
        row["group_count"] = len(row["group_keys"])
        row["activity_ratio"] = (
            max(18, int((row["record_count"] / max_record_count) * 100))
            if max_record_count
            else 18
        )
        del row["source_ids"]
        del row["group_keys"]
        rows.append(row)

    rows.sort(
        key=lambda row: (
            row["incident_count"],
            row["record_count"],
            row["latest_activity_at"],
            row["country"].lower(),
        ),
        reverse=True,
    )
    return rows


def _dark_map_group_rows(hits, *, selected_country: str = ""):
    rows = _active_group_rows(hits)
    group_countries = {}
    for hit in hits:
        group_name = resolve_group_name(
            record_type=hit.record_type,
            group_name=hit.group_name,
            title=hit.title,
            victim_name=hit.victim_name,
        )
        if not group_name:
            continue
        country_display, _country_code = normalize_dark_country(hit.country)
        if not country_display:
            continue
        country_map = group_countries.setdefault(group_name.lower(), {})
        country_map.setdefault(country_display.lower(), country_display)

    selected_country_key = _normalized_country_key(selected_country)
    for row in rows:
        countries = sorted(group_countries.get(row["group_name"].lower(), {}).values())
        row["countries"] = countries
        row["country_match"] = (
            bool(selected_country_key)
            and selected_country_key in {country.lower() for country in countries}
        )
    return rows


def _dark_map_latest_incidents(hits, *, selected_country: str = ""):
    selected_country_key = _normalized_country_key(selected_country)
    incidents = []
    for hit in hits:
        if hit.record_type != "incident":
            continue
        country_display, country_code = normalize_dark_country(hit.country)
        if selected_country_key and _normalized_country_key(country_display) != selected_country_key:
            continue
        hit.map_country = country_display
        hit.map_country_code = country_code
        incidents.append(hit)
    return incidents[:8]


@superuser_required
def dark_dashboard_view(request):
    base_hits, hits, filter_context = _dark_filtered_hits_queryset(request)
    selected_hits = list(hits)
    active_groups = _active_group_rows(selected_hits)
    grouped_incident_count = sum(row["incident_count"] for row in active_groups)
    groups_paginator = Paginator(active_groups, 40)
    groups_page = groups_paginator.get_page(request.GET.get("page"))
    health_context = _dark_source_health_context()
    summary_metrics = _dark_dashboard_summary(base_hits, selected_hits)
    live_incidents = _live_incident_hits(selected_hits)

    return render(
        request,
        "intel/dark/dashboard.html",
        {
            "page_title": "Dark Intel",
            "current_page": "dark",
            "group_rows": groups_page,
            "page_obj": groups_page,
            "active_group_count": len(active_groups),
            "incident_count": grouped_incident_count,
            "summary_metrics": summary_metrics,
            "live_incidents": live_incidents,
            "recent_hits_url": reverse("dark-recent-hits"),
            "window_options": DARK_WINDOW_OPTIONS,
            **health_context,
            **filter_context,
        },
    )


@superuser_required
def dark_map_view(request):
    _, hits, filter_context = _dark_filtered_hits_queryset(request)
    selected_hits = list(hits)
    country_rows = _dark_country_activity_rows(selected_hits)
    selected_source_name = ""
    if filter_context["selected_source"]:
        selected_source_name = (
            DarkSource.objects.filter(slug=filter_context["selected_source"])
            .values_list("name", flat=True)
            .first()
            or filter_context["selected_source"]
        )

    selected_country = ""
    requested_country = (request.GET.get("country") or "").strip()
    if requested_country:
        requested_country_key = _normalized_country_key(requested_country)
        for row in country_rows:
            if row["country_key"] == requested_country_key:
                selected_country = row["country"]
                break
        if not selected_country:
            normalized_country, _country_code = normalize_dark_country(requested_country)
            selected_country = normalized_country or requested_country

    selected_country_key = _normalized_country_key(selected_country)
    for row in country_rows:
        row["is_selected"] = row["country_key"] == selected_country_key

    map_tiles, unmapped_country_rows = _dark_map_tiles(
        country_rows,
        selected_country=selected_country,
        window=filter_context["window"],
        selected_source=filter_context["selected_source"],
        match_filter=filter_context["match_filter"],
    )
    map_empty_state = _dark_map_empty_state(
        selected_hits,
        country_rows,
        selected_source_name=selected_source_name,
    )
    top_countries = country_rows[:8]
    group_rows = _dark_map_group_rows(selected_hits, selected_country=selected_country)
    top_groups = group_rows[:8]
    latest_incidents = _dark_map_latest_incidents(
        selected_hits,
        selected_country=selected_country,
    )
    latest_incident_empty_message = _dark_map_latest_incident_empty_message(
        selected_country=selected_country,
        map_empty_state=map_empty_state,
    )

    map_metrics = {
        "country_count": len(country_rows),
        "group_count": len(group_rows),
        "incident_count": len([hit for hit in selected_hits if hit.record_type == "incident"]),
        "source_count": len({hit.dark_source_id for hit in selected_hits}),
    }

    return render(
        request,
        "intel/dark/map.html",
        {
            "page_title": "Dark Intel Threat Map",
            "current_page": "dark",
            "country_rows": country_rows,
            "map_tiles": map_tiles,
            "map_region_labels": DARK_MAP_REGION_LABELS,
            "map_empty_state": map_empty_state,
            "unmapped_country_rows": unmapped_country_rows,
            "top_countries": top_countries,
            "top_groups": top_groups,
            "latest_incidents": latest_incidents,
            "latest_incident_empty_message": latest_incident_empty_message,
            "selected_country": selected_country,
            "selected_country_key": selected_country_key,
            "selected_country_on_map": any(tile["is_selected"] for tile in map_tiles),
            "selected_source_name": selected_source_name,
            "map_metrics": map_metrics,
            "dashboard_url": reverse("dark-dashboard"),
            "recent_hits_url": reverse("dark-recent-hits"),
            "window_options": DARK_WINDOW_OPTIONS,
            **_dark_source_health_context(),
            **filter_context,
        },
    )


@superuser_required
def dark_recent_hits_view(request):
    _, hits, filter_context = _dark_filtered_hits_queryset(request)
    paginator = Paginator(hits, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    health_context = _dark_source_health_context()

    return render(
        request,
        "intel/dark/recent_hits.html",
        {
            "page_title": "Dark Intel",
            "current_page": "dark",
            "hits": page_obj,
            "page_obj": page_obj,
            "groups_url": reverse("dark-dashboard"),
            "window_options": DARK_WINDOW_OPTIONS,
            **health_context,
            **filter_context,
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


def admin_login_view(request):
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect("intel_admin:ops")

    next_url = _validated_next_url(request)
    form = AuthenticationForm(request=request, data=request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            user = form.get_user()
            if user is not None and user.is_superuser:
                login(request, user)
                return redirect(next_url)

            # giltiga credentials men inte superuser
            messages.error(request, "Invalid credentials.")
        else:
            # ogiltiga credentials
            messages.error(request, "Invalid credentials.")

    return render(
        request,
        "intel/admin_panel/login.html",
        {"form": form, "next_url": next_url, "current_page": "admin-login"},
    )


@require_POST
def admin_logout_view(request):
    logout(request)
    return redirect("intel_admin:login")


def _build_feed_rows(feeds):
    latest_run_by_feed = {}
    feed_ids = [feed.id for feed in feeds]
    if feed_ids:
        for run in FetchRun.objects.filter(feed_id__in=feed_ids).order_by("feed_id", "-started_at"):
            if run.feed_id not in latest_run_by_feed:
                latest_run_by_feed[run.feed_id] = run

    feed_rows = []
    for feed in feeds:
        latest_run = latest_run_by_feed.get(feed.id)
        display_error = ""
        if latest_run is not None:
            if latest_run.ok:
                status = "ok"
            elif latest_run.error or feed.last_error:
                status = "error"
            else:
                status = "error"
            last_run_at = latest_run.finished_at or latest_run.started_at
            display_error = (latest_run.error or "").strip()
        else:
            if feed.last_success_at is None:
                status = "never"
            elif feed.last_error:
                status = "error"
            else:
                status = "ok"
            last_run_at = None
        if not display_error:
            display_error = (feed.last_error or "").strip()

        feed_rows.append(
            {
                "feed": feed,
                "latest_run": latest_run,
                "status": status,
                "last_run_at": last_run_at,
                "display_error": display_error,
                "collection_mode": "expanded" if feed.expanded_collection else "normal",
                "effective_max_items": (
                    feed.expanded_max_items_per_run or max(feed.max_items_per_run, 1000)
                    if feed.expanded_collection
                    else feed.max_items_per_run
                ),
                "effective_max_age_days": (
                    feed.expanded_max_age_days or max(feed.max_age_days, 365)
                    if feed.expanded_collection
                    else feed.max_age_days
                ),
            }
        )
    return feed_rows


@superuser_required
def ops_dashboard(request):
    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action in OPS_ACTIONS:
            job, label = queue_ops_job(action=action, requested_by=request.user)
            try:
                launch_ops_job_subprocess(job.id)
                messages.success(
                    request,
                    f"{label} queued as job #{job.id}. Refresh this page to follow status/output.",
                )
            except Exception as exc:
                job.status = OpsJob.Status.FAILED
                job.started_at = timezone.now()
                job.finished_at = timezone.now()
                job.error_summary = f"Failed to start background runner: {exc}"[:2000]
                job.stderr = job.error_summary
                job.save(
                    update_fields=[
                        "status",
                        "started_at",
                        "finished_at",
                        "error_summary",
                        "stderr",
                        "updated_at",
                    ]
                )
                messages.error(request, f"{label} failed to queue: {exc}")
        else:
            messages.error(request, "Unknown action.")
        return redirect("intel_admin:ops")

    enabled_feeds_qs = Feed.objects.filter(enabled=True).select_related("source")
    enabled_feeds = list(enabled_feeds_qs.order_by("source__name", "name"))

    enabled_feeds_count = len(enabled_feeds)
    ok_count = enabled_feeds_qs.filter(last_success_at__isnull=False, last_error="").count()
    error_count = enabled_feeds_qs.exclude(last_error="").count()
    never_run_count = enabled_feeds_qs.filter(last_success_at__isnull=True).count()

    latest_finished = (
        FetchRun.objects.filter(finished_at__isnull=False)
        .order_by("-finished_at")
        .values_list("finished_at", flat=True)
        .first()
    )
    if latest_finished is None:
        latest_finished = (
            FetchRun.objects.order_by("-started_at")
            .values_list("started_at", flat=True)
            .first()
        )

    feed_rows = _build_feed_rows(enabled_feeds)

    recent_runs = list(
        FetchRun.objects.select_related("feed", "feed__source").order_by("-started_at")[:50]
    )
    recent_jobs = list(
        OpsJob.objects.select_related("requested_by").order_by("-created_at")[:30]
    )
    selected_job = None
    selected_job_id = (request.GET.get("job") or "").strip()
    if selected_job_id.isdigit():
        selected_job = (
            OpsJob.objects.select_related("requested_by")
            .filter(id=int(selected_job_id))
            .first()
        )

    feed_list_url = None
    try:
        feed_list_url = reverse("admin:intel_feed_changelist")
    except NoReverseMatch:
        feed_list_url = None

    return render(
        request,
        "intel/ops_dashboard.html",
        {
            "page_title": "Ops",
            "current_page": "ops",
            "enabled_feeds_count": enabled_feeds_count,
            "ok_count": ok_count,
            "error_count": error_count,
            "never_run_count": never_run_count,
            "last_ingest_at": latest_finished,
            "feed_rows": feed_rows,
            "recent_runs": recent_runs,
            "recent_jobs": recent_jobs,
            "selected_job": selected_job,
            "feed_list_url": feed_list_url,
            "admin_panel_url": reverse("intel_admin:panel"),
            "django_admin_url": reverse("admin:index"),
        },
    )


@superuser_required
def admin_panel_view(request):
    query = (request.GET.get("q") or "").strip()
    selected_section = (request.GET.get("section") or "").strip()
    selected_enabled = (request.GET.get("enabled") or "all").strip().lower()
    selected_status = (request.GET.get("status") or "all").strip().lower()

    valid_sections = {value for value, _label in Feed.Section.choices}
    if selected_section not in valid_sections:
        selected_section = ""

    if selected_enabled not in {"all", "enabled", "disabled"}:
        selected_enabled = "all"

    if selected_status not in {"all", "ok", "error", "never"}:
        selected_status = "all"

    feeds_qs = Feed.objects.select_related("source")
    if query:
        feeds_qs = feeds_qs.filter(
            Q(source__name__icontains=query)
            | Q(name__icontains=query)
            | Q(url__icontains=query)
            | Q(adapter_key__icontains=query)
        )
    if selected_section:
        feeds_qs = feeds_qs.filter(section=selected_section)
    if selected_enabled == "enabled":
        feeds_qs = feeds_qs.filter(enabled=True)
    elif selected_enabled == "disabled":
        feeds_qs = feeds_qs.filter(enabled=False)

    feeds = list(feeds_qs.order_by("source__name", "name"))
    feed_rows = _build_feed_rows(feeds)
    if selected_status != "all":
        feed_rows = [row for row in feed_rows if row["status"] == selected_status]

    total_feeds_count = len(feed_rows)
    enabled_feeds_count = sum(1 for row in feed_rows if row["feed"].enabled)
    disabled_feeds_count = total_feeds_count - enabled_feeds_count
    error_feeds_count = sum(1 for row in feed_rows if row["status"] == "error")

    return render(
        request,
        "intel/admin_panel/feed_list.html",
        {
            "page_title": "Admin Panel",
            "current_page": "admin",
            "feed_rows": feed_rows,
            "total_feeds_count": total_feeds_count,
            "enabled_feeds_count": enabled_feeds_count,
            "disabled_feeds_count": disabled_feeds_count,
            "error_feeds_count": error_feeds_count,
            "query": query,
            "selected_section": selected_section,
            "selected_enabled": selected_enabled,
            "selected_status": selected_status,
            "section_options": Feed.Section.choices,
            "has_active_filters": bool(
                query
                or selected_section
                or selected_enabled != "all"
                or selected_status != "all"
            ),
            "sources_url": reverse("intel_admin:sources"),
            "dark_sources_url": reverse("intel_admin:dark_sources"),
            "django_admin_url": reverse("admin:index"),
        },
    )


@superuser_required
def admin_panel_feed_create(request):
    form = FeedCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        feed = form.save()
        messages.success(request, f"Feed '{feed.name}' created.")
        return redirect("intel_admin:panel")
    return render(
        request,
        "intel/admin_panel/feed_form.html",
        {
            "page_title": "Create Feed",
            "current_page": "admin",
            "form": form,
            "mode": "create",
            "cancel_url": reverse("intel_admin:panel"),
        },
    )


@superuser_required
def admin_panel_sources_list(request):
    sources = list(
        Source.objects.annotate(
            feed_count=Count("feeds", distinct=True),
            item_count=Count("items", distinct=True),
            last_item_at=Max(Coalesce("items__published_at", "items__created_at")),
        ).order_by("name")
    )
    return render(
        request,
        "intel/admin_panel/source_list.html",
        {
            "page_title": "Source Admin",
            "current_page": "admin",
            "sources": sources,
            "feeds_url": reverse("intel_admin:panel"),
            "dark_sources_url": reverse("intel_admin:dark_sources"),
            "django_admin_url": reverse("admin:index"),
        },
    )


def _dark_source_rows():
    sources = list(
        DarkSource.objects.annotate(
            hit_count=Count("hits", distinct=True),
            document_count=Count("documents", distinct=True),
            last_hit_at=Max("hits__last_seen_at"),
        ).order_by("name")
    )
    latest_run_by_source = {}
    source_ids = [source.id for source in sources]
    if source_ids:
        for run in (
            DarkFetchRun.objects.filter(dark_source_id__in=source_ids)
            .only(
                "dark_source_id",
                "ok",
                "error",
                "started_at",
                "finished_at",
                "bytes_received",
                "http_status",
                "documents_fetched",
                "hits_new",
                "hits_updated",
            )
            .order_by("dark_source_id", "-started_at")
        ):
            if run.dark_source_id not in latest_run_by_source:
                latest_run_by_source[run.dark_source_id] = run

    source_rows = []
    for source in sources:
        latest_run = latest_run_by_source.get(source.id)
        if latest_run is None:
            status = "never"
            last_run_at = None
            last_error = ""
            latest_hit_count = 0
        else:
            status = "ok" if latest_run.ok else "error"
            last_run_at = latest_run.finished_at or latest_run.started_at
            last_error = (latest_run.error or "").strip()
            latest_hit_count = int(latest_run.hits_new or 0) + int(latest_run.hits_updated or 0)
        keyword_watch_count = len(
            [value for value in re.split(r"[\n,]+", source.watch_keywords or "") if value.strip()]
        )
        regex_watch_count = len(
            [value for value in (source.watch_regex or "").splitlines() if value.strip()]
        )
        partial_success = (
            status == "error"
            and latest_run is not None
            and (
                int(latest_run.documents_fetched or 0) > 0
                or latest_hit_count > 0
            )
        )
        source_rows.append(
            {
                "source": source,
                "latest_run": latest_run,
                "status": status,
                "last_run_at": last_run_at,
                "last_error": last_error,
                "latest_hit_count": latest_hit_count,
                "partial_success": partial_success,
                "has_keyword_watch": keyword_watch_count > 0,
                "has_regex_watch": regex_watch_count > 0,
                "keyword_watch_count": keyword_watch_count,
                "regex_watch_count": regex_watch_count,
                "extractor_profile_display": source.get_extractor_profile_display(),
                "suitability_warning": dark_source_suitability_warning(
                    source.url, source.source_type
                ),
                "open_url": f"{reverse('dark-dashboard')}?source={source.slug}",
            }
        )
    return source_rows


def _queue_custom_ops_job(*, command_name: str, args: list[str], requested_by, label: str):
    job = OpsJob.objects.create(
        command_name=command_name,
        command_args=list(args),
        command_options={},
        requested_by=requested_by,
    )
    try:
        launch_ops_job_subprocess(job.id)
        return job
    except Exception as exc:
        job.status = OpsJob.Status.FAILED
        job.started_at = timezone.now()
        job.finished_at = timezone.now()
        job.error_summary = f"Failed to start background runner: {exc}"[:2000]
        job.stderr = job.error_summary
        job.save(
            update_fields=[
                "status",
                "started_at",
                "finished_at",
                "error_summary",
                "stderr",
                "updated_at",
            ]
        )
        raise RuntimeError(f"{label} failed to queue: {exc}") from exc


def _next_dark_copy_slug(base_slug: str) -> str:
    stem = f"{slugify(base_slug) or 'dark-source'}-copy"
    slug = stem
    index = 2
    while DarkSource.objects.filter(slug=slug).exists():
        slug = f"{stem}-{index}"
        index += 1
    return slug


def _next_dark_copy_name(base_name: str) -> str:
    stem = f"{(base_name or 'Dark Source').strip()} (copy)"
    name = stem
    index = 2
    while DarkSource.objects.filter(name=name).exists():
        name = f"{stem} {index}"
        index += 1
    return name


def _build_dark_source_preview(source: DarkSource):
    from intel.management.commands.ingest_dark import Command as IngestDarkCommand

    command = IngestDarkCommand()
    markup, http_status, final_url, bytes_received = command._fetch_with_retries(
        source.url, source
    )
    summary = summarize_profile_content(
        markup,
        profile=source.extractor_profile,
        base_url=final_url or source.url,
    )
    title = summary["title"]
    extracted_text = summary["text"]
    excerpt = summary["excerpt"][:220] if len(summary["excerpt"]) > 220 else summary["excerpt"]
    if len(excerpt) < 40:
        raise ValueError("No useful content extracted from response.")

    preview_notes = []
    suitability_warning = dark_source_suitability_warning(source.url, source.source_type)
    if suitability_warning:
        preview_notes.append(suitability_warning)

    if source.source_type == DarkSource.SourceType.INDEX_PAGE:
        candidate_links = extract_links(
            markup,
            base_url=final_url or source.url,
            max_links=settings.DARK_INDEX_MAX_LINKS,
        )
        link_count = len(candidate_links)
        if link_count == 0:
            preview_notes.append("No same-host candidate links were discovered.")
    elif source.source_type == DarkSource.SourceType.FEED:
        parsed = feedparser.parse(markup)
        if getattr(parsed, "bozo", False) and not getattr(parsed, "entries", None):
            raise ValueError(f"Feed parse issue: {parsed.bozo_exception}")
        feed_links = [
            (entry.get("link") or entry.get("id") or "").strip()
            for entry in (parsed.entries or [])
        ]
        link_count = len([link for link in feed_links if link])
        candidate_links = [link for link in feed_links if link][:5]
        if link_count == 0:
            preview_notes.append("Feed payload parsed, but no usable entry links were found.")
    else:
        link_count = 1
        candidate_links = [final_url or source.url]

    return {
        "source_name": source.name,
        "source_id": source.id,
        "source_type": source.source_type,
        "extractor_profile": source.extractor_profile,
        "http_status": http_status,
        "final_url": final_url or source.url,
        "title": title,
        "excerpt": excerpt,
        "text_length": len(extracted_text),
        "record_count": len(summary["records"]),
        "link_count": link_count,
        "candidate_links": candidate_links,
        "bytes_received": bytes_received,
        "notes": preview_notes,
    }


def _dark_preview_failure_info(exc: Exception) -> dict:
    detail = str(exc).strip() or exc.__class__.__name__
    lowered = detail.lower()
    if "timeout" in lowered or "timed out" in lowered:
        reason = "Timeout while fetching source."
    elif "403" in lowered or "401" in lowered or "forbidden" in lowered:
        reason = "Remote endpoint blocked the request."
    elif "max_bytes" in lowered:
        reason = "Response exceeded configured max bytes."
    elif "parse" in lowered or "feed" in lowered:
        reason = "Parse issue in response payload."
    elif "no useful content" in lowered:
        reason = "No useful content extracted from response."
    else:
        reason = "Fetch or processing failed."
    return {"reason": reason, "detail": detail[:500]}


def _prepare_dark_source_form(form):
    field_overrides = {
        "name": {
            "label": "Source Name",
            "help_text": "Operator-facing name shown in the dark admin and dark dashboard.",
            "placeholder": "Acme leak monitor",
        },
        "slug": {
            "label": "Slug",
            "help_text": "Stable identifier used in routes and filtered dashboard links.",
            "placeholder": "acme-leak-monitor",
            "spellcheck": "false",
        },
        "homepage": {
            "label": "Homepage / Context URL",
            "help_text": "Optional operator reference page for context or documentation.",
            "placeholder": "https://example.com/advisories/",
            "spellcheck": "false",
        },
        "url": {
            "label": "Fetch URL",
            "help_text": "Primary allowlisted fetch target. Prefer a direct RSS/Atom endpoint when using feed mode.",
            "placeholder": "https://example.com/feed.xml",
            "spellcheck": "false",
        },
        "source_type": {
            "label": "Source Type",
            "help_text": "Choose feed for RSS/Atom, index_page for same-host discovery, or single_page for one URL only.",
        },
        "extractor_profile": {
            "label": "Extractor Profile",
            "help_text": "Use generic_page for one cleaned page, incident_cards/group_cards for repeated cards, or table_rows for structured summary tables.",
        },
        "enabled": {
            "label": "Enabled",
            "help_text": "Turn off to keep the source configured without including it in ingest jobs.",
        },
        "use_tor": {
            "label": "Route Through Tor",
            "help_text": "Onion URLs always use Tor. Enable this to force Tor for clearnet targets.",
        },
        "timeout_seconds": {
            "label": "Timeout Seconds",
            "help_text": "Per-source timeout override. Leave blank to use the global DARK_FETCH_TIMEOUT value.",
            "placeholder": "15",
        },
        "max_bytes": {
            "label": "Max Response Bytes",
            "help_text": "Hard response size cap. Leave blank to use the global DARK_MAX_BYTES value.",
            "placeholder": "1048576",
        },
        "fetch_retries": {
            "label": "Retry Attempts",
            "help_text": "Retry count for transient failures. Leave blank to use the global DARK_FETCH_RETRIES value.",
            "placeholder": "2",
        },
        "tags": {
            "label": "Tags",
            "help_text": "Comma-separated internal tags for grouping and triage.",
            "placeholder": "vendor, sweden, ransomware",
        },
        "watch_keywords": {
            "label": "Keyword Watches",
            "help_text": "Comma-separated passive match terms applied to extracted records. Saved in lowercase on submit.",
            "placeholder": "breach, leak, initial access",
            "textarea_rows": 4,
            "spellcheck": "false",
        },
        "watch_regex": {
            "label": "Regex Watches",
            "help_text": "One regex per line. Structured profiles test these against each extracted record instead of the whole page.",
            "placeholder": r"CVE-\d{4}-\d+" + "\n" + r"ransomware",
            "textarea_rows": 6,
            "spellcheck": "false",
        },
    }
    for name, overrides in field_overrides.items():
        field = form.fields[name]
        base_class = field.widget.attrs.get("class", "")
        field.label = overrides["label"]
        field.help_text = overrides["help_text"]
        if "textarea_rows" in overrides and not isinstance(field.widget, forms.Textarea):
            field.widget = forms.Textarea()
            if base_class:
                field.widget.attrs["class"] = base_class
        if "placeholder" in overrides:
            field.widget.attrs["placeholder"] = overrides["placeholder"]
        if "spellcheck" in overrides:
            field.widget.attrs["spellcheck"] = overrides["spellcheck"]
        if "textarea_rows" in overrides:
            field.widget.attrs["rows"] = overrides["textarea_rows"]
            field.widget.attrs["class"] = (
                f"{field.widget.attrs.get('class', '')} min-h-28 whitespace-pre-wrap".strip()
            )
        if name in {"slug", "homepage", "url", "watch_regex"}:
            field.widget.attrs["class"] = (
                f"{field.widget.attrs.get('class', '')} font-mono text-sm".strip()
            )
        if name in {"timeout_seconds", "max_bytes", "fetch_retries"}:
            field.widget.attrs["inputmode"] = "numeric"
        if form.errors.get(name):
            field.widget.attrs["aria-invalid"] = "true"
    return [
        {
            "title": section["title"],
            "description": section["description"],
            "fields": [form[name] for name in section["fields"]],
        }
        for section in DARK_SOURCE_FORM_SECTIONS
    ]


@superuser_required
def admin_panel_dark_sources_list(request):
    source_rows = _dark_source_rows()
    test_preview = request.session.pop("dark_source_test_preview", None)
    total_dark_sources_count = len(source_rows)
    enabled_dark_sources_count = sum(1 for row in source_rows if row["source"].enabled)
    disabled_dark_sources_count = total_dark_sources_count - enabled_dark_sources_count
    tor_enabled_sources_count = sum(1 for row in source_rows if row["source"].use_tor)
    keyword_watch_sources_count = sum(1 for row in source_rows if row["has_keyword_watch"])

    return render(
        request,
        "intel/admin_panel/dark_source_list.html",
        {
            "page_title": "Dark Admin",
            "current_page": "admin",
            "source_rows": source_rows,
            "total_dark_sources_count": total_dark_sources_count,
            "enabled_dark_sources_count": enabled_dark_sources_count,
            "disabled_dark_sources_count": disabled_dark_sources_count,
            "tor_enabled_sources_count": tor_enabled_sources_count,
            "keyword_watch_sources_count": keyword_watch_sources_count,
            "feeds_url": reverse("intel_admin:panel"),
            "sources_url": reverse("intel_admin:sources"),
            "django_admin_url": reverse("admin:index"),
            "test_preview": test_preview,
        },
    )


@superuser_required
def admin_panel_dark_source_create(request):
    preset_key = (request.GET.get("preset") or "").strip()
    initial = {}
    if request.method == "GET":
        for preset in DARK_SOURCE_PRESETS:
            if preset["key"] == preset_key:
                initial = dict(preset["initial"])
                break
    form = DarkSourceCreateForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        source = form.save()
        messages.success(request, f"Dark source '{source.name}' created.")
        return redirect("intel_admin:dark_sources")
    form_sections = _prepare_dark_source_form(form)
    return render(
        request,
        "intel/admin_panel/dark_source_form.html",
        {
            "page_title": "Create Dark Source",
            "current_page": "admin",
            "form": form,
            "form_sections": form_sections,
            "mode": "create",
            "cancel_url": reverse("intel_admin:dark_sources"),
            "presets": DARK_SOURCE_PRESETS,
            "selected_preset": preset_key,
        },
    )


@superuser_required
def admin_panel_dark_source_edit(request, source_id: int):
    source = get_object_or_404(DarkSource, id=source_id)
    form = DarkSourceEditForm(request.POST or None, instance=source)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, f"Dark source '{source.name}' updated.")
        return redirect("intel_admin:dark_sources")
    form_sections = _prepare_dark_source_form(form)
    return render(
        request,
        "intel/admin_panel/dark_source_form.html",
        {
            "page_title": "Edit Dark Source",
            "current_page": "admin",
            "form": form,
            "form_sections": form_sections,
            "mode": "edit",
            "source": source,
            "cancel_url": reverse("intel_admin:dark_sources"),
            "presets": DARK_SOURCE_PRESETS,
        },
    )


@superuser_required
@require_POST
def admin_panel_dark_source_toggle(request, source_id: int):
    source = get_object_or_404(DarkSource, id=source_id)
    source.enabled = not source.enabled
    source.save(update_fields=["enabled", "updated_at"])
    state = "enabled" if source.enabled else "disabled"
    messages.success(request, f"Dark source '{source.name}' {state}.")
    return redirect(
        _validated_redirect_target(request, reverse("intel_admin:dark_sources"))
    )


@superuser_required
@require_POST
def admin_panel_dark_source_delete(request, source_id: int):
    source = get_object_or_404(DarkSource, id=source_id)
    source_name = source.name
    source.delete()
    messages.success(request, f"Dark source '{source_name}' deleted.")
    return redirect(
        _validated_redirect_target(request, reverse("intel_admin:dark_sources"))
    )


@superuser_required
@require_POST
def admin_panel_dark_source_ingest(request, source_id: int):
    source = get_object_or_404(DarkSource, id=source_id)
    if not source.enabled:
        messages.error(request, f"Dark source '{source.name}' is disabled.")
        return redirect(
            _validated_redirect_target(request, reverse("intel_admin:dark_sources"))
        )

    try:
        job = _queue_custom_ops_job(
            command_name="ingest_dark",
            args=["--source", source.slug],
            requested_by=request.user,
            label="Dark ingest run",
        )
    except Exception as exc:
        messages.error(request, str(exc))
    else:
        messages.success(
            request,
            (
                f"Queued dark ingest for '{source.name}' as job #{job.id}. "
                f"Open Ops for full output."
            ),
        )
    return redirect(
        _validated_redirect_target(request, reverse("intel_admin:dark_sources"))
    )


@superuser_required
@require_POST
def admin_panel_dark_source_duplicate(request, source_id: int):
    source = get_object_or_404(DarkSource, id=source_id)
    duplicated = DarkSource.objects.create(
        name=_next_dark_copy_name(source.name),
        slug=_next_dark_copy_slug(source.slug),
        homepage=source.homepage,
        url=source.url,
        source_type=source.source_type,
        extractor_profile=source.extractor_profile,
        enabled=False,
        use_tor=source.use_tor,
        timeout_seconds=source.timeout_seconds,
        max_bytes=source.max_bytes,
        fetch_retries=source.fetch_retries,
        tags=list(source.tags or []),
        watch_keywords=source.watch_keywords,
        watch_regex=source.watch_regex,
    )
    messages.success(
        request,
        f"Duplicated '{source.name}' into '{duplicated.name}' (disabled by default).",
    )
    return redirect("intel_admin:dark_source_edit", source_id=duplicated.id)


@superuser_required
@require_POST
def admin_panel_dark_source_test(request, source_id: int):
    source = get_object_or_404(DarkSource, id=source_id)
    try:
        preview = _build_dark_source_preview(source)
    except Exception as exc:
        failure = _dark_preview_failure_info(exc)
        request.session["dark_source_test_preview"] = {
            "ok": False,
            "source_name": source.name,
            "source_id": source.id,
            "failure_reason": failure["reason"],
            "failure_detail": failure["detail"],
        }
        messages.error(request, f"Test failed for '{source.name}': {failure['reason']}")
    else:
        preview["ok"] = True
        request.session["dark_source_test_preview"] = preview
        messages.success(request, f"Test fetch succeeded for '{source.name}'.")
    return redirect(
        _validated_redirect_target(request, reverse("intel_admin:dark_sources"))
    )


@superuser_required
def admin_panel_source_create(request):
    form = SourceCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        source = form.save()
        messages.success(request, f"Source '{source.name}' created.")
        return redirect("intel_admin:sources")
    return render(
        request,
        "intel/admin_panel/source_form.html",
        {
            "page_title": "Create Source",
            "current_page": "admin",
            "form": form,
            "mode": "create",
            "cancel_url": reverse("intel_admin:sources"),
        },
    )


@superuser_required
def admin_panel_source_edit(request, source_id: int):
    source = get_object_or_404(Source, id=source_id)
    form = SourceEditForm(request.POST or None, instance=source)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, f"Source '{source.name}' updated.")
        return redirect("intel_admin:sources")
    return render(
        request,
        "intel/admin_panel/source_form.html",
        {
            "page_title": "Edit Source",
            "current_page": "admin",
            "form": form,
            "mode": "edit",
            "source": source,
            "cancel_url": reverse("intel_admin:sources"),
        },
    )


@superuser_required
@require_POST
def admin_panel_source_toggle(request, source_id: int):
    source = get_object_or_404(Source, id=source_id)
    source.enabled = not source.enabled
    source.save(update_fields=["enabled", "updated_at"])
    state = "enabled" if source.enabled else "disabled"
    messages.success(request, f"Source '{source.name}' {state}.")
    return redirect(
        _validated_redirect_target(request, reverse("intel_admin:sources"))
    )


@superuser_required
@require_POST
def admin_panel_source_delete(request, source_id: int):
    source = get_object_or_404(Source, id=source_id)
    source_name = source.name
    source.delete()
    messages.success(request, f"Source '{source_name}' deleted.")
    return redirect(
        _validated_redirect_target(request, reverse("intel_admin:sources"))
    )


@superuser_required
def admin_panel_feed_edit(request, feed_id: int):
    feed = get_object_or_404(Feed.objects.select_related("source"), id=feed_id)
    form = FeedEditForm(request.POST or None, instance=feed)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, f"Feed '{feed.name}' updated.")
        return redirect("intel_admin:panel")
    return render(
        request,
        "intel/admin_panel/feed_form.html",
        {
            "page_title": "Edit Feed",
            "current_page": "admin",
            "form": form,
            "mode": "edit",
            "feed": feed,
            "cancel_url": reverse("intel_admin:panel"),
        },
    )


@superuser_required
@require_POST
def admin_panel_feed_disable(request, feed_id: int):
    feed = get_object_or_404(Feed, id=feed_id)
    if feed.enabled:
        feed.enabled = False
        feed.save(update_fields=["enabled", "updated_at"])
        messages.success(request, f"Feed '{feed.name}' disabled.")
    else:
        messages.info(request, f"Feed '{feed.name}' is already disabled.")
    return redirect("intel_admin:panel")


@superuser_required
@require_POST
def admin_panel_feed_delete(request, feed_id: int):
    feed = get_object_or_404(Feed, id=feed_id)
    feed_name = feed.name
    feed.delete()
    messages.success(request, f"Feed '{feed_name}' deleted.")
    return redirect(
        _validated_redirect_target(request, reverse("intel_admin:panel"))
    )
