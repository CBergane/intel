import re
from collections import Counter
from datetime import timedelta
from io import StringIO

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.forms import AuthenticationForm
from django.core.paginator import Paginator
from django.core.management import call_command
from django.db.models import Count, Max, Q
from django.db.models.functions import Coalesce
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import NoReverseMatch, reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils import timezone
from django.views.decorators.http import require_POST

from .forms import FeedCreateForm, FeedEditForm
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


def _is_superuser(user):
    return user.is_active and user.is_superuser


def superuser_required(view_func):
    return user_passes_test(_is_superuser, login_url="intel_admin:login")(view_func)


def _validated_next_url(request) -> str:
    raw = (request.POST.get("next") or request.GET.get("next") or "").strip()
    default_target = reverse("intel_admin:ops")
    if not raw:
        return default_target
    if url_has_allowed_host_and_scheme(
        raw,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ) and raw.startswith("/"):
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
    page_obj.object_list = _attach_item_meta(list(page_obj.object_list))

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

    context = {
        "page_title": "Now",
        "current_page": "now",
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


def _run_ops_command(request, *, command_name: str, args: list[str], label: str):
    output = StringIO()
    try:
        call_command(command_name, *args, stdout=output, stderr=output)
        text = output.getvalue().strip() or f"{label} completed."
        messages.success(request, f"{label} completed.\n{text[:8000]}")
    except Exception as exc:
        base = output.getvalue().strip()
        detail = f"{base}\n{exc}" if base else str(exc)
        messages.error(request, f"{label} failed.\n{detail[:8000]}")


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
        if latest_run is not None:
            if latest_run.ok:
                status = "ok"
            elif latest_run.error or feed.last_error:
                status = "error"
            else:
                status = "error"
            last_run_at = latest_run.finished_at or latest_run.started_at
        else:
            if feed.last_success_at is None:
                status = "never"
            elif feed.last_error:
                status = "error"
            else:
                status = "ok"
            last_run_at = None

        feed_rows.append(
            {
                "feed": feed,
                "latest_run": latest_run,
                "status": status,
                "last_run_at": last_run_at,
            }
        )
    return feed_rows


@superuser_required
def ops_dashboard(request):
    actions = {
        "ingest": ("ingest_sources", [], "Ingest run"),
        "prune": ("prune_items", [], "Prune run"),
        "prune_dry_run": ("prune_items", ["--dry-run"], "Prune dry-run"),
        "seed": ("seed_sources", [], "Seed run"),
    }

    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action in actions:
            command_name, args, label = actions[action]
            _run_ops_command(
                request,
                command_name=command_name,
                args=args,
                label=label,
            )
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
            "feed_list_url": feed_list_url,
            "admin_panel_url": reverse("intel_admin:panel"),
        },
    )


@superuser_required
def admin_panel_view(request):
    feeds = list(Feed.objects.select_related("source").order_by("source__name", "name"))
    feed_rows = _build_feed_rows(feeds)
    return render(
        request,
        "intel/admin_panel/feed_list.html",
        {
            "page_title": "Admin Panel",
            "current_page": "admin",
            "feed_rows": feed_rows,
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
