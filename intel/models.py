from django.conf import settings
from django.db import models
from django.db.models import Index
from django.utils import timezone

from .utils import build_stable_id, canonicalize_url, hash_title, normalize_title, sanitize_summary


class Source(models.Model):
    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=120, unique=True)
    homepage = models.URLField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class Feed(models.Model):
    class FeedType(models.TextChoices):
        RSS = "rss", "RSS"
        ATOM = "atom", "Atom"
        JSON = "json", "JSON"

    class Section(models.TextChoices):
        ACTIVE = "active", "Active"
        ADVISORIES = "advisories", "Advisories"
        RESEARCH = "research", "Research"
        SWEDEN = "sweden", "Sweden"

    source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name="feeds")
    name = models.CharField(max_length=160)
    url = models.URLField(unique=True)
    feed_type = models.CharField(max_length=20, choices=FeedType.choices, default=FeedType.RSS)
    adapter_key = models.CharField(max_length=64, blank=True, default="")
    section = models.CharField(
        max_length=20,
        choices=Section.choices,
        default=Section.ADVISORIES,
    )
    priority = models.PositiveSmallIntegerField(default=100)
    enabled = models.BooleanField(default=True)
    expanded_collection = models.BooleanField(default=False)
    expanded_max_items_per_run = models.PositiveIntegerField(null=True, blank=True)
    expanded_max_age_days = models.PositiveIntegerField(null=True, blank=True)
    timeout_seconds = models.PositiveSmallIntegerField(default=10)
    max_bytes = models.PositiveIntegerField(default=1_500_000)
    max_items_per_run = models.PositiveIntegerField(default=200)
    max_age_days = models.PositiveIntegerField(default=180)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["source__name", "name"]

    def __str__(self) -> str:
        return f"{self.source.name} / {self.name}"


class Item(models.Model):
    source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name="items")
    feed = models.ForeignKey(Feed, on_delete=models.CASCADE, related_name="items")
    title = models.CharField(max_length=1500)
    normalized_title = models.CharField(max_length=1500, blank=True)
    title_hash = models.CharField(max_length=64, db_index=True)
    external_id = models.CharField(max_length=255, blank=True, db_index=True)
    url = models.URLField(max_length=1500, blank=True)
    canonical_url = models.URLField(max_length=1500, blank=True, db_index=True)
    stable_id = models.CharField(max_length=64, unique=True)
    published_at = models.DateTimeField(default=timezone.now, db_index=True)
    summary = models.TextField(blank=True)
    raw_payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-published_at", "-id"]
        indexes = [
            Index(fields=["-published_at"], name="intel_item_pub_idx"),
            Index(fields=["source", "-published_at"], name="intel_item_src_pub_idx"),
        ]

    def save(self, *args, **kwargs):
        self.title = normalize_title(self.title)
        self.normalized_title = normalize_title(self.title)
        self.title_hash = hash_title(self.normalized_title)
        self.canonical_url = canonicalize_url(self.canonical_url or self.url)
        self.summary = sanitize_summary(self.summary)
        if not self.stable_id:
            self.stable_id = build_stable_id(
                feed_id=self.feed_id,
                canonical_url=self.canonical_url,
                normalized_title=self.normalized_title,
                published_at=self.published_at,
                external_id=self.external_id,
                summary=self.summary,
            )
        return super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.title


class FetchRun(models.Model):
    feed = models.ForeignKey(Feed, on_delete=models.CASCADE, related_name="fetch_runs")
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    ok = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    items_fetched = models.PositiveIntegerField(default=0)
    items_stored = models.PositiveIntegerField(default=0)
    items_skipped_old = models.PositiveIntegerField(default=0)
    items_skipped_invalid = models.PositiveIntegerField(default=0)
    items_deduped = models.PositiveIntegerField(default=0)
    items_limited = models.PositiveIntegerField(default=0)
    items_new = models.PositiveIntegerField(default=0)
    items_updated = models.PositiveIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"{self.feed.name} @ {self.started_at.isoformat()}"


class OpsJob(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    command_name = models.CharField(max_length=120)
    command_args = models.JSONField(default=list, blank=True)
    command_options = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
        db_index=True,
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ops_jobs",
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    stdout = models.TextField(blank=True)
    stderr = models.TextField(blank=True)
    error_summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.command_name} #{self.id} ({self.status})"


from .dark_models import (  # noqa: E402,F401
    DarkDocument,
    DarkFetchRun,
    DarkHit,
    DarkSnapshot,
    DarkSource,
)
