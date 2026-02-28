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
    section = models.CharField(
        max_length=20,
        choices=Section.choices,
        default=Section.ADVISORIES,
    )
    enabled = models.BooleanField(default=True)
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
    items_new = models.PositiveIntegerField(default=0)
    items_updated = models.PositiveIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"{self.feed.name} @ {self.started_at.isoformat()}"


from .dark_models import DarkFetchRun, DarkHit, DarkSource  # noqa: E402,F401
