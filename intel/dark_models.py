from django.conf import settings
from django.db import models
from django.utils import timezone


class DarkSource(models.Model):
    class SourceType(models.TextChoices):
        SINGLE_PAGE = "single_page", "Single Page"
        INDEX_PAGE = "index_page", "Index Page"
        FEED = "feed", "RSS/Atom Feed"

    class ExtractorProfile(models.TextChoices):
        GENERIC_PAGE = "generic_page", "Generic Page"
        INCIDENT_CARDS = "incident_cards", "Incident Cards"
        GROUP_CARDS = "group_cards", "Group Cards"
        TABLE_ROWS = "table_rows", "Table Rows"

    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=120, unique=True)
    homepage = models.URLField(blank=True)
    url = models.URLField(max_length=1500)
    source_type = models.CharField(
        max_length=20, choices=SourceType.choices, default=SourceType.SINGLE_PAGE
    )
    extractor_profile = models.CharField(
        max_length=20,
        choices=ExtractorProfile.choices,
        default=ExtractorProfile.GENERIC_PAGE,
        help_text="How fetched pages should be turned into matchable records.",
    )
    enabled = models.BooleanField(default=True)
    use_tor = models.BooleanField(
        default=False,
        help_text="Force Tor even for clearnet sources. Onion URLs always use Tor.",
    )
    timeout_seconds = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="Optional per-source timeout override (seconds).",
    )
    max_bytes = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Optional per-source response size cap in bytes.",
    )
    fetch_retries = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        help_text="Optional per-source retry count override.",
    )
    tags = models.JSONField(default=list, blank=True)
    watch_keywords = models.TextField(blank=True)
    watch_regex = models.TextField(blank=True, help_text="One regex per line.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def effective_timeout_seconds(self) -> int:
        return int(self.timeout_seconds or settings.DARK_FETCH_TIMEOUT)

    def effective_max_bytes(self) -> int:
        return int(self.max_bytes or settings.DARK_MAX_BYTES)

    def effective_fetch_retries(self) -> int:
        return int(self.fetch_retries or settings.DARK_FETCH_RETRIES)


class DarkFetchRun(models.Model):
    dark_source = models.ForeignKey(
        DarkSource, on_delete=models.CASCADE, related_name="fetch_runs"
    )
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    ok = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    bytes_received = models.PositiveIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    final_url = models.TextField(blank=True)
    documents_discovered = models.PositiveIntegerField(default=0)
    documents_fetched = models.PositiveIntegerField(default=0)
    hits_new = models.PositiveIntegerField(default=0)
    hits_updated = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"{self.dark_source.name} @ {self.started_at.isoformat()}"


class DarkDocument(models.Model):
    dark_source = models.ForeignKey(
        DarkSource, on_delete=models.CASCADE, related_name="documents"
    )
    url = models.URLField(max_length=1500)
    canonical_url = models.URLField(max_length=1500, blank=True, db_index=True)
    title = models.CharField(max_length=500, blank=True)
    excerpt = models.TextField(blank=True)
    content_hash = models.CharField(max_length=64, db_index=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    last_fetched_at = models.DateTimeField(null=True, blank=True)
    last_http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-last_seen", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["dark_source", "canonical_url"],
                name="intel_darkdoc_source_canonical_uniq",
            ),
            models.UniqueConstraint(
                fields=["dark_source", "url"],
                name="intel_darkdoc_source_url_uniq",
            ),
        ]

    def __str__(self) -> str:
        return self.title or self.url


class DarkSnapshot(models.Model):
    dark_document = models.ForeignKey(
        DarkDocument, on_delete=models.CASCADE, related_name="snapshots"
    )
    fetched_at = models.DateTimeField(default=timezone.now, db_index=True)
    content_hash = models.CharField(max_length=64, db_index=True)
    title = models.CharField(max_length=500, blank=True)
    excerpt = models.TextField(blank=True)
    raw = models.TextField(blank=True)

    class Meta:
        ordering = ["-fetched_at", "-id"]

    def __str__(self) -> str:
        return f"{self.dark_document_id}:{self.content_hash[:12]}"


class DarkHit(models.Model):
    dark_source = models.ForeignKey(
        DarkSource, on_delete=models.CASCADE, related_name="hits"
    )
    dark_document = models.ForeignKey(
        DarkDocument, on_delete=models.CASCADE, related_name="hits", null=True, blank=True
    )
    detected_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen_at = models.DateTimeField(default=timezone.now)
    matched_keywords = models.JSONField(default=list, blank=True)
    matched_regex = models.JSONField(default=list, blank=True)
    record_type = models.CharField(max_length=32, blank=True, db_index=True)
    group_name = models.CharField(max_length=255, blank=True, db_index=True)
    victim_name = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=120, blank=True)
    industry = models.CharField(max_length=120, blank=True)
    website_url = models.URLField(max_length=1500, blank=True)
    victim_count = models.PositiveIntegerField(null=True, blank=True)
    last_activity_text = models.CharField(max_length=255, blank=True)
    title = models.CharField(max_length=500)
    excerpt = models.TextField(blank=True)
    url = models.TextField()
    content_hash = models.CharField(max_length=64)
    raw = models.TextField(blank=True)

    class Meta:
        ordering = ["-detected_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["dark_document", "content_hash"],
                name="intel_darkhit_doc_hash_uniq",
            )
        ]

    def __str__(self) -> str:
        return self.title
