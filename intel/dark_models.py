from django.db import models
from django.utils import timezone


class DarkSource(models.Model):
    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=120, unique=True)
    homepage = models.URLField(blank=True)
    url = models.URLField(max_length=1500)
    enabled = models.BooleanField(default=True)
    tags = models.JSONField(default=list, blank=True)
    watch_keywords = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class DarkFetchRun(models.Model):
    dark_source = models.ForeignKey(
        DarkSource, on_delete=models.CASCADE, related_name="fetch_runs"
    )
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    ok = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    bytes_received = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"{self.dark_source.name} @ {self.started_at.isoformat()}"


class DarkHit(models.Model):
    dark_source = models.ForeignKey(
        DarkSource, on_delete=models.CASCADE, related_name="hits"
    )
    detected_at = models.DateTimeField(auto_now_add=True, db_index=True)
    matched_keywords = models.JSONField(default=list, blank=True)
    title = models.CharField(max_length=500)
    excerpt = models.TextField(blank=True)
    url = models.TextField()
    content_hash = models.CharField(max_length=64)
    raw = models.TextField(blank=True)

    class Meta:
        ordering = ["-detected_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["dark_source", "content_hash"],
                name="intel_darkhit_source_hash_uniq",
            )
        ]

    def __str__(self) -> str:
        return self.title
