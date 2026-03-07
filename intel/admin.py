from django.contrib import admin

from .models import (
    DarkDocument,
    DarkFetchRun,
    DarkHit,
    DarkSnapshot,
    DarkSource,
    Feed,
    FetchRun,
    Item,
    OpsJob,
    Source,
)


@admin.register(Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "enabled", "created_at")
    list_filter = ("enabled",)
    search_fields = ("name", "slug")
    readonly_fields = ("created_at", "updated_at")


@admin.register(Feed)
class FeedAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "source",
        "feed_type",
        "adapter_key",
        "section",
        "expanded_collection",
        "enabled",
        "last_success_at",
    )
    list_filter = ("feed_type", "adapter_key", "section", "expanded_collection", "enabled")
    search_fields = ("name", "url", "source__name")
    readonly_fields = ("created_at", "updated_at", "last_success_at", "last_error")


@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ("title", "source", "feed", "external_id", "published_at", "created_at")
    list_filter = ("source", "feed__section")
    search_fields = ("title", "summary", "canonical_url", "stable_id", "external_id")
    readonly_fields = ("stable_id", "title_hash", "normalized_title", "created_at", "updated_at")


@admin.register(FetchRun)
class FetchRunAdmin(admin.ModelAdmin):
    list_display = (
        "feed",
        "started_at",
        "finished_at",
        "ok",
        "items_fetched",
        "items_stored",
        "items_new",
        "items_updated",
        "items_skipped_old",
        "items_skipped_invalid",
        "items_limited",
    )
    list_filter = ("ok",)
    search_fields = ("feed__name", "error")
    readonly_fields = ("started_at", "finished_at", "duration_ms")


@admin.register(OpsJob)
class OpsJobAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "command_name",
        "status",
        "requested_by",
        "created_at",
        "started_at",
        "finished_at",
    )
    list_filter = ("status", "command_name")
    search_fields = ("command_name", "requested_by__username", "stdout", "stderr", "error_summary")
    readonly_fields = (
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
        "stdout",
        "stderr",
        "error_summary",
    )


@admin.register(DarkSource)
class DarkSourceAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "source_type", "enabled", "use_tor", "created_at")
    list_filter = ("source_type", "enabled", "use_tor")
    search_fields = ("name", "slug", "url")
    readonly_fields = ("created_at", "updated_at")


@admin.register(DarkFetchRun)
class DarkFetchRunAdmin(admin.ModelAdmin):
    list_display = (
        "dark_source",
        "started_at",
        "ok",
        "http_status",
        "bytes_received",
        "documents_discovered",
        "documents_fetched",
        "hits_new",
        "hits_updated",
    )
    list_filter = ("ok",)
    search_fields = ("dark_source__name", "error", "final_url")
    readonly_fields = ("started_at", "finished_at", "duration_ms")


@admin.register(DarkDocument)
class DarkDocumentAdmin(admin.ModelAdmin):
    list_display = (
        "dark_source",
        "title",
        "canonical_url",
        "last_fetched_at",
        "last_http_status",
        "last_seen",
        "active",
    )
    list_filter = ("active", "dark_source")
    search_fields = ("title", "url", "canonical_url", "content_hash")
    readonly_fields = ("first_seen", "last_seen", "last_fetched_at")


@admin.register(DarkHit)
class DarkHitAdmin(admin.ModelAdmin):
    list_display = (
        "dark_source",
        "dark_document",
        "title",
        "detected_at",
        "last_seen_at",
    )
    list_filter = ("dark_source",)
    search_fields = ("title", "url", "content_hash")
    readonly_fields = ("detected_at", "last_seen_at")


@admin.register(DarkSnapshot)
class DarkSnapshotAdmin(admin.ModelAdmin):
    list_display = ("dark_document", "fetched_at", "content_hash")
    list_filter = ("dark_document__dark_source",)
    search_fields = ("dark_document__title", "content_hash")
    readonly_fields = ("fetched_at",)
