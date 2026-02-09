from django.contrib import admin

from .models import Feed, FetchRun, Item, Source


@admin.register(Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "enabled", "created_at")
    list_filter = ("enabled",)
    search_fields = ("name", "slug")


@admin.register(Feed)
class FeedAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "source",
        "feed_type",
        "section",
        "enabled",
        "last_success_at",
    )
    list_filter = ("feed_type", "section", "enabled")
    search_fields = ("name", "url", "source__name")


@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ("title", "source", "published_at", "created_at")
    list_filter = ("source", "feed__section")
    search_fields = ("title", "summary", "canonical_url", "stable_id")


@admin.register(FetchRun)
class FetchRunAdmin(admin.ModelAdmin):
    list_display = (
        "feed",
        "started_at",
        "finished_at",
        "ok",
        "items_new",
        "items_updated",
    )
    list_filter = ("ok",)
    search_fields = ("feed__name", "error")
