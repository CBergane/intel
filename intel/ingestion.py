import calendar
from datetime import datetime, timezone
from typing import Any

from django.db import transaction
from django.utils import timezone as django_timezone
from django.utils.dateparse import parse_datetime

from .models import Item
from .utils import build_stable_id, canonicalize_url, normalize_title, sanitize_summary


def parse_entry_datetime(entry: dict[str, Any], *, fallback: datetime | None = None) -> datetime:
    for parsed_key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(parsed_key)
        if parsed is not None:
            return datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc)

    for text_key in ("published", "updated"):
        raw = entry.get(text_key)
        if not raw:
            continue
        parsed_dt = parse_datetime(raw)
        if parsed_dt is None:
            continue
        if django_timezone.is_naive(parsed_dt):
            parsed_dt = django_timezone.make_aware(parsed_dt, timezone.utc)
        return parsed_dt.astimezone(timezone.utc)

    if fallback is not None:
        if django_timezone.is_naive(fallback):
            fallback = django_timezone.make_aware(fallback, timezone.utc)
        return fallback.astimezone(timezone.utc)
    return django_timezone.now()


def upsert_item(feed, entry: dict[str, Any], *, published_at: datetime | None = None):
    title = normalize_title(entry.get("title") or "Untitled")
    url = (entry.get("link") or "").strip()
    canonical_url = canonicalize_url(url)
    summary = sanitize_summary(entry.get("summary") or entry.get("description") or "")
    if published_at is None:
        published_at = parse_entry_datetime(entry)

    stable_id = build_stable_id(
        feed_id=feed.id,
        canonical_url=canonical_url,
        normalized_title=title,
        published_at=published_at,
    )

    raw_payload = {
        "id": entry.get("id"),
        "title": entry.get("title"),
        "link": url,
        "published": entry.get("published") or entry.get("updated"),
        "summary": entry.get("summary") or entry.get("description"),
    }

    with transaction.atomic():
        existing = None
        if canonical_url:
            existing = (
                Item.objects.select_for_update().filter(canonical_url=canonical_url).first()
            )
        if existing is None:
            existing = Item.objects.select_for_update().filter(stable_id=stable_id).first()

        if existing is not None:
            existing.source = feed.source
            existing.feed = feed
            existing.title = title
            existing.url = url
            existing.canonical_url = canonical_url
            existing.summary = summary
            existing.published_at = published_at
            existing.raw_payload = raw_payload
            existing.save()
            return existing, False

        created = Item.objects.create(
            source=feed.source,
            feed=feed,
            title=title,
            url=url,
            canonical_url=canonical_url,
            summary=summary,
            published_at=published_at,
            stable_id=stable_id,
            raw_payload=raw_payload,
        )
        return created, True
