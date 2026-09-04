from datetime import datetime, timezone as datetime_timezone
from typing import TypedDict

from django.utils import timezone

from intel.classification import SignalProfile, classify_item
from intel.models import Item
from intel.ransomware_countries import normalize_ransomware_country


SIGNAL_SCHEMA_VERSION = "1"
RANSOMWARE_LIVE_ADAPTER = "ransomware_live_victims"


class PublishableClassification(TypedDict):
    active_exploitation: bool
    vulnerability: bool
    threat_news: bool
    ransomware: bool
    nordic: bool
    research: bool


class PublishableCountry(TypedDict):
    code: str
    name: str


class PublishableEntities(TypedDict):
    cves: list[str]
    countries: list[PublishableCountry]
    ransomware_actor: str | None
    ransomware_victim: str | None


class PublishableSource(TypedDict):
    slug: str
    name: str


class PublishableSignal(TypedDict):
    schema_version: str
    id: str
    kind: str
    title: str
    summary: str | None
    url: str | None
    published_at: str
    observed_at: str
    classified_at: str
    priority: str
    score: int
    classification: PublishableClassification
    entities: PublishableEntities
    source: PublishableSource


def format_utc_datetime(value: datetime) -> str:
    if timezone.is_naive(value):
        raise ValueError("API contract timestamps must be timezone-aware.")
    return value.astimezone(datetime_timezone.utc).isoformat().replace("+00:00", "Z")


def _optional_text(value) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _classification(profile: SignalProfile) -> PublishableClassification:
    return {
        "active_exploitation": profile.active_exploitation,
        "vulnerability": profile.vulnerability,
        "threat_news": profile.threat_news,
        "ransomware": profile.ransomware,
        "nordic": profile.nordic_relevance,
        "research": profile.research,
    }


def _countries(item: Item) -> list[PublishableCountry]:
    raw_payload = item.raw_payload if isinstance(item.raw_payload, dict) else {}
    country_value = raw_payload.get("country")
    if not isinstance(country_value, str):
        return []
    country = normalize_ransomware_country(country_value)
    if not country.recognized:
        return []
    countries: list[PublishableCountry] = [
        {
            "code": country.country_id,
            "name": country.display_name,
        }
    ]
    countries.sort(key=lambda value: (value["code"], value["name"]))
    return countries


def _ransomware_entities(item: Item) -> tuple[str | None, str | None]:
    if (item.feed.adapter_key or "").strip().lower() != RANSOMWARE_LIVE_ADAPTER:
        return None, None
    raw_payload = item.raw_payload if isinstance(item.raw_payload, dict) else {}
    return (
        _optional_text(raw_payload.get("group")),
        _optional_text(raw_payload.get("victim")),
    )


def build_publishable_signal(
    item: Item,
    *,
    classified_at: datetime | None = None,
) -> PublishableSignal:
    if not isinstance(item, Item):
        raise TypeError("Publishable signal input must be an Item instance.")
    if not item.stable_id or item.created_at is None or item.published_at is None:
        raise ValueError("Publishable signals require a saved Item with timestamps.")

    evaluation_time = classified_at or timezone.now()
    serialized_classified_at = format_utc_datetime(evaluation_time)
    profile = classify_item(item, now=evaluation_time)
    ransomware_actor, ransomware_victim = _ransomware_entities(item)

    return {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "id": f"intel:item:{item.stable_id}",
        "kind": profile.primary_category,
        "title": item.title,
        "summary": _optional_text(item.summary),
        "url": _optional_text(item.canonical_url),
        "published_at": format_utc_datetime(item.published_at),
        "observed_at": format_utc_datetime(item.created_at),
        "classified_at": serialized_classified_at,
        "priority": profile.priority,
        "score": profile.score,
        "classification": _classification(profile),
        "entities": {
            "cves": sorted(set(profile.cves)),
            "countries": _countries(item),
            "ransomware_actor": ransomware_actor,
            "ransomware_victim": ransomware_victim,
        },
        "source": {
            "slug": item.source.slug,
            "name": item.source.name,
        },
    }
