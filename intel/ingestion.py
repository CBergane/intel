import base64
import calendar
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit

import feedparser
import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone as django_timezone
from django.utils.dateparse import parse_datetime

from .models import Feed, Item
from .utils import build_stable_id, canonicalize_url, normalize_title, sanitize_summary

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NormalizedEntry:
    title: str
    url: str
    canonical_url: str
    published_at: datetime
    summary: str
    raw_payload: dict[str, Any]
    external_id: str = ""


def parse_entry_datetime(entry: dict[str, Any], *, fallback: datetime | None = None) -> datetime:
    for parsed_key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(parsed_key)
        if parsed is not None:
            return datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc)

    for text_key in (
        "published",
        "updated",
        "created",
        "published_at",
        "updated_at",
        "date",
        "pubDate",
        "issued",
    ):
        raw = entry.get(text_key)
        if not raw:
            continue
        parsed_dt = _parse_datetime_value(raw)
        if parsed_dt is None:
            continue
        return parsed_dt

    if fallback is not None:
        if django_timezone.is_naive(fallback):
            fallback = django_timezone.make_aware(fallback, timezone.utc)
        return fallback.astimezone(timezone.utc)
    return django_timezone.now()


def _parse_datetime_value(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed_dt = value
    elif isinstance(value, (int, float)):
        parsed_dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        raw = str(value).strip()
        if not raw:
            return None
        parsed_dt = parse_datetime(raw)
        if parsed_dt is None:
            try:
                parsed_dt = parsedate_to_datetime(raw)
            except (TypeError, ValueError):
                return None

    if django_timezone.is_naive(parsed_dt):
        parsed_dt = django_timezone.make_aware(parsed_dt, timezone.utc)
    return parsed_dt.astimezone(timezone.utc)


def extract_entry_url(entry: dict[str, Any], *, feed_url: str = "", source_homepage: str = "") -> str:
    candidates: list[str] = []
    for key in ("link", "url", "canonical_url", "id", "guid", "permalink"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())

    links = entry.get("links")
    if isinstance(links, list):
        alternate = []
        for link in links:
            if not isinstance(link, dict):
                continue
            href = (link.get("href") or "").strip()
            if not href:
                continue
            rel = (link.get("rel") or "").strip().lower()
            if rel == "alternate":
                alternate.append(href)
            else:
                candidates.append(href)
        candidates = alternate + candidates

    for candidate in candidates:
        canonical = canonicalize_url(candidate)
        if not canonical:
            continue
        if not _looks_like_web_url(canonical):
            continue
        return canonical

    fallback_candidates = [canonicalize_url(feed_url), canonicalize_url(source_homepage)]
    for fallback in fallback_candidates:
        if fallback and _looks_like_web_url(fallback):
            return fallback
    return ""


def _looks_like_web_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


def is_low_quality_url(url: str, *, feed_url: str = "", source_homepage: str = "") -> bool:
    canonical = canonicalize_url(url)
    if not canonical:
        return True

    if not _looks_like_web_url(canonical):
        return True

    if canonical in {canonicalize_url(feed_url), canonicalize_url(source_homepage)}:
        return True

    try:
        parts = urlsplit(canonical)
    except ValueError:
        return True
    if (parts.path or "/") == "/" and not parts.query:
        return True
    return False


def normalize_syndication_entry(
    feed: Feed, entry: dict[str, Any], *, fallback_published_at: datetime
) -> NormalizedEntry:
    title = normalize_title(entry.get("title") or entry.get("id") or "Untitled")
    external_id = normalize_title(str(entry.get("id") or entry.get("guid") or ""))
    url = extract_entry_url(
        entry,
        feed_url=feed.url,
        source_homepage=feed.source.homepage,
    )
    canonical_url = canonicalize_url(url)
    summary = sanitize_summary(_extract_summary(entry))
    published_at = parse_entry_datetime(entry, fallback=fallback_published_at)
    raw_payload = {
        "id": entry.get("id") or entry.get("guid"),
        "title": entry.get("title"),
        "link": entry.get("link"),
        "links": entry.get("links"),
        "published": entry.get("published") or entry.get("updated"),
        "summary": entry.get("summary") or entry.get("description"),
    }
    return NormalizedEntry(
        title=title,
        url=url,
        canonical_url=canonical_url,
        published_at=published_at,
        summary=summary,
        raw_payload=raw_payload,
        external_id=external_id,
    )


def _extract_summary(entry: dict[str, Any]) -> str:
    summary = entry.get("summary") or entry.get("description")
    if summary:
        return str(summary)
    content = entry.get("content")
    if isinstance(content, list):
        for row in content:
            if isinstance(row, dict) and row.get("value"):
                return str(row.get("value"))
    return ""


def parse_feed_payload(feed: Feed, payload: bytes, *, fetched_at: datetime) -> list[NormalizedEntry]:
    if feed.feed_type in {Feed.FeedType.RSS, Feed.FeedType.ATOM}:
        parsed = feedparser.parse(payload)
        if getattr(parsed, "bozo", False) and getattr(parsed, "entries", None) is None:
            raise ValueError(f"Invalid feed payload: {parsed.bozo_exception}")
        return [
            normalize_syndication_entry(feed, entry, fallback_published_at=fetched_at)
            for entry in parsed.entries
        ]

    if feed.feed_type == Feed.FeedType.JSON:
        return parse_json_payload(feed, payload, fetched_at=fetched_at)

    raise ValueError(f"Unsupported feed type: {feed.feed_type}")


def parse_json_payload(feed: Feed, payload: bytes, *, fetched_at: datetime) -> list[NormalizedEntry]:
    try:
        parsed = json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON payload: {exc}") from exc

    adapter_key = (feed.adapter_key or "").strip().lower() or _infer_json_adapter(feed)
    if adapter_key == "cisa_kev":
        return _parse_cisa_kev(feed, parsed, fetched_at=fetched_at)
    if adapter_key == "epss":
        return _parse_epss(feed, parsed, fetched_at=fetched_at)
    if adapter_key == "ransomware_live_victims":
        return _parse_ransomware_live_victims(feed, parsed, fetched_at=fetched_at)
    if adapter_key == "psbdmp":
        return _parse_psbdmp(feed, parsed, fetched_at=fetched_at)

    return _parse_generic_json_entries(feed, parsed, fetched_at=fetched_at)


def _infer_json_adapter(feed: Feed) -> str:
    if "known_exploited_vulnerabilities" in feed.url.lower() or "kev" in feed.name.lower():
        return "cisa_kev"
    return "generic_json"


def _parse_cisa_kev(feed: Feed, payload: Any, *, fetched_at: datetime) -> list[NormalizedEntry]:
    if not isinstance(payload, dict):
        raise ValueError("CISA KEV payload must be an object.")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV payload missing vulnerabilities list.")

    results: list[NormalizedEntry] = []
    feed_page = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        cve_id = normalize_title(str(vuln.get("cveID") or vuln.get("cveId") or ""))
        vendor = normalize_title(str(vuln.get("vendorProject") or "")).strip()
        product = normalize_title(str(vuln.get("product") or "")).strip()
        title_bits = [part for part in (cve_id, vendor, product) if part]
        title = " - ".join(title_bits) if title_bits else "CISA KEV Entry"
        if cve_id:
            url = f"{feed_page}?cve={cve_id}"
        else:
            url = feed_page
        canonical_url = canonicalize_url(url)

        summary_parts = [
            f"Ransomware use: {vuln.get('knownRansomwareCampaignUse') or 'Unknown'}",
            f"Action: {vuln.get('requiredAction') or 'n/a'}",
            f"Notes: {vuln.get('notes') or 'n/a'}",
        ]
        published_at = parse_entry_datetime(
            {
                "published": vuln.get("dateAdded") or vuln.get("dueDate"),
                "updated": payload.get("dateReleased"),
            },
            fallback=fetched_at,
        )
        results.append(
            NormalizedEntry(
                title=normalize_title(title) or "CISA KEV Entry",
                url=url,
                canonical_url=canonical_url,
                published_at=published_at,
                summary=sanitize_summary(" | ".join(summary_parts)),
                raw_payload=vuln,
                external_id=cve_id,
            )
        )
    return results


def _parse_epss(feed: Feed, payload: Any, *, fetched_at: datetime) -> list[NormalizedEntry]:
    if not isinstance(payload, dict):
        raise ValueError("EPSS payload must be an object.")
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError("EPSS payload missing data list.")

    min_score = getattr(settings, "EPSS_MIN_SCORE", 0.1)
    results: list[NormalizedEntry] = []
    skipped = 0
    for entry in data:
        if not isinstance(entry, dict):
            continue
        try:
            epss_score = float(entry.get("epss", 0))
        except (TypeError, ValueError):
            continue
        if epss_score < min_score:
            skipped += 1
            continue

        cve_id = str(entry.get("cve") or "").strip()
        if not cve_id:
            continue

        try:
            percentile = float(entry.get("percentile", 0))
        except (TypeError, ValueError):
            percentile = 0.0

        title = f"{cve_id} \u2014 EPSS {epss_score:.1%}"
        url = f"https://www.cve.org/CVERecord?id={cve_id}"
        canonical_url = canonicalize_url(url)
        summary = sanitize_summary(
            f"EPSS score: {epss_score:.1%} (percentile: {percentile:.1%}). "
            "High likelihood of exploitation in the wild within 30 days."
        )

        date_raw = entry.get("date")
        if date_raw:
            try:
                published_at = datetime.fromisoformat(str(date_raw)).replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                published_at = django_timezone.now()
        else:
            published_at = django_timezone.now()

        results.append(
            NormalizedEntry(
                title=title,
                url=url,
                canonical_url=canonical_url,
                published_at=published_at,
                summary=summary,
                raw_payload={
                    "cve": cve_id,
                    "epss": str(entry.get("epss")),
                    "percentile": str(entry.get("percentile")),
                    "date": date_raw,
                },
                external_id=cve_id,
            )
        )

    logger.info(
        "EPSS adapter: %d entries parsed, %d below min_score (%.2f) filtered out.",
        len(results),
        skipped,
        min_score,
    )
    return results


_NORDIC_COUNTRY_TOKENS = {
    "SWEDEN",
    "NORWAY",
    "DENMARK",
    "FINLAND",
    "ICELAND",
    "SE",
    "NO",
    "DK",
    "FI",
    "IS",
}
_NORDIC_TLDS = {".se", ".no", ".dk", ".fi", ".is"}


def _is_nordic_victim(offer: dict) -> bool:
    country = str(offer.get("country") or "").strip().upper()
    if country in _NORDIC_COUNTRY_TOKENS:
        return True
    victim = str(offer.get("victim") or "").lower()
    return any(victim.endswith(tld) for tld in _NORDIC_TLDS)


def _parse_ransomware_live_victims(
    feed: Feed, payload: Any, *, fetched_at: datetime
) -> list[NormalizedEntry]:
    if not isinstance(payload, list):
        raise ValueError("ransomware.live victims payload must be a list.")

    nordics_only = getattr(settings, "RANSOMWARE_LIVE_NORDICS_ONLY", True)
    results: list[NormalizedEntry] = []
    skipped = 0

    for offer in payload:
        if not isinstance(offer, dict):
            continue

        if nordics_only and not _is_nordic_victim(offer):
            skipped += 1
            continue

        victim = str(offer.get("victim") or "").strip()
        group = str(offer.get("group") or "").strip()
        if not victim or not group:
            continue

        title = f"{group.title()}: {victim}"
        victim_token = base64.b64encode(f"{victim}@{group}".encode("utf-8")).decode("ascii")
        url = f"https://www.ransomware.live/id/{victim_token}"
        canonical_url = canonicalize_url(url)
        external_id = f"{group}:{victim}"
        summary = sanitize_summary(str(offer.get("description") or "")[:500])

        discovered = offer.get("discovered")
        if discovered:
            try:
                published_at = datetime.fromisoformat(str(discovered))
                if django_timezone.is_naive(published_at):
                    published_at = django_timezone.make_aware(published_at, timezone.utc)
            except (TypeError, ValueError):
                published_at = fetched_at
        else:
            published_at = fetched_at

        results.append(
            NormalizedEntry(
                title=title,
                url=url,
                canonical_url=canonical_url,
                published_at=published_at,
                summary=summary,
                raw_payload={
                    "victim": victim,
                    "group": group,
                    "country": offer.get("country"),
                    "discovered": discovered,
                    "description": offer.get("description"),
                },
                external_id=external_id,
            )
        )

    logger.info(
        "ransomware.live adapter: %d nordic victims parsed, %d non-nordic filtered out.",
        len(results),
        skipped,
    )
    return results


_CREDENTIAL_KEYWORDS = frozenset({"password", "passwd", "credential", "credentials", "apikey", "api_key", "secret"})


def _looks_like_credentials(text: str) -> bool:
    if "@" in text:
        return True
    lower = text.lower()
    return any(kw in lower for kw in _CREDENTIAL_KEYWORDS)


def _parse_psbdmp(feed: Feed, payload: Any, *, fetched_at: datetime) -> list[NormalizedEntry]:
    queries_raw = getattr(settings, "PSBDMP_QUERIES", ".se password,.se credentials,sweden leak")
    queries = [q.strip() for q in queries_raw.split(",") if q.strip()]

    # Accumulate paste objects; start with the initial payload (from the feed URL fetch)
    all_pastes: list[dict] = []
    if isinstance(payload, list):
        all_pastes.extend(p for p in payload if isinstance(p, dict))

    # Fetch additional queries defined in settings
    timeout = getattr(settings, "INTEL_FETCH_TIMEOUT", 10)
    ua = getattr(settings, "INTEL_USER_AGENT", "borealsec-intel-bot/0.1")
    for query in queries:
        encoded = query.replace(" ", "+")
        url = f"https://psbdmp.ws/api/v3/search/{encoded}"
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": ua})
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                all_pastes.extend(p for p in data if isinstance(p, dict))
        except Exception as exc:
            logger.warning("psbdmp query %r failed: %s", query, exc)

    seen_ids: set[str] = set()
    results: list[NormalizedEntry] = []

    for paste in all_pastes:
        paste_id = str(paste.get("id") or "").strip()
        if not paste_id or paste_id in seen_ids:
            continue
        seen_ids.add(paste_id)

        tags = str(paste.get("tags") or "")
        paste_url = f"https://psbdmp.ws/{paste_id}"
        canonical_url = canonicalize_url(paste_url)

        tag_display = tags[:120] if tags else "paste"
        title = normalize_title(f"Paste {paste_id}: {tag_display}")

        time_raw = paste.get("time")
        if time_raw:
            try:
                published_at = datetime.fromtimestamp(int(time_raw), tz=timezone.utc)
            except (TypeError, ValueError):
                published_at = fetched_at
        else:
            published_at = fetched_at

        results.append(
            NormalizedEntry(
                title=title,
                url=paste_url,
                canonical_url=canonical_url,
                published_at=published_at,
                summary=sanitize_summary(tags[:500]),
                raw_payload=paste,
                external_id=paste_id,
            )
        )

    logger.info("psbdmp adapter: %d pastes collected across queries.", len(results))
    return results


def _parse_generic_json_entries(feed: Feed, payload: Any, *, fetched_at: datetime) -> list[NormalizedEntry]:
    items: list[dict[str, Any]]
    if isinstance(payload, list):
        items = [row for row in payload if isinstance(row, dict)]
    elif isinstance(payload, dict):
        candidate = payload.get("items") or payload.get("entries") or payload.get("data")
        if isinstance(candidate, list):
            items = [row for row in candidate if isinstance(row, dict)]
        else:
            items = [payload]
    else:
        raise ValueError("Unsupported JSON payload shape.")

    normalized: list[NormalizedEntry] = []
    for row in items:
        title = normalize_title(
            str(
                row.get("title")
                or row.get("name")
                or row.get("headline")
                or row.get("id")
                or "Untitled"
            )
        )
        external_id = normalize_title(str(row.get("id") or row.get("guid") or ""))
        url = extract_entry_url(
            row,
            feed_url=feed.url,
            source_homepage=feed.source.homepage,
        )
        canonical_url = canonicalize_url(url)
        summary = sanitize_summary(
            str(
                row.get("summary")
                or row.get("description")
                or row.get("content")
                or row.get("body")
                or ""
            )
        )
        published_at = parse_entry_datetime(
            {
                "published": row.get("published")
                or row.get("published_at")
                or row.get("date"),
                "updated": row.get("updated") or row.get("updated_at"),
            },
            fallback=fetched_at,
        )
        normalized.append(
            NormalizedEntry(
                title=title,
                url=url,
                canonical_url=canonical_url,
                published_at=published_at,
                summary=summary,
                raw_payload=row,
                external_id=external_id,
            )
        )
    return normalized


def is_valid_normalized_entry(entry: NormalizedEntry, *, feed: Feed | None = None) -> bool:
    title = normalize_title(entry.title)
    if title and title.lower() != "untitled":
        return True
    if entry.external_id:
        return True
    feed_url = feed.url if feed is not None else ""
    source_homepage = feed.source.homepage if feed is not None else ""
    if entry.canonical_url and not is_low_quality_url(
        entry.canonical_url,
        feed_url=feed_url,
        source_homepage=source_homepage,
    ):
        return True
    return False


def upsert_normalized_item(feed: Feed, entry: NormalizedEntry):
    title = normalize_title(entry.title or "Untitled")
    url = (entry.url or "").strip()
    canonical_url = canonicalize_url(entry.canonical_url or url)
    external_id = normalize_title(entry.external_id or "")
    summary = sanitize_summary(entry.summary or "")
    published_at = entry.published_at
    if django_timezone.is_naive(published_at):
        published_at = django_timezone.make_aware(published_at, timezone.utc)
    published_at = published_at.astimezone(timezone.utc)

    canonical_for_dedupe = ""
    if canonical_url and not is_low_quality_url(
        canonical_url,
        feed_url=feed.url,
        source_homepage=feed.source.homepage,
    ):
        canonical_for_dedupe = canonical_url

    stable_id = build_stable_id(
        feed_id=feed.id,
        canonical_url=canonical_for_dedupe,
        normalized_title=title,
        published_at=published_at,
        external_id=external_id,
        summary=summary,
    )

    raw_payload = dict(entry.raw_payload or {})
    if external_id and not raw_payload.get("id"):
        raw_payload["id"] = external_id

    with transaction.atomic():
        existing = None
        if external_id:
            existing = (
                Item.objects.select_for_update()
                .filter(feed=feed, external_id=external_id)
                .first()
            )
        if existing is None and canonical_for_dedupe:
            existing = (
                Item.objects.select_for_update()
                .filter(canonical_url=canonical_for_dedupe)
                .first()
            )
        if existing is None:
            existing = Item.objects.select_for_update().filter(stable_id=stable_id).first()

        if existing is not None:
            existing.source = feed.source
            existing.feed = feed
            existing.title = title
            existing.external_id = external_id
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
            external_id=external_id,
            url=url,
            canonical_url=canonical_url,
            summary=summary,
            published_at=published_at,
            stable_id=stable_id,
            raw_payload=raw_payload,
        )
        return created, True


def upsert_item(feed, entry: dict[str, Any], *, published_at: datetime | None = None):
    normalized = normalize_syndication_entry(
        feed, entry, fallback_published_at=published_at or django_timezone.now()
    )
    if published_at is not None:
        normalized.published_at = parse_entry_datetime(
            {"published": published_at}, fallback=published_at
        )
    return upsert_normalized_item(feed, normalized)
