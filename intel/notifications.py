from __future__ import annotations

import hashlib
import logging
import re
from datetime import timedelta
from typing import TYPE_CHECKING

import requests
from django.conf import settings
from django.utils import timezone

from intel.dark_utils import evaluate_record_watch_matches, normalize_text

if TYPE_CHECKING:
    from intel.models import DarkHit, Item

logger = logging.getLogger(__name__)
DARK_HIT_ALERT_COOLDOWN = timedelta(hours=24)

MATCH_FIELD_LABELS = {
    "title": "title",
    "victim_name": "victim",
    "group_name": "group",
    "country": "country",
    "industry": "industry",
    "website_url": "website",
    "last_activity_text": "last activity",
    "details": "details",
}
RELATIVE_TIME_RE = re.compile(r"\b\d+\s+(?:minute|minutes|hour|hours|day|days)\s+ago\b", re.IGNORECASE)


def _normalized_dark_alert_list(values) -> list[str]:
    normalized = []
    for value in values or []:
        cleaned = normalize_text(str(value)).lower()
        if cleaned:
            normalized.append(cleaned)
    return sorted(dict.fromkeys(normalized))


def _normalized_dark_alert_excerpt(value: str) -> str:
    cleaned = normalize_text(value)
    cleaned = RELATIVE_TIME_RE.sub("", cleaned)
    return normalize_text(cleaned).lower()


def build_dark_hit_alert_identity(
    *,
    source_id: int | None = None,
    record_type: str = "",
    title: str = "",
    victim_name: str = "",
    group_name: str = "",
    url: str = "",
) -> str:
    stable_entity = normalize_text(victim_name or group_name or title).lower()
    fallback_url = normalize_text(url).lower()
    payload = "\n".join(
        part
        for part in (
            str(source_id or ""),
            normalize_text(record_type).lower() or "page",
            stable_entity or fallback_url,
        )
        if part
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_dark_hit_alert_fingerprint(
    *,
    record_type: str = "",
    title: str = "",
    excerpt: str = "",
    victim_name: str = "",
    group_name: str = "",
    country: str = "",
    industry: str = "",
    website_url: str = "",
    url: str = "",
    matched_keywords=None,
    matched_regex=None,
) -> str:
    payload = "\n".join(
        [
            normalize_text(record_type).lower(),
            normalize_text(title).lower(),
            normalize_text(victim_name).lower(),
            normalize_text(group_name).lower(),
            normalize_text(country).lower(),
            normalize_text(industry).lower(),
            normalize_text(website_url).lower(),
            normalize_text(url).lower(),
            _normalized_dark_alert_excerpt(excerpt),
            "|".join(_normalized_dark_alert_list(matched_keywords)),
            "|".join(_normalized_dark_alert_list(matched_regex)),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def dark_hit_alert_reason(
    previous_hit: DarkHit | None,
    *,
    record_values: dict,
    keyword_matches: list[str],
    regex_matches: list[str],
) -> str:
    if previous_hit is None or not previous_hit.last_alerted_at:
        return "new finding"
    if not previous_hit.is_watch_match:
        return "new watch match"

    previous_keywords = _normalized_dark_alert_list(previous_hit.matched_keywords)
    current_keywords = _normalized_dark_alert_list(keyword_matches)
    if previous_keywords != current_keywords:
        added_keywords = [value for value in current_keywords if value not in previous_keywords]
        if len(added_keywords) == 1:
            return f"{added_keywords[0].title()} keyword match"
        return "keywords changed"

    previous_regex = _normalized_dark_alert_list(previous_hit.matched_regex)
    current_regex = _normalized_dark_alert_list(regex_matches)
    if previous_regex != current_regex:
        return "regex changed"

    if normalize_text(previous_hit.group_name).lower() != normalize_text(record_values["group_name"]).lower():
        return "threat group changed"
    if normalize_text(previous_hit.country).lower() != normalize_text(record_values["country"]).lower():
        return "country changed"
    if normalize_text(previous_hit.industry).lower() != normalize_text(record_values["industry"]).lower():
        return "industry changed"
    if normalize_text(previous_hit.url).lower() != normalize_text(record_values["url"]).lower():
        return "URL changed"

    previous_entity = normalize_text(
        previous_hit.victim_name or previous_hit.group_name or previous_hit.title
    ).lower()
    current_entity = normalize_text(
        record_values["victim_name"] or record_values["group_name"] or record_values["title"]
    ).lower()
    if previous_entity != current_entity or normalize_text(previous_hit.title).lower() != normalize_text(
        record_values["title"]
    ).lower():
        return "entity changed"
    if normalize_text(previous_hit.website_url).lower() != normalize_text(record_values["website_url"]).lower():
        return "website changed"
    if _normalized_dark_alert_excerpt(previous_hit.excerpt) != _normalized_dark_alert_excerpt(
        record_values["excerpt"]
    ):
        return "details changed"
    return "meaningful change"


def should_emit_dark_hit_alert(
    *,
    is_watch_match: bool,
    record_type: str,
    current_alert_fingerprint: str,
    previous_alert_hit: DarkHit | None,
) -> bool:
    if not is_watch_match:
        return False
    if (record_type or "").strip().lower() in {"group", "table_row"}:
        return False
    if previous_alert_hit is None:
        return True
    if previous_alert_hit.last_alert_fingerprint == current_alert_fingerprint:
        if previous_alert_hit.last_alerted_at and (
            timezone.now() - previous_alert_hit.last_alerted_at
        ) < DARK_HIT_ALERT_COOLDOWN:
            return False
        return False
    return True


def should_send_dark_hit_alert(hit: DarkHit) -> bool:
    if not hit.is_watch_match:
        return False
    record_type = (hit.record_type or "").strip().lower()
    if record_type in {"group", "table_row"}:
        return False
    return True


def _matched_dark_hit_fields(hit: DarkHit, matched_fields: list[str] | None) -> list[str]:
    if matched_fields is not None:
        return matched_fields
    match_result = evaluate_record_watch_matches(
        raw_keywords=", ".join(hit.matched_keywords or []),
        raw_regex="\n".join(hit.matched_regex or []),
        title=hit.title,
        excerpt=hit.excerpt,
        victim_name=hit.victim_name,
        group_name=hit.group_name,
        country=hit.country,
        industry=hit.industry,
        website_url=hit.website_url,
        last_activity_text=hit.last_activity_text,
    )
    return match_result.fields


def send_dark_hit_alert(
    hit: DarkHit,
    *,
    matched_fields: list[str] | None = None,
    why_alerted: str | None = None,
) -> None:
    webhook = getattr(settings, "DARK_DISCORD_WEBHOOK", "")
    if not webhook:
        logger.debug("DARK_DISCORD_WEBHOOK not configured, skipping dark hit alert.")
        return
    if not should_send_dark_hit_alert(hit):
        logger.debug(
            "Skipping dark hit alert for non-operational record_type=%s",
            hit.record_type or "(blank)",
        )
        return

    keywords = hit.matched_keywords
    if isinstance(keywords, list):
        keywords_str = ", ".join(str(k) for k in keywords) if keywords else "(none)"
    else:
        keywords_str = str(keywords) if keywords else "(none)"

    regex_matches = hit.matched_regex or []
    if isinstance(regex_matches, list):
        regex_str = ", ".join(str(pattern) for pattern in regex_matches) if regex_matches else "(none)"
    else:
        regex_str = str(regex_matches) if regex_matches else "(none)"
    matched_field_labels = [
        MATCH_FIELD_LABELS.get(field_name, field_name.replace("_", " "))
        for field_name in _matched_dark_hit_fields(hit, matched_fields)
    ]
    matched_fields_str = ", ".join(matched_field_labels) if matched_field_labels else "(unknown)"

    payload = {
        "embeds": [
            {
                "title": (hit.title or "")[:256],
                "description": (hit.excerpt[:300] if hit.excerpt else "(no excerpt)"),
                "color": 0xFF4444,
                "fields": [
                    {
                        "name": "Source",
                        "value": hit.dark_source.name,
                        "inline": True,
                    },
                    {
                        "name": "Keywords matched",
                        "value": keywords_str,
                        "inline": True,
                    },
                    {
                        "name": "Regex matched",
                        "value": regex_str,
                        "inline": True,
                    },
                    {
                        "name": "Matched in",
                        "value": matched_fields_str,
                        "inline": True,
                    },
                    *(
                        [
                            {
                                "name": "Why alerted",
                                "value": why_alerted[:200],
                                "inline": True,
                            }
                        ]
                        if why_alerted
                        else []
                    ),
                    {
                        "name": "URL",
                        "value": "dark source (onion)",
                        "inline": False,
                    },
                    {
                        "name": "Detected",
                        "value": str(hit.detected_at),
                        "inline": True,
                    },
                ],
                "footer": {"text": "borealsec-intel \u00b7 dark monitor"},
            }
        ]
    }

    logger.debug("Sending dark hit alert")
    try:
        requests.post(webhook, json=payload, timeout=10)
    except requests.RequestException as e:
        logger.warning("Discord alert failed: %s", e)


def send_high_epss_alert(item: Item) -> None:
    webhook = getattr(settings, "INTEL_DISCORD_WEBHOOK", "") or getattr(
        settings, "DARK_DISCORD_WEBHOOK", ""
    )
    if not webhook:
        return

    match = re.search(r"EPSS (\d+\.?\d*)%", item.title or "")
    if not match:
        return

    score = float(match.group(1)) / 100
    threshold = getattr(settings, "EPSS_ALERT_THRESHOLD", 0.7)
    if score < threshold:
        return

    payload = {
        "embeds": [
            {
                "title": f"High EPSS: {(item.title or '')[:200]}",
                "description": (item.summary[:300] if item.summary else "(no summary)"),
                "color": 0xFF8C00,
                "fields": [
                    {
                        "name": "EPSS Score",
                        "value": f"{score:.1%}",
                        "inline": True,
                    },
                    {
                        "name": "Source",
                        "value": item.source.name,
                        "inline": True,
                    },
                    {
                        "name": "Link",
                        "value": (item.url[:500] if item.url else "(no link)"),
                        "inline": False,
                    },
                ],
                "footer": {"text": "borealsec-intel \u00b7 EPSS monitor"},
            }
        ]
    }

    try:
        requests.post(webhook, json=payload, timeout=10)
    except requests.RequestException as e:
        logger.warning("Discord alert failed: %s", e)


def send_ransomware_victim_alert(item: Item) -> None:
    # Primary: DARK_DISCORD_WEBHOOK (urgent intel); fallback: INTEL_DISCORD_WEBHOOK
    webhook = getattr(settings, "INTEL_DISCORD_WEBHOOK", "") or getattr(
        settings, "DARK_DISCORD_WEBHOOK", ""
    )
    if not webhook:
        return

    raw = item.raw_payload or {}
    victim = str(raw.get("victim") or item.title)
    group = str(raw.get("group") or "")
    country = str(raw.get("country") or "")

    fields = [
        {"name": "Group", "value": group.title() or "(unknown)", "inline": True},
        {"name": "Victim", "value": victim[:200], "inline": True},
    ]
    if country:
        fields.append({"name": "Country", "value": country, "inline": True})
    if item.url:
        fields.append({"name": "Link", "value": item.url[:500], "inline": False})

    payload = {
        "embeds": [
            {
                "title": f"\U0001f6a8 Ransomware Victim: {item.title[:200]}",
                "description": (item.summary[:300] if item.summary else "(no description)"),
                "color": 0xFF4444,
                "fields": fields,
                "footer": {"text": "borealsec-intel \u00b7 ransomware.live"},
            }
        ]
    }

    try:
        requests.post(webhook, json=payload, timeout=10)
    except requests.RequestException as e:
        logger.warning("Discord alert failed: %s", e)
