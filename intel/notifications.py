from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import requests
from django.conf import settings

from intel.dark_utils import evaluate_record_watch_matches

if TYPE_CHECKING:
    from intel.models import DarkHit, Item

logger = logging.getLogger(__name__)

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


def send_dark_hit_alert(hit: DarkHit, *, matched_fields: list[str] | None = None) -> None:
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
