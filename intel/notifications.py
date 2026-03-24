from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

import requests
from django.conf import settings

if TYPE_CHECKING:
    from intel.models import DarkHit, Item

logger = logging.getLogger(__name__)


def send_dark_hit_alert(hit: DarkHit) -> None:
    webhook = getattr(settings, "DARK_DISCORD_WEBHOOK", "")
    if not webhook:
        logger.debug("DARK_DISCORD_WEBHOOK not configured, skipping dark hit alert.")
        return

    keywords = hit.matched_keywords
    if isinstance(keywords, list):
        keywords_str = ", ".join(str(k) for k in keywords) if keywords else "(none)"
    else:
        keywords_str = str(keywords) if keywords else "(none)"

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
