from django.urls import reverse


NAVIGATION_GROUPS = (
    (
        "Overview",
        (
            {
                "key": "now",
                "label": "Now",
                "url_name": "now",
                "route_names": ("now",),
            },
        ),
    ),
    (
        "Threats",
        (
            {
                "key": "active",
                "label": "Active Exploitation",
                "url_name": "active",
                "route_names": ("active",),
            },
            {
                "key": "vulnerabilities",
                "label": "Vulnerabilities",
                "url_name": "advisories",
                "route_names": ("advisories",),
            },
            {
                "key": "threat-news",
                "label": "Threat News",
                "url_name": "threat-news",
                "route_names": ("threat-news",),
            },
        ),
    ),
    (
        "Intelligence",
        (
            {
                "key": "ransomware",
                "label": "Ransomware",
                "url_name": "ransomware-map",
                "route_names": ("ransomware-map",),
            },
            {
                "key": "nordics",
                "label": "Nordics",
                "url_name": "sweden",
                "route_names": ("sweden",),
            },
            {
                "key": "research",
                "label": "Research",
                "url_name": "research",
                "route_names": ("research",),
            },
            {
                "key": "threat-watch",
                "label": "Threat Watch",
                "url_name": "dark-dashboard",
                "route_names": ("dark-dashboard", "dark-map", "dark-recent-hits"),
                "superuser_only": True,
            },
        ),
    ),
    (
        "Data",
        (
            {
                "key": "sources",
                "label": "Sources",
                "url_name": "sources",
                "route_names": ("sources",),
            },
            {
                "key": "feed-health",
                "label": "Feed Health",
                "url_name": "feed-health",
                "route_names": ("feed-health",),
            },
        ),
    ),
)

NAVIGATION_UTILITY = (
    {
        "key": "about",
        "label": "About",
        "url_name": "about",
        "route_names": ("about",),
    },
)

PAGE_ORIENTATION = {
    "now": ("Overview", "A current view of high-signal security activity."),
    "active": ("Threats", "Confirmed or strongly evidenced exploitation activity."),
    "advisories": ("Threats", "Vendor and vulnerability intelligence."),
    "threat-news": ("Threats", "Security events, campaigns, and industry developments."),
    "ransomware-map": ("Intelligence", "Victim, group, and geography intelligence."),
    "sweden": ("Intelligence", "Security intelligence with meaningful Nordic relevance."),
    "research": ("Intelligence", "Technical research, analysis, and practitioner writeups."),
    "dark-dashboard": ("Intelligence", "Restricted monitoring for configured threat-watch sources."),
    "dark-map": ("Intelligence", "Restricted group activity and incident geography."),
    "dark-recent-hits": ("Intelligence", "Restricted recent findings for analyst verification."),
    "sources": ("Data", "Coverage, provenance, and recent intelligence by source."),
    "feed-health": ("Data", "Freshness, ingest outcomes, and feed-level errors."),
    "about": ("System", "Purpose, safeguards, and operating principles."),
}


def _navigation_item(item, *, route_name: str, is_superuser: bool) -> dict:
    restricted = bool(item.get("superuser_only") and not is_superuser)
    return {
        "key": item["key"],
        "label": item["label"],
        "url": None if restricted else reverse(item["url_name"]),
        "is_active": route_name in item["route_names"],
        "is_restricted": restricted,
    }


def navigation_context(request) -> dict:
    route_name = request.resolver_match.url_name if request.resolver_match else ""
    is_superuser = bool(request.user.is_authenticated and request.user.is_superuser)
    groups = []
    active_item = None

    for group_label, item_definitions in NAVIGATION_GROUPS:
        items = [
            _navigation_item(
                item,
                route_name=route_name,
                is_superuser=is_superuser,
            )
            for item in item_definitions
        ]
        groups.append({"label": group_label, "items": items})
        active_item = active_item or next(
            (item for item in items if item["is_active"]),
            None,
        )

    utility_items = [
        _navigation_item(
            item,
            route_name=route_name,
            is_superuser=is_superuser,
        )
        for item in NAVIGATION_UTILITY
    ]
    active_item = active_item or next(
        (item for item in utility_items if item["is_active"]),
        None,
    )
    page_group, page_description = PAGE_ORIENTATION.get(route_name, ("", ""))

    return {
        "app_navigation_groups": groups,
        "app_navigation_utility": utility_items,
        "active_navigation_item": active_item,
        "page_group": page_group,
        "page_description": page_description,
    }
