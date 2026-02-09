TIER1_SOURCES = [
    {
        "name": "CERT-SE",
        "slug": "cert-se",
        "homepage": "https://www.cert.se/",
        "tags": ["government", "sweden"],
        "enabled": True,
        "feeds": [
            {
                "name": "CERT-SE Feed",
                "url": "https://www.cert.se/feed/",
                "feed_type": "rss",
                "section": "sweden",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 180,
                "max_items_per_run": 200,
            }
        ],
    },
    {
        "name": "CISA",
        "slug": "cisa",
        "homepage": "https://www.cisa.gov/",
        "tags": ["government", "us"],
        "enabled": True,
        "feeds": [
            {
                "name": "CISA Alerts",
                "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
                "feed_type": "rss",
                "section": "active",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 180,
                "max_items_per_run": 200,
            }
        ],
    },
    {
        "name": "MSRC",
        "slug": "msrc",
        "homepage": "https://msrc.microsoft.com/",
        "tags": ["vendor", "microsoft"],
        "enabled": True,
        "feeds": [
            {
                "name": "MSRC Security Updates",
                "url": "https://api.msrc.microsoft.com/update-guide/rss",
                "feed_type": "rss",
                "section": "advisories",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 90,
                "max_items_per_run": 200,
            }
        ],
    },
    {
        "name": "Cisco",
        "slug": "cisco",
        "homepage": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
        "tags": ["vendor", "network"],
        "enabled": True,
        "feeds": [
            {
                "name": "Cisco Security Advisories",
                "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
                "feed_type": "rss",
                "section": "advisories",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 180,
                "max_items_per_run": 200,
            }
        ],
    },
    {
        "name": "Red Hat",
        "slug": "red-hat",
        "homepage": "https://access.redhat.com/security",
        "tags": ["vendor", "linux"],
        "enabled": True,
        "feeds": [
            {
                "name": "Red Hat CVE Feed",
                "url": "https://access.redhat.com/security/data/metrics/recently-published-cve.rss",
                "feed_type": "rss",
                "section": "advisories",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 180,
                "max_items_per_run": 200,
            }
        ],
    },
    {
        "name": "Debian",
        "slug": "debian",
        "homepage": "https://www.debian.org/security/",
        "tags": ["vendor", "linux"],
        "enabled": True,
        "feeds": [
            {
                "name": "Debian Security Advisories",
                "url": "https://www.debian.org/security/dsa.en.rdf",
                "feed_type": "rss",
                "section": "advisories",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 180,
                "max_items_per_run": 200,
            }
        ],
    },
    {
        "name": "SANS ISC",
        "slug": "sans-isc",
        "homepage": "https://isc.sans.edu/",
        "tags": ["research"],
        "enabled": True,
        "feeds": [
            {
                "name": "SANS ISC Diaries",
                "url": "https://isc.sans.edu/rssfeed.xml",
                "feed_type": "rss",
                "section": "research",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 180,
                "max_items_per_run": 200,
            }
        ],
    },
    {
        "name": "ZDI",
        "slug": "zdi",
        "homepage": "https://www.zerodayinitiative.com/",
        "tags": ["research", "threat-intel"],
        "enabled": True,
        "feeds": [
            {
                "name": "ZDI Blog",
                "url": "https://www.zerodayinitiative.com/blog?format=rss",
                "feed_type": "rss",
                "section": "research",
                "enabled": True,
                "timeout_seconds": 10,
                "max_bytes": 1_500_000,
                "max_age_days": 180,
                "max_items_per_run": 200,
            }
        ],
    },
]
