import hashlib
import html
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit, urlunsplit

try:
    import bleach
except ModuleNotFoundError:  # pragma: no cover
    bleach = None

TRACKING_PARAMS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "ref_src",
    "source",
}

SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
WHITESPACE_RE = re.compile(r"\s+")


def normalize_title(value: str) -> str:
    return WHITESPACE_RE.sub(" ", (value or "").strip())


def hash_title(value: str) -> str:
    return hashlib.sha256(normalize_title(value).encode("utf-8")).hexdigest()


def canonicalize_url(url: str) -> str:
    if not url:
        return ""

    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return url.strip()

    if not parsed.scheme or not parsed.netloc:
        return url.strip()

    filtered_params = []
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered.startswith("utm_") or lowered in TRACKING_PARAMS:
            continue
        filtered_params.append((key, val))

    query = "&".join(
        [
            f"{k}={v}" if v != "" else k
            for k, v in sorted(filtered_params, key=lambda pair: pair[0].lower())
        ]
    )

    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            query,
            "",
        )
    )


def sanitize_summary(value: str) -> str:
    if not value:
        return ""

    stripped_script = SCRIPT_STYLE_RE.sub(" ", value)
    if bleach is not None:
        cleaned = bleach.clean(
            stripped_script, tags=[], attributes={}, protocols=[], strip=True
        )
    else:
        cleaned = re.sub(r"<[^>]+>", " ", stripped_script)
    cleaned = html.unescape(cleaned)
    return WHITESPACE_RE.sub(" ", cleaned).strip()


def build_stable_id(
    *, feed_id: int, canonical_url: str, normalized_title: str, published_at: datetime
) -> str:
    if canonical_url:
        raw = canonical_url
    else:
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)
        day_bucket = published_at.astimezone(timezone.utc).strftime("%Y%m%d")
        raw = f"{feed_id}:{hash_title(normalized_title)}:{day_bucket}"

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
