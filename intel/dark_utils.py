import hashlib
import html
import re

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
WHITESPACE_RE = re.compile(r"[ \t\r\f\v]+")
BLANKLINES_RE = re.compile(r"\n{3,}")

# Remove noisy blocks before stripping tags
SCRIPT_RE = re.compile(r"(?is)<script[^>]*>.*?</script>")
STYLE_RE = re.compile(r"(?is)<style[^>]*>.*?</style>")
NOSCRIPT_RE = re.compile(r"(?is)<noscript[^>]*>.*?</noscript>")
SVG_RE = re.compile(r"(?is)<svg[^>]*>.*?</svg>")
HTML_TAG_RE = re.compile(r"(?s)<[^>]+>")

# Optional: drop common boilerplate blocks (light heuristic)
HEADER_FOOTER_NAV_ASIDE_RE = re.compile(r"(?is)<(header|footer|nav|aside)[^>]*>.*?</\1>")


def parse_watch_keywords(raw: str) -> list[str]:
    return [part.strip().lower() for part in (raw or "").split(",") if part.strip()]


def normalize_text(value: str) -> str:
    # preserve newlines, normalize spaces
    s = (value or "").strip()
    s = s.replace("\xa0", " ").replace("\u200b", " ")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = WHITESPACE_RE.sub(" ", s)
    # cleanup spaces around newlines
    s = re.sub(r" *\n *", "\n", s)
    s = BLANKLINES_RE.sub("\n\n", s)
    return s.strip()


def extract_title(markup: str) -> str:
    match = TITLE_RE.search(markup or "")
    if not match:
        return "Untitled"
    # strip tags inside title, unescape, normalize
    title = html.unescape(match.group(1))
    title = HTML_TAG_RE.sub(" ", title)
    return normalize_text(title) or "Untitled"


def extract_main_html(markup: str) -> str:
    """
    Prefer <main> or <article> content when present.
    Falls back to full markup if not found.
    """
    m = re.search(r"(?is)<main[^>]*>(.*?)</main>", markup or "")
    if m:
        return m.group(1)
    m = re.search(r"(?is)<article[^>]*>(.*?)</article>", markup or "")
    if m:
        return m.group(1)
    return markup or ""


def strip_tags(markup: str) -> str:
    s = html.unescape(markup or "")

    # Remove the worst offenders first
    s = SCRIPT_RE.sub(" ", s)
    s = STYLE_RE.sub(" ", s)
    s = NOSCRIPT_RE.sub(" ", s)
    s = SVG_RE.sub(" ", s)
    s = HEADER_FOOTER_NAV_ASIDE_RE.sub(" ", s)

    # Drop remaining tags
    s = HTML_TAG_RE.sub(" ", s)

    return normalize_text(s)


def build_excerpt(text: str, limit: int = 280) -> str:
    cleaned = normalize_text(text)
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1].rstrip() + "…"


def matched_keywords(text: str, raw_keywords: str) -> list[str]:
    lowered = (text or "").lower()
    matches = []
    for keyword in parse_watch_keywords(raw_keywords):
        if keyword in lowered and keyword not in matches:
            matches.append(keyword)
    return matches


def build_content_hash(*, url: str, title: str, text: str, matched: list[str]) -> str:
    # Only hash a limited amount of text to avoid huge payloads
    payload = "\n".join([url or "", title or "", normalize_text(text)[:2000], ",".join(matched or [])])
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()