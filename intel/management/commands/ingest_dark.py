import time
import os

import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from intel.dark_utils import (
    build_content_hash,
    build_excerpt,
    extract_title,
    matched_keywords,
    strip_tags,
    extract_main_html
)
from intel.models import DarkFetchRun, DarkHit, DarkSource


class Command(BaseCommand):
    help = "Fetch allowlisted dark intel sources over Tor and create deduplicated keyword hits."

    def handle(self, *args, **options):
        sources = DarkSource.objects.filter(enabled=True).order_by("name")
        if not sources.exists():
            self.stdout.write(self.style.WARNING("No enabled dark sources matched."))
            return

        total_hits = 0
        for dark_source in sources:
            run = DarkFetchRun.objects.create(dark_source=dark_source, started_at=timezone.now())
            started = time.monotonic()
            try:
                markup, bytes_received = self._fetch_with_retries(dark_source)
                run.bytes_received = bytes_received

                title = extract_title(markup)
                main_html = extract_main_html(markup)
                text = strip_tags(main_html)
                excerpt = build_excerpt(text)
                matches = matched_keywords(f"{title}\n{text}", dark_source.watch_keywords)
                content_hash = build_content_hash(
                    url=dark_source.url,
                    title=title,
                    text=text,
                    matched=matches,
                )

                if matches:
                    _, created = DarkHit.objects.get_or_create(
                        dark_source=dark_source,
                        content_hash=content_hash,
                        defaults={
                            "matched_keywords": matches,
                            "title": title,
                            "excerpt": excerpt,
                            "url": dark_source.url,
                            "raw":  main_html[:4000],
                        },
                    )
                    if created:
                        total_hits += 1

                run.ok = True
                run.finished_at = timezone.now()
                run.save()
                self.stdout.write(
                    self.style.SUCCESS(
                        f"[{dark_source.id}] {dark_source.name}: ok bytes={bytes_received} matches={len(matches)}"
                    )
                )
            except Exception as exc:
                run.ok = False
                run.error = str(exc)[:4000]
                run.finished_at = timezone.now()
                run.save()
                self.stderr.write(self.style.ERROR(f"[{dark_source.id}] {dark_source.name}: {exc}"))
            finally:
                _ = int((time.monotonic() - started) * 1000)

        self.stdout.write(self.style.SUCCESS(f"Done. total_hits_new={total_hits}"))

    def _fetch_with_retries(self, dark_source):
        retries = max(settings.DARK_FETCH_RETRIES, 1)
        last_error = None
        for attempt in range(1, retries + 1):
            try:
                return self._fetch_once(dark_source)
            except Exception as exc:
                last_error = exc
                if attempt < retries:
                    time.sleep(2 ** (attempt - 1))
        raise RuntimeError(f"Failed to fetch dark source after {retries} attempt(s): {last_error}")

    def _fetch_once(self, dark_source):
        use_tor = (dark_source.url or "").endswith(".onion")

        proxies = None
        if use_tor:
            proxies = {
                "http": settings.DARK_TOR_SOCKS_URL,
                "https": settings.DARK_TOR_SOCKS_URL,
            }

        headers = {
            # "browser-ish" för att minska bot-404/WAF-strul
            "User-Agent": os.getenv("DARK_USER_AGENT", "Mozilla/5.0"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
        }

        try:
            with requests.get(
                dark_source.url,
                headers=headers,
                timeout=settings.DARK_FETCH_TIMEOUT,
                proxies=proxies,
                stream=True,
                allow_redirects=True,
            ) as response:
                # tydligare error med final_url
                if response.status_code >= 400:
                    raise RuntimeError(
                        f"{response.status_code} for url={dark_source.url} (final_url={response.url})"
                    )

                content_type = (response.headers.get("Content-Type") or "").lower()
                if content_type and not any(
                    ct in content_type for ct in ("text/html", "application/xhtml+xml", "text/plain")
                ):
                    raise RuntimeError(
                        f"Unsupported Content-Type={content_type} for url={response.url}"
                    )

                size = 0
                chunks = []
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > settings.DARK_MAX_BYTES:
                        raise ValueError(
                            f"Dark source response exceeded max_bytes={settings.DARK_MAX_BYTES} (final_url={response.url})"
                        )
                    chunks.append(chunk)

                raw = b"".join(chunks)

                # requests kan oftast gissa encoding; fallback till utf-8
                encoding = response.encoding or "utf-8"
                markup = raw.decode(encoding, errors="replace")
                return markup, size

        except requests.RequestException as exc:
            # samlar alla requests-relaterade fel och gör dem tydliga
            raise RuntimeError(f"Request failed for url={dark_source.url}: {exc}") from exc
