import time

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
                text = strip_tags(markup)
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
                            "raw": markup[:4000],
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
        response = requests.get(
            dark_source.url,
            headers={"User-Agent": settings.INTEL_USER_AGENT},
            timeout=settings.DARK_FETCH_TIMEOUT,
            proxies={
                "http": settings.DARK_TOR_SOCKS_URL,
                "https": settings.DARK_TOR_SOCKS_URL,
            },
            stream=True,
        )
        response.raise_for_status()

        size = 0
        chunks = []
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            size += len(chunk)
            if size > settings.DARK_MAX_BYTES:
                raise ValueError(f"Dark source response exceeded max_bytes={settings.DARK_MAX_BYTES}")
            chunks.append(chunk)

        markup = b"".join(chunks).decode("utf-8", errors="replace")
        return markup, size
