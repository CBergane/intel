import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path


COUNTRY_DATA_PATH = (
    Path(__file__).resolve().parent / "data" / "ransomware_map_countries.json"
)
COUNTRY_VALUE_SPLIT_RE = re.compile(r"\s*(?:/|\||;)\s*")
WHITESPACE_RE = re.compile(r"\s+")
COUNTRY_PLACEHOLDER_VALUES = {
    "",
    "-",
    "--",
    "global",
    "international",
    "multiple",
    "n/a",
    "na",
    "none",
    "unknown",
    "various",
    "worldwide",
}


@dataclass(frozen=True, slots=True)
class RansomwareCountryIdentity:
    display_name: str = ""
    country_id: str = ""
    iso_alpha2: str = ""
    iso_alpha3: str = ""
    iso_numeric: str = ""

    @property
    def recognized(self) -> bool:
        return bool(self.country_id)


def _lookup_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or ""))
    normalized = WHITESPACE_RE.sub(" ", normalized).strip().casefold()
    return normalized.replace("&", "and").strip(" .:-")


def _unknown_display(value: str) -> str:
    cleaned = WHITESPACE_RE.sub(" ", str(value or "")).strip()
    if not cleaned or _lookup_key(cleaned) in COUNTRY_PLACEHOLDER_VALUES:
        return ""
    return cleaned.title() if cleaned.islower() else cleaned


with COUNTRY_DATA_PATH.open(encoding="utf-8") as country_data_file:
    _COUNTRY_DATA = json.load(country_data_file)


RANSOMWARE_MAP_COUNTRIES = tuple(
    RansomwareCountryIdentity(
        display_name=row["name"],
        country_id=row["country_id"],
        iso_alpha2=row.get("iso_a2", ""),
        iso_alpha3=row.get("iso_a3", ""),
        iso_numeric=row.get("iso_n3", ""),
    )
    for row in _COUNTRY_DATA["countries"]
)
RANSOMWARE_MAP_DATASET = dict(_COUNTRY_DATA["dataset"])
RANSOMWARE_COUNTRY_BY_ID = {
    country.country_id: country for country in RANSOMWARE_MAP_COUNTRIES
}


def _build_country_lookup() -> dict[str, RansomwareCountryIdentity]:
    country_lookup = {}
    for row, country in zip(_COUNTRY_DATA["countries"], RANSOMWARE_MAP_COUNTRIES):
        aliases = {
            country.country_id,
            country.display_name,
            country.iso_alpha2,
            country.iso_alpha3,
            country.iso_numeric,
            row.get("geometry_name", ""),
            *row.get("aliases", []),
        }
        for alias in aliases:
            key = _lookup_key(alias)
            if key:
                country_lookup.setdefault(key, country)

    explicit_aliases = {
        "america": "USA",
        "u.s.": "USA",
        "u.s.a.": "USA",
        "uk": "GBR",
        "u.k.": "GBR",
        "great britain": "GBR",
        "britain": "GBR",
        "england": "GBR",
        "russian federation": "RUS",
        "republic of korea": "KOR",
        "korea, republic of": "KOR",
        "czech republic": "CZE",
        "uae": "ARE",
        "u.a.e.": "ARE",
        "ivory coast": "CIV",
        "democratic republic of the congo": "COD",
        "congo-kinshasa": "COD",
        "republic of the congo": "COG",
        "congo-brazzaville": "COG",
        "swaziland": "SWZ",
        "macedonia": "MKD",
        "east timor": "TLS",
        "viet nam": "VNM",
        "brunei darussalam": "BRN",
        "sverige": "SWE",
        "suomi": "FIN",
        "danmark": "DNK",
        "norge": "NOR",
        "deutschland": "DEU",
        "holland": "NLD",
        "brasil": "BRA",
        "espana": "ESP",
        "españa": "ESP",
        "turkiye": "TUR",
        "türkiye": "TUR",
    }
    for alias, country_id in explicit_aliases.items():
        country = RANSOMWARE_COUNTRY_BY_ID.get(country_id)
        if country is None:
            raise RuntimeError(
                f"Ransomware map country alias target {country_id!r} is not in the geometry manifest."
            )
        country_lookup[_lookup_key(alias)] = country
    return country_lookup


RANSOMWARE_COUNTRY_LOOKUP = _build_country_lookup()


def normalize_ransomware_country(value: str) -> RansomwareCountryIdentity:
    cleaned = WHITESPACE_RE.sub(" ", str(value or "")).strip()
    if not cleaned:
        return RansomwareCountryIdentity()

    candidates = [cleaned]
    for part in COUNTRY_VALUE_SPLIT_RE.split(cleaned):
        part = WHITESPACE_RE.sub(" ", part).strip()
        if part and part not in candidates:
            candidates.append(part)

    for candidate in candidates:
        key = _lookup_key(candidate)
        if key in COUNTRY_PLACEHOLDER_VALUES:
            continue
        country = RANSOMWARE_COUNTRY_LOOKUP.get(key)
        if country is not None:
            return country

    return RansomwareCountryIdentity(display_name=_unknown_display(cleaned))
