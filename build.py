#!/usr/bin/env python3
"""Download upstream blocklists, normalize them, and write Pi-hole lists."""

from __future__ import annotations

import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
SOURCES_FILE = ROOT / "sources.txt"
WHITELIST_FILE = ROOT / "whitelist.txt"
CACHE_DIR = ROOT / ".cache"
USER_AGENT = "pihole-blocklist-builder/1.0 (+local curated list)"
TIMEOUT_SEC = 60
RETRIES = 3
TZ = ZoneInfo("America/New_York")

CATEGORIES = ("ads", "trackers", "malware", "smart-tv-iot")
CATEGORY_TITLES = {
    "ads": "Ads",
    "trackers": "Trackers / telemetry",
    "malware": "Malware / phishing",
    "smart-tv-iot": "Smart TV / IoT telemetry",
}

# Hosts-file tokens we never treat as domains.
LOCALHOST_NAMES = {
    "localhost",
    "localhost.localdomain",
    "local",
    "localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
}
HOSTS_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
}

IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)
IPV6_RE = re.compile(r"^\[?[0-9a-f:]+\]?$", re.I)

# ||example.com^ or ||example.com^$important  (plain domain rules only)
ADBLOCK_DOMAIN_RE = re.compile(
    r"^\|\|([A-Za-z0-9._-]+)\^(?:\$[^\s/]*)?$"
)

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def log(msg: str) -> None:
    print(msg, flush=True)


def parse_sources(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"Bad sources.txt line: {raw!r}")
        category, url = parts
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category {category!r} in sources.txt")
        entries.append((category, url))
    return entries


def parse_whitelist(path: Path) -> set[str]:
    names: set[str] = set()
    if not path.exists():
        return names
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = normalize_candidate(line)
        if domain:
            names.add(domain)
    return names


def is_whitelisted(domain: str, whitelist: set[str]) -> bool:
    if domain in whitelist:
        return True
    return any(domain.endswith("." + allowed) for allowed in whitelist)


def normalize_candidate(value: str) -> str | None:
    """Return a lowercase registrable hostname, or None if invalid."""
    value = value.strip().strip(".").lower()
    if not value or "/" in value or ":" in value or value.startswith("*"):
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    if value in LOCALHOST_NAMES:
        return None
    if IPV4_RE.match(value) or IPV6_RE.match(value):
        return None
    if len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if any(not LABEL_RE.match(label) for label in labels):
        return None
    return value


def parse_line(line: str) -> tuple[str | None, bool]:
    """Parse one source line. Returns (domain_or_None, is_exception)."""
    line = line.strip().lstrip("\ufeff")
    if not line:
        return None, False
    if line[0] in "#!;[" or line.startswith("!#"):
        return None, False

    is_exception = False
    if line.startswith("@@"):
        is_exception = True
        line = line[2:]

    if line.startswith("||"):
        match = ADBLOCK_DOMAIN_RE.match(line)
        if not match:
            return None, False
        return normalize_candidate(match.group(1)), is_exception

    # Drop trailing comments for hosts / plain-domain lines.
    if "#" in line:
        line = line.split("#", 1)[0].strip()
        if not line:
            return None, False

    parts = line.split()
    if not parts:
        return None, False
    if parts[0] in HOSTS_IPS or IPV4_RE.match(parts[0]) or IPV6_RE.match(parts[0]):
        if len(parts) < 2:
            return None, False
        # Standard hosts format: IP host [aliases...]
        return normalize_candidate(parts[1]), is_exception
    if len(parts) != 1:
        return None, False
    return normalize_candidate(parts[0]), is_exception


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    ctx = ssl.create_default_context()
    last_error: Exception | None = None
    for attempt in range(1, RETRIES + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=TIMEOUT_SEC) as resp:
                data = resp.read()
            dest.write_bytes(data)
            return
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            last_error = exc
            log(f"  retry {attempt}/{RETRIES} failed: {exc}")
    raise RuntimeError(f"Failed to download {url}: {last_error}")


def cache_name(url: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", url)
    return safe[:180]


def extract_domains(text: str) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    exceptions: set[str] = set()
    for raw in text.splitlines():
        domain, is_exception = parse_line(raw)
        if not domain:
            continue
        if is_exception:
            exceptions.add(domain)
        else:
            domains.add(domain)
    return domains, exceptions


def write_list(path: Path, header_lines: list[str], domains: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for line in header_lines:
            handle.write(line.rstrip() + "\n")
        handle.write("\n".join(domains))
        if domains:
            handle.write("\n")


def main() -> int:
    sources = parse_sources(SOURCES_FILE)
    whitelist = parse_whitelist(WHITELIST_FILE)
    build_time = datetime.now(TZ)
    build_stamp = build_time.strftime("%Y-%m-%d %H:%M %Z")

    log(f"Building curated Pi-hole lists at {build_stamp}")
    log(f"Whitelist entries: {len(whitelist)}")

    by_category: dict[str, set[str]] = {cat: set() for cat in CATEGORIES}
    source_results: list[tuple[str, str, str, int]] = []
    failures: list[tuple[str, str, str]] = []
    applied_exceptions: set[str] = set(whitelist)

    for category, url in sources:
        log(f"[{category}] fetching {url}")
        dest = CACHE_DIR / cache_name(url)
        try:
            download(url, dest)
            text = dest.read_text(encoding="utf-8", errors="replace")
            domains, exceptions = extract_domains(text)
            applied_exceptions.update(exceptions)
            kept = {d for d in domains if not is_whitelisted(d, applied_exceptions)}
            by_category[category].update(kept)
            source_results.append((category, url, "ok", len(kept)))
            skipped = len(domains) - len(kept)
            log(
                f"  parsed {len(domains)} domains, "
                f"kept {len(kept)} (whitelisted {skipped}, "
                f"exceptions {len(exceptions)})"
            )
        except Exception as exc:  # noqa: BLE001 - continue remaining sources
            failures.append((category, url, str(exc)))
            source_results.append((category, url, f"FAILED: {exc}", 0))
            log(f"  FAILED: {exc}")

    # Re-apply the full exception/whitelist set after all sources are in,
    # so a later @@exception can still remove an earlier hit.
    for category, domains in by_category.items():
        by_category[category] = {
            d for d in domains if not is_whitelisted(d, applied_exceptions)
        }

    combined: set[str] = set()
    category_counts: dict[str, int] = {}
    for category in CATEGORIES:
        ordered = sorted(by_category[category])
        category_counts[category] = len(ordered)
        combined.update(ordered)
        out = ROOT / f"{category}.txt"
        header = [
            f"# Title: Bryan's Curated Pi-hole Blocklist — {CATEGORY_TITLES[category]}",
            f"# Build date: {build_stamp}",
            f"# Domains: {len(ordered):,}",
            f"# Sources:",
        ]
        for cat, url, status, _count in source_results:
            if cat == category:
                note = "" if status == "ok" else f"  ({status})"
                header.append(f"#   {url}{note}")
        header.append("# Format: one domain per line (Pi-hole compatible)")
        header.append("#")
        write_list(out, header, ordered)
        log(f"Wrote {out} ({len(ordered):,} domains)")

    # Combined list: unique domains, sorted. A domain may appear in more
    # than one category file but only once here.
    combined_ordered = sorted(combined)
    source_header = ["# Sources:"]
    for category, url, status, _count in source_results:
        note = "" if status == "ok" else f"  ({status})"
        source_header.append(f"#   [{category}] {url}{note}")
    header = [
        "# Title: Bryan's Curated Pi-hole Blocklist",
        "# Description: Combined ads, trackers/telemetry, malware/phishing,",
        "#   and smart TV/IoT telemetry domains for use as a Pi-hole adlist.",
        f"# Build date: {build_stamp}",
        f"# Domains: {len(combined_ordered):,}",
        *source_header,
        "# Format: one domain per line (Pi-hole compatible)",
        "#",
    ]
    combined_path = ROOT / "blocklist.txt"
    write_list(combined_path, header, combined_ordered)
    log(f"Wrote {combined_path} ({len(combined_ordered):,} domains)")

    log("")
    log("=== Build summary ===")
    for category in CATEGORIES:
        log(f"  {category}: {category_counts[category]:,}")
    log(f"  combined (unique): {len(combined_ordered):,}")
    if failures:
        log("  failed sources:")
        for category, url, err in failures:
            log(f"    [{category}] {url}")
            log(f"      {err}")
        return 1
    log("  failed sources: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
