"""
Remove blacklist entries whose registered domain no longer exists in RDAP.

How it works
------------
Each line in blacklist.txt is a uBlacklist URL pattern such as:

    *://goods.taobao.com/*
    *://*.eyewated.com/*
    *://www.iodraw.com/blog/*

For every line we:
1. Extract the hostname portion (stripping the leading ``*://*.`` or ``*://``
   and the trailing path).
2. Resolve the *registrable domain* (eTLD+1) via ``tldextract``.
3. Query ``https://rdap.org/domain/<registrable-domain>`` once per unique
   registrable domain (with a short sleep between requests to respect rate
   limits).
4. The RDAP JSON response is parsed to confirm the result contains a valid
   domain object (``objectClassName == "domain"``).  Lines whose registrable
   domain returns HTTP 404 *or* whose response does not contain a valid RDAP
   domain object are dropped; all other lines (including lines for which the
   lookup fails for any network reason) are kept so we don't accidentally
   remove valid entries.
5. When RDAP returns HTTP 403 (Forbidden), a WHOIS lookup is used as a
   fallback.  A domain is considered non-existent only when WHOIS also
   confirms it has no registration data; on any WHOIS error the entry is kept.

Usage
-----
    python cleanup_expired_domains.py [--blacklist PATH] [--delay SECONDS]
"""

import argparse
import re
import sys
import time

import requests
import tldextract
import whois


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(r"^\*://(?:\*\.)?([^/]+)")


def extract_host(pattern: str) -> str | None:
    """Return the hostname from a uBlacklist URL-match pattern, or None."""
    m = _HOST_RE.match(pattern.strip())
    return m.group(1) if m else None


def registrable_domain(host: str) -> str | None:
    """Return the eTLD+1 for *host*, or None if it cannot be determined."""
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def domain_exists_whois(domain: str, timeout: int = 15) -> bool:
    """
    Return True if *domain* appears to be registered according to WHOIS.

    A domain is considered non-existent only when the WHOIS response contains
    no ``domain_name`` data.  On any error (network failure, parse error, …)
    return True so we never accidentally drop an entry we cannot verify.
    """
    try:
        result = whois.whois(domain, quiet=True, timeout=timeout)
        domain_name = result.get("domain_name") if isinstance(result, dict) else getattr(result, "domain_name", None)
        if domain_name:
            return True
        print(f"  [warn] WHOIS found no registration for {domain!r}; treating as not found")
        return False
    except Exception as exc:
        print(f"  [warn] WHOIS error for {domain!r}: {exc}; keeping entry")
        return True


def domain_exists_rdap(domain: str, timeout: int = 15) -> bool:
    """
    Return True if *domain* is confirmed to exist by the RDAP response body.

    The RDAP JSON is parsed and the ``objectClassName`` field is checked to
    ensure the response contains a valid domain object.  HTTP 404 responses
    and 200 responses that lack a ``"domain"`` object class are treated as
    non-existent.  On HTTP 403, a WHOIS lookup is used as a fallback.  On any
    other error (network failure, non-404/403 HTTP error, unparseable JSON, …)
    return True so we never accidentally drop an entry we cannot verify.
    """
    url = f"https://rdap.org/domain/{domain}"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        if resp.status_code == 404:
            return False
        if resp.status_code == 403:
            print(f"  [warn] RDAP 403 for {domain!r}; falling back to WHOIS")
            return domain_exists_whois(domain, timeout=timeout)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                print(f"  [warn] Invalid RDAP JSON for {domain!r}; keeping entry")
                return True
            if data.get("objectClassName") == "domain":
                return True
            print(f"  [warn] Unexpected RDAP object for {domain!r}; keeping entry")
            return True
        # Rate-limit (429) or server errors → keep the entry
        print(f"  [warn] Unexpected HTTP {resp.status_code} for {domain!r}; keeping entry")
        return True
    except requests.exceptions.RequestException as exc:
        print(f"  [warn] Network error for {domain!r}: {exc}; keeping entry")
        return True


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def main(blacklist_path: str = "blacklist.txt", delay: float = 1.0) -> int:
    with open(blacklist_path, encoding="utf-8") as fh:
        lines = fh.readlines()

    # Map each registrable domain → list of line indices that reference it
    domain_lines: dict[str, list[int]] = {}
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped:
            continue
        host = extract_host(stripped)
        if host is None:
            continue
        reg = registrable_domain(host)
        if reg is None:
            continue
        domain_lines.setdefault(reg, []).append(idx)

    print(f"Found {len(domain_lines)} unique registrable domains to check.")

    # Query RDAP for each unique domain
    expired: set[str] = set()
    for i, domain in enumerate(sorted(domain_lines), start=1):
        print(f"[{i}/{len(domain_lines)}] Checking {domain!r} … ", end="", flush=True)
        exists = domain_exists_rdap(domain)
        if exists:
            print("OK")
        else:
            print("NOT FOUND – will remove")
            expired.add(domain)
        if i < len(domain_lines):
            time.sleep(delay)

    if not expired:
        print("\nNo expired domains found. blacklist.txt unchanged.")
        return 0

    # Build the set of line indices to drop
    drop_indices: set[int] = set()
    for domain in expired:
        drop_indices.update(domain_lines[domain])

    kept = [line for idx, line in enumerate(lines) if idx not in drop_indices]

    with open(blacklist_path, "w", encoding="utf-8") as fh:
        fh.writelines(kept)

    removed_lines = len(lines) - len(kept)
    print(
        f"\nRemoved {removed_lines} line(s) for {len(expired)} expired domain(s): "
        + ", ".join(sorted(expired))
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove expired domains from blacklist.txt")
    parser.add_argument(
        "--blacklist",
        default="blacklist.txt",
        help="Path to the blacklist file (default: blacklist.txt)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds to sleep between RDAP requests (default: 1.0)",
    )
    args = parser.parse_args()
    sys.exit(main(blacklist_path=args.blacklist, delay=args.delay))
