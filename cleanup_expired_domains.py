"""
Remove blacklist entries whose registered domain is no longer resolvable via DNS.

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
3. Attempt a DNS lookup for each unique registrable domain (with a short sleep
   between lookups to avoid hammering the resolver).
4. Lines whose registrable domain raises ``socket.gaierror`` with
   ``errno.ENOENT`` (or the equivalent NXDOMAIN / name-not-found error) are
   dropped.  All other lines (including those for which the lookup fails for
   any other reason) are kept so we don't accidentally remove valid entries.

Usage
-----
    python cleanup_expired_domains.py [--blacklist PATH] [--delay SECONDS]
"""

import argparse
import errno
import re
import socket
import sys
import time

import tldextract


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


def domain_is_resolvable(domain: str) -> bool:
    """
    Return True if *domain* resolves via DNS, False if it does not exist.

    A domain is considered non-existent only when ``socket.getaddrinfo``
    raises a ``socket.gaierror`` that definitively indicates the name was not
    found: ``errno.ENOENT`` on some resolvers, ``EAI_NONAME`` (-2, NXDOMAIN)
    on Linux, or ``WSAHOST_NOT_FOUND`` (11001) on Windows.  Transient errors
    such as ``EAI_AGAIN`` (-3) are treated conservatively – the entry is kept.
    On any other error the entry is also kept so we never accidentally drop a
    valid entry.
    """
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror as exc:
        # errno codes that definitively mean "name does not exist"
        _not_found = {
            errno.ENOENT,           # some resolvers
            -2,                     # EAI_NONAME on Linux (NXDOMAIN)
            11001,                  # WSAHOST_NOT_FOUND on Windows
        }
        if exc.args[0] in _not_found:
            print(f"  [warn] DNS lookup failed for {domain!r}: {exc}; treating as not found")
            return False
        print(f"  [warn] DNS lookup error for {domain!r}: {exc}; keeping entry")
        return True
    except OSError as exc:
        print(f"  [warn] OS error looking up {domain!r}: {exc}; keeping entry")
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

    # Check DNS resolvability for each unique domain
    expired: set[str] = set()
    for i, domain in enumerate(sorted(domain_lines), start=1):
        print(f"[{i}/{len(domain_lines)}] Checking {domain!r} … ", end="", flush=True)
        exists = domain_is_resolvable(domain)
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
        help="Seconds to sleep between DNS lookups (default: 1.0)",
    )
    args = parser.parse_args()
    sys.exit(main(blacklist_path=args.blacklist, delay=args.delay))
