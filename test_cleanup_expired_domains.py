"""
Unit and integration tests for cleanup_expired_domains.py.

Run with:
    pytest test_cleanup_expired_domains.py -v
"""

import socket
import textwrap
from unittest.mock import MagicMock, patch

import pytest

from cleanup_expired_domains import (
    domain_is_resolvable,
    extract_host,
    main,
    registrable_domain,
)


# ---------------------------------------------------------------------------
# extract_host
# ---------------------------------------------------------------------------

class TestExtractHost:
    """Tests for the extract_host() helper."""

    @pytest.mark.parametrize("pattern,expected", [
        # Standard wildcard subdomain patterns
        ("*://*.eyewated.com/*",         "eyewated.com"),
        ("*://*.baidu.com/s?word=*",     "baidu.com"),
        ("*://*.10jqka.com.cn/*",        "10jqka.com.cn"),
        ("*://*.hqyman.cn/*",            "hqyman.cn"),
        # Explicit hostname (no wildcard)
        ("*://goods.taobao.com/*",       "goods.taobao.com"),
        ("*://www.iodraw.com/blog/*",    "www.iodraw.com"),
        ("*://www.8682.cc/*",            "www.8682.cc"),
        ("*://developer.aliyun.com/*",   "developer.aliyun.com"),
        # Trailing whitespace / newlines should be stripped
        ("*://*.example.com/*\n",        "example.com"),
        ("*://*.example.com/*  ",        "example.com"),
    ])
    def test_valid_patterns(self, pattern, expected):
        assert extract_host(pattern) == expected

    @pytest.mark.parametrize("pattern", [
        "",                         # empty
        "# comment",               # comment line
        "some random text",        # no protocol
        "http://example.com/",     # wrong protocol prefix (not *)
    ])
    def test_invalid_patterns_return_none(self, pattern):
        assert extract_host(pattern) is None


# ---------------------------------------------------------------------------
# registrable_domain
# ---------------------------------------------------------------------------

class TestRegistrableDomain:
    """Tests for the registrable_domain() helper."""

    @pytest.mark.parametrize("host,expected", [
        # Simple domains
        ("eyewated.com",            "eyewated.com"),
        ("baidu.com",               "baidu.com"),
        # Subdomain → eTLD+1
        ("goods.taobao.com",        "taobao.com"),
        ("www.iodraw.com",          "iodraw.com"),
        ("www.8682.cc",             "8682.cc"),
        # Multi-part TLD
        ("10jqka.com.cn",           "10jqka.com.cn"),
        ("sub.something.com.cn",    "something.com.cn"),
        # Numeric-heavy domain names
        ("021east.com",             "021east.com"),
    ])
    def test_known_domains(self, host, expected):
        assert registrable_domain(host) == expected

    @pytest.mark.parametrize("host", [
        "226.195",       # no recognizable TLD
        "localhost",     # no TLD at all
        "",              # empty
    ])
    def test_unresolvable_returns_none(self, host):
        assert registrable_domain(host) is None


# ---------------------------------------------------------------------------
# domain_is_resolvable  (socket calls are mocked)
# ---------------------------------------------------------------------------

class TestDomainIsResolvable:
    """Tests for the domain_is_resolvable() function with mocked DNS."""

    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_successful_lookup_returns_true(self, mock_gai):
        """Successful DNS resolution → domain exists."""
        mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]
        assert domain_is_resolvable("example.com") is True

    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_nxdomain_linux_returns_false(self, mock_gai):
        """EAI_NONAME (-2) → domain does not exist."""
        mock_gai.side_effect = socket.gaierror(-2, "Name or service not known")
        assert domain_is_resolvable("expired-domain-xyz.com") is False

    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_enoent_returns_false(self, mock_gai):
        """errno.ENOENT → domain does not exist."""
        import errno as errno_mod
        mock_gai.side_effect = socket.gaierror(errno_mod.ENOENT, "No such file or directory")
        assert domain_is_resolvable("expired-domain-xyz.com") is False

    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_windows_not_found_returns_false(self, mock_gai):
        """WSAHOST_NOT_FOUND (11001) → domain does not exist."""
        mock_gai.side_effect = socket.gaierror(11001, "No such host is known")
        assert domain_is_resolvable("expired-domain-xyz.com") is False

    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_eai_again_keeps_entry(self, mock_gai):
        """EAI_AGAIN (-3, transient failure) → keep the entry conservatively."""
        mock_gai.side_effect = socket.gaierror(-3, "Temporary failure in name resolution")
        assert domain_is_resolvable("example.com") is True

    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_other_gaierror_keeps_entry(self, mock_gai):
        """Any other gaierror → keep the entry."""
        mock_gai.side_effect = socket.gaierror(-4, "Unknown DNS error")
        assert domain_is_resolvable("example.com") is True

    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_os_error_keeps_entry(self, mock_gai):
        """Generic OSError → keep the entry."""
        mock_gai.side_effect = OSError("unexpected OS error")
        assert domain_is_resolvable("example.com") is True


# ---------------------------------------------------------------------------
# main()  (end-to-end, using a temp file and mocked DNS)
# ---------------------------------------------------------------------------

class TestMain:
    """Integration tests for the main() orchestration function."""

    BLACKLIST_CONTENT = textwrap.dedent("""\
        *://goods.taobao.com/*
        *://*.eyewated.com/*
        *://www.iodraw.com/blog/*
        *://*.expireddomain.com/*
        *://*.another-expired.org/*
        *://*.226.195/*
    """)
    # taobao.com, eyewated.com, iodraw.com → resolvable
    # expireddomain.com, another-expired.org → not resolvable (NXDOMAIN)
    # 226.195 → no registrable domain, should be kept regardless

    def _write_blacklist(self, tmp_path, content: str) -> str:
        p = tmp_path / "blacklist.txt"
        p.write_text(content, encoding="utf-8")
        return str(p)

    def _make_dns_mock(self, unresolvable_domains: set) -> MagicMock:
        """Return a mock for socket.getaddrinfo that raises gaierror(-2) for
        unresolvable_domains and returns a fake result for all others."""
        def _gai(domain, port, **kwargs):
            if domain in unresolvable_domains:
                raise socket.gaierror(-2, "Name or service not known")
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]
        mock = MagicMock(side_effect=_gai)
        return mock

    @patch("cleanup_expired_domains.time.sleep")  # skip actual delays
    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_no_expired_domains_leaves_file_unchanged(self, mock_gai, mock_sleep, tmp_path):
        path = self._write_blacklist(tmp_path, self.BLACKLIST_CONTENT)
        mock_gai.side_effect = self._make_dns_mock(unresolvable_domains=set()).side_effect

        result = main(blacklist_path=path, delay=0)

        assert result == 0
        with open(path, encoding="utf-8") as f:
            assert f.read() == self.BLACKLIST_CONTENT

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_expired_domains_are_removed(self, mock_gai, mock_sleep, tmp_path):
        path = self._write_blacklist(tmp_path, self.BLACKLIST_CONTENT)
        mock_gai.side_effect = self._make_dns_mock(
            unresolvable_domains={"expireddomain.com", "another-expired.org"}
        ).side_effect

        result = main(blacklist_path=path, delay=0)

        assert result == 0
        with open(path, encoding="utf-8") as f:
            remaining = f.read()
        assert "*://*.expireddomain.com/*\n" not in remaining
        assert "*://*.another-expired.org/*\n" not in remaining
        # Non-expired entries must still be present
        assert "*://goods.taobao.com/*\n" in remaining
        assert "*://*.eyewated.com/*\n" in remaining
        assert "*://www.iodraw.com/blog/*\n" in remaining

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_unresolvable_host_lines_are_kept(self, mock_gai, mock_sleep, tmp_path):
        """Lines without a valid registrable domain must never be removed."""
        path = self._write_blacklist(tmp_path, self.BLACKLIST_CONTENT)
        mock_gai.side_effect = self._make_dns_mock(unresolvable_domains=set()).side_effect

        main(blacklist_path=path, delay=0)

        with open(path, encoding="utf-8") as f:
            assert "*://*.226.195/*\n" in f.read()

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_multiple_lines_same_domain_all_removed(self, mock_gai, mock_sleep, tmp_path):
        """Multiple entries sharing a domain are all removed together."""
        content = (
            "*://sub1.expireddomain.com/*\n"
            "*://*.expireddomain.com/*\n"
            "*://www.gooddomain.com/*\n"
        )
        path = self._write_blacklist(tmp_path, content)
        mock_gai.side_effect = self._make_dns_mock(
            unresolvable_domains={"expireddomain.com"}
        ).side_effect

        main(blacklist_path=path, delay=0)

        with open(path, encoding="utf-8") as f:
            remaining = f.read()
        assert "expireddomain.com" not in remaining
        assert "*://www.gooddomain.com/*\n" in remaining

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_dns_error_keeps_entry(self, mock_gai, mock_sleep, tmp_path):
        """When DNS lookup fails with a transient error the entry must be preserved."""
        content = "*://*.example.com/*\n"
        path = self._write_blacklist(tmp_path, content)
        mock_gai.side_effect = socket.gaierror(-3, "Temporary failure in name resolution")

        main(blacklist_path=path, delay=0)

        with open(path, encoding="utf-8") as f:
            assert f.read() == content

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_empty_blacklist(self, mock_gai, mock_sleep, tmp_path):
        path = self._write_blacklist(tmp_path, "")
        result = main(blacklist_path=path, delay=0)
        assert result == 0
        mock_gai.assert_not_called()

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.socket.getaddrinfo")
    def test_delay_is_applied_between_requests(self, mock_gai, mock_sleep, tmp_path):
        """time.sleep should be called (n_domains - 1) times."""
        content = (
            "*://www.alpha.com/*\n"
            "*://www.beta.com/*\n"
            "*://www.gamma.com/*\n"
        )
        path = self._write_blacklist(tmp_path, content)
        mock_gai.side_effect = self._make_dns_mock(unresolvable_domains=set()).side_effect

        main(blacklist_path=path, delay=0.5)

        # 3 domains → sleep called exactly 2 times (between consecutive requests)
        assert mock_sleep.call_count == 2
        mock_sleep.assert_called_with(0.5)

