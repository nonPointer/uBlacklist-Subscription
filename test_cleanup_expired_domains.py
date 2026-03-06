"""
Unit and integration tests for cleanup_expired_domains.py.

Run with:
    pytest test_cleanup_expired_domains.py -v
"""

import textwrap
from unittest.mock import MagicMock, patch

import pytest

from cleanup_expired_domains import (
    domain_exists_rdap,
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
# domain_exists_rdap  (HTTP responses are mocked)
# ---------------------------------------------------------------------------

class TestDomainExistsRdap:
    """Tests for the domain_exists_rdap() function with mocked HTTP."""

    def _mock_response(self, status_code: int) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        return resp

    @patch("cleanup_expired_domains.requests.get")
    def test_http_200_returns_true(self, mock_get):
        mock_get.return_value = self._mock_response(200)
        assert domain_exists_rdap("example.com") is True

    @patch("cleanup_expired_domains.requests.get")
    def test_http_404_returns_false(self, mock_get):
        mock_get.return_value = self._mock_response(404)
        assert domain_exists_rdap("expired-domain-xyz.com") is False

    @patch("cleanup_expired_domains.requests.get")
    def test_http_429_keeps_entry(self, mock_get):
        """Rate-limited response should be treated as 'exists' (keep entry)."""
        mock_get.return_value = self._mock_response(429)
        assert domain_exists_rdap("example.com") is True

    @patch("cleanup_expired_domains.requests.get")
    def test_http_500_keeps_entry(self, mock_get):
        """Server errors should be treated as 'exists' (keep entry)."""
        mock_get.return_value = self._mock_response(500)
        assert domain_exists_rdap("example.com") is True

    @patch("cleanup_expired_domains.requests.get")
    def test_network_error_keeps_entry(self, mock_get):
        """Network failures should be treated as 'exists' (keep entry)."""
        import requests as req_lib
        mock_get.side_effect = req_lib.exceptions.ConnectionError("unreachable")
        assert domain_exists_rdap("example.com") is True

    @patch("cleanup_expired_domains.requests.get")
    def test_timeout_keeps_entry(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = req_lib.exceptions.Timeout("timed out")
        assert domain_exists_rdap("example.com") is True

    @patch("cleanup_expired_domains.requests.get")
    def test_correct_url_is_requested(self, mock_get):
        mock_get.return_value = self._mock_response(200)
        domain_exists_rdap("taobao.com")
        mock_get.assert_called_once_with(
            "https://rdap.org/domain/taobao.com",
            timeout=15,
            allow_redirects=True,
        )


# ---------------------------------------------------------------------------
# main()  (end-to-end, using a temp file and mocked RDAP)
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
    # taobao.com, eyewated.com, iodraw.com → exist
    # expireddomain.com, another-expired.org → expired (404)
    # 226.195 → no registrable domain, should be kept regardless

    def _write_blacklist(self, tmp_path, content: str) -> str:
        p = tmp_path / "blacklist.txt"
        p.write_text(content, encoding="utf-8")
        return str(p)

    def _make_rdap_mock(self, expired_domains: set) -> MagicMock:
        """Return a mock for requests.get that returns 404 for expired_domains."""
        def _get(url, **kwargs):
            resp = MagicMock()
            domain = url.replace("https://rdap.org/domain/", "")
            resp.status_code = 404 if domain in expired_domains else 200
            return resp
        mock = MagicMock(side_effect=_get)
        return mock

    @patch("cleanup_expired_domains.time.sleep")  # skip actual delays
    @patch("cleanup_expired_domains.requests.get")
    def test_no_expired_domains_leaves_file_unchanged(self, mock_get, mock_sleep, tmp_path):
        path = self._write_blacklist(tmp_path, self.BLACKLIST_CONTENT)
        mock_get.side_effect = self._make_rdap_mock(expired_domains=set()).side_effect

        result = main(blacklist_path=path, delay=0)

        assert result == 0
        with open(path, encoding="utf-8") as f:
            assert f.read() == self.BLACKLIST_CONTENT

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.requests.get")
    def test_expired_domains_are_removed(self, mock_get, mock_sleep, tmp_path):
        path = self._write_blacklist(tmp_path, self.BLACKLIST_CONTENT)
        mock_get.side_effect = self._make_rdap_mock(
            expired_domains={"expireddomain.com", "another-expired.org"}
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
    @patch("cleanup_expired_domains.requests.get")
    def test_unresolvable_host_lines_are_kept(self, mock_get, mock_sleep, tmp_path):
        """Lines without a valid registrable domain must never be removed."""
        path = self._write_blacklist(tmp_path, self.BLACKLIST_CONTENT)
        mock_get.side_effect = self._make_rdap_mock(expired_domains=set()).side_effect

        main(blacklist_path=path, delay=0)

        with open(path, encoding="utf-8") as f:
            assert "*://*.226.195/*\n" in f.read()

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.requests.get")
    def test_multiple_lines_same_domain_all_removed(self, mock_get, mock_sleep, tmp_path):
        """Multiple entries sharing a domain are all removed together."""
        content = (
            "*://sub1.expireddomain.com/*\n"
            "*://*.expireddomain.com/*\n"
            "*://www.gooddomain.com/*\n"
        )
        path = self._write_blacklist(tmp_path, content)
        mock_get.side_effect = self._make_rdap_mock(
            expired_domains={"expireddomain.com"}
        ).side_effect

        main(blacklist_path=path, delay=0)

        with open(path, encoding="utf-8") as f:
            remaining = f.read()
        assert "expireddomain.com" not in remaining
        assert "*://www.gooddomain.com/*\n" in remaining

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.requests.get")
    def test_network_error_keeps_entry(self, mock_get, mock_sleep, tmp_path):
        """When RDAP is unreachable the entry must be preserved."""
        import requests as req_lib
        content = "*://*.example.com/*\n"
        path = self._write_blacklist(tmp_path, content)
        mock_get.side_effect = req_lib.exceptions.ConnectionError("unreachable")

        main(blacklist_path=path, delay=0)

        with open(path, encoding="utf-8") as f:
            assert f.read() == content

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.requests.get")
    def test_empty_blacklist(self, mock_get, mock_sleep, tmp_path):
        path = self._write_blacklist(tmp_path, "")
        result = main(blacklist_path=path, delay=0)
        assert result == 0
        mock_get.assert_not_called()

    @patch("cleanup_expired_domains.time.sleep")
    @patch("cleanup_expired_domains.requests.get")
    def test_delay_is_applied_between_requests(self, mock_get, mock_sleep, tmp_path):
        """time.sleep should be called (n_domains - 1) times."""
        content = (
            "*://www.alpha.com/*\n"
            "*://www.beta.com/*\n"
            "*://www.gamma.com/*\n"
        )
        path = self._write_blacklist(tmp_path, content)
        mock_get.side_effect = self._make_rdap_mock(expired_domains=set()).side_effect

        main(blacklist_path=path, delay=0.5)

        # 3 domains → sleep called exactly 2 times (between consecutive requests)
        assert mock_sleep.call_count == 2
        mock_sleep.assert_called_with(0.5)
