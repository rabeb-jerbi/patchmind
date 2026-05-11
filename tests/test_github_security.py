"""
tests/test_github_security.py
Tests for _validate_git_url() — the SSRF/injection guard for GitHub scans.
No HTTP calls or subprocess calls are made; this is pure Python logic.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from dashboard.app import _validate_git_url


# ─── Valid URLs ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://github.com/user/repo",
    "https://github.com/org/project.git",
    "https://gitlab.com/group/subgroup/repo",
    "https://bitbucket.org/team/repo",
    "http://github.com/user/repo",   # http is allowed
])
def test_valid_url_passes(url):
    _validate_git_url(url)  # must not raise


# ─── Blocked: localhost / loopback ────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://localhost/repo",
    "http://localhost:8080/repo",
    "https://127.0.0.1/repo",
    "https://127.0.0.2/repo",
    "https://[::1]/repo",
])
def test_loopback_rejected(url):
    with pytest.raises(ValueError):
        _validate_git_url(url)


# ─── Blocked: private IP ranges ──────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://10.0.0.1/repo",
    "https://10.255.255.255/repo",
    "https://192.168.1.1/repo",
    "https://192.168.0.100/repo",
    "https://172.16.0.1/repo",
    "https://172.31.255.255/repo",
    "https://169.254.169.254/latest/meta-data/",   # AWS metadata
    "https://169.254.0.1/repo",
])
def test_private_ip_rejected(url):
    with pytest.raises(ValueError):
        _validate_git_url(url)


# ─── Blocked: non-git-host domains ───────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://evil.com/user/repo",
    "https://github.com.evil.com/user/repo",
    "https://notgithub.com/repo",
    "https://internal-git.company.com/repo",
    "https://raw.githubusercontent.com/user/repo",   # subdomain not in allowlist
])
def test_unknown_host_rejected(url):
    with pytest.raises(ValueError):
        _validate_git_url(url)


# ─── Blocked: non-HTTP schemes ───────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "git://github.com/user/repo",
    "ssh://github.com/user/repo",
    "file:///etc/passwd",
    "ftp://github.com/repo",
    "data:text/html,<script>alert(1)</script>",
])
def test_non_http_scheme_rejected(url):
    with pytest.raises(ValueError):
        _validate_git_url(url)


# ─── Blocked: git option injection ───────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://github.com/-u/repo",
    "https://github.com/--upload-pack=/bin/sh/repo",
])
def test_option_injection_rejected(url):
    with pytest.raises(ValueError):
        _validate_git_url(url)


# ─── Blocked: too long / empty ───────────────────────────────────────────────

def test_empty_url_rejected():
    with pytest.raises(ValueError):
        _validate_git_url("")


def test_none_rejected():
    with pytest.raises((ValueError, AttributeError, TypeError)):
        _validate_git_url(None)


def test_url_too_long_rejected():
    long_url = "https://github.com/user/" + "a" * 600
    with pytest.raises(ValueError):
        _validate_git_url(long_url)


def test_missing_hostname_rejected():
    with pytest.raises(ValueError):
        _validate_git_url("https:///path")


# ─── Verify allowed hosts whitelist ──────────────────────────────────────────

def test_allowed_hosts_are_github_gitlab_bitbucket():
    from dashboard.app import _GIT_ALLOWED_HOSTS
    assert "github.com" in _GIT_ALLOWED_HOSTS
    assert "gitlab.com" in _GIT_ALLOWED_HOSTS
    assert "bitbucket.org" in _GIT_ALLOWED_HOSTS
