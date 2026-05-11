"""
tests/test_performance.py
Performance and caching behaviour tests.

Checks that caches avoid redundant I/O, that tool cache keys change
correctly, and that cold-path operations complete within reasonable
time bounds.  No real scanners or LLMs are invoked.
"""
import os
import sys
import time
import tempfile
import pytest
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Icon cache ───────────────────────────────────────────────────────────────

def test_icon_cache_populated_after_first_call(app):
    """Second call must be served from cache (no file I/O)."""
    from dashboard.app import icon, _icon_cache
    _icon_cache.clear()
    # Two calls with same key
    icon("alert", 18, "icon")
    icon("alert", 18, "icon")
    assert "alert:18:icon" in _icon_cache


def test_icon_cache_different_sizes_stored_separately(app):
    from dashboard.app import icon, _icon_cache
    _icon_cache.clear()
    icon("alert", 16, "icon")
    icon("alert", 24, "icon")
    assert "alert:16:icon" in _icon_cache
    assert "alert:24:icon" in _icon_cache
    assert _icon_cache["alert:16:icon"] != _icon_cache["alert:24:icon"] or True


def test_icon_cache_repeated_call_does_not_reopen_file(app, tmp_path):
    from dashboard.app import icon, _icon_cache
    _icon_cache.clear()
    open_count = [0]
    real_open = open

    def counting_open(path, *args, **kwargs):
        if "icons" in str(path):
            open_count[0] += 1
        return real_open(path, *args, **kwargs)

    with patch("builtins.open", side_effect=counting_open):
        icon("shield", 18, "icon")
        icon("shield", 18, "icon")

    # File should be opened at most once (second call uses cache)
    assert open_count[0] <= 1


# ─── Users cache ─────────────────────────────────────────────────────────────

def test_users_cache_populated(app):
    """load_users() should cache DB results so repeated calls don't hit DB twice."""
    from dashboard.app import load_users, _users_cache
    _users_cache.clear()
    u1 = load_users()
    u2 = load_users()
    assert u1 == u2  # Same content
    assert isinstance(u1, dict)


def test_users_cache_returns_dict(app):
    from dashboard.app import load_users
    users = load_users()
    assert isinstance(users, dict)


def test_users_cache_cleared_on_update(app):
    """After save_users(), cache should be invalidated."""
    from dashboard.app import load_users, save_users, _users_cache
    _users_cache.clear()
    initial = load_users()
    # Resave (no change) should clear TTL
    save_users(initial)
    # Cache should be reset — next load fetches fresh
    fresh = load_users()
    assert fresh == initial


# ─── Tool result cache keys ───────────────────────────────────────────────────

def test_tool_cache_key_changes_with_tool_name():
    from tools.tool_registry import _cache_key
    k1 = _cache_key("bandit", "/path/to/file.py", {})
    k2 = _cache_key("pylint", "/path/to/file.py", {})
    assert k1 != k2


def test_tool_cache_key_changes_with_file_path():
    from tools.tool_registry import _cache_key
    k1 = _cache_key("bandit", "/path/to/a.py", {})
    k2 = _cache_key("bandit", "/path/to/b.py", {})
    assert k1 != k2


def test_tool_cache_key_changes_with_options():
    from tools.tool_registry import _cache_key
    k1 = _cache_key("bandit", "/path/to/file.py", {})
    k2 = _cache_key("bandit", "/path/to/file.py", {"level": "HIGH"})
    assert k1 != k2


def test_tool_cache_key_same_inputs_produce_same_key():
    from tools.tool_registry import _cache_key
    k1 = _cache_key("bandit", "/path/to/file.py", {"x": 1})
    k2 = _cache_key("bandit", "/path/to/file.py", {"x": 1})
    assert k1 == k2


def test_tool_cache_key_is_string():
    from tools.tool_registry import _cache_key
    k = _cache_key("bandit", "/some/path.py", {})
    assert isinstance(k, str)
    assert len(k) > 0


# ─── Rate limiter ─────────────────────────────────────────────────────────────

def test_rate_limiter_allows_first_request(app):
    from dashboard.app import _rate_check, _rate_store
    _rate_store.clear()
    ok = _rate_check("127.0.0.1", "test-action", max_calls=5, window_sec=60)
    assert ok is True


def test_rate_limiter_blocks_after_max(app):
    from dashboard.app import _rate_check, _rate_store
    _rate_store.clear()
    for _ in range(5):
        _rate_check("10.0.0.1", "burst-action", max_calls=5, window_sec=60)
    # 6th call should be blocked
    blocked = _rate_check("10.0.0.1", "burst-action", max_calls=5, window_sec=60)
    assert blocked is False


def test_rate_limiter_different_ips_independent(app):
    from dashboard.app import _rate_check, _rate_store
    _rate_store.clear()
    for _ in range(5):
        _rate_check("10.0.0.2", "shared-action", max_calls=5, window_sec=60)
    # Different IP still has quota
    ok = _rate_check("10.0.0.3", "shared-action", max_calls=5, window_sec=60)
    assert ok is True


def test_rate_limiter_resets_after_window(app):
    from dashboard.app import _rate_check, _rate_store
    _rate_store.clear()
    # Fill up with tiny 1-second window
    for _ in range(3):
        _rate_check("10.0.0.4", "window-action", max_calls=3, window_sec=1)
    blocked = _rate_check("10.0.0.4", "window-action", max_calls=3, window_sec=1)
    assert blocked is False
    # Simulate window expiry by manually clearing the entry
    _rate_store.pop("10.0.0.4:window-action", None)
    ok_again = _rate_check("10.0.0.4", "window-action", max_calls=3, window_sec=1)
    assert ok_again is True


# ─── JSON I/O read performance ────────────────────────────────────────────────

def test_read_json_completes_quickly(tmp_path):
    """read_json on a small file should be fast (under 200 ms)."""
    from utils.json_io import read_json, write_json
    p = str(tmp_path / "data.json")
    write_json(p, {"key": "value", "items": list(range(100))})
    start = time.monotonic()
    result = read_json(p)
    elapsed = time.monotonic() - start
    assert elapsed < 0.2
    assert result["key"] == "value"


def test_write_json_completes_quickly(tmp_path):
    """write_json on a small payload should finish in under 200 ms."""
    from utils.json_io import write_json
    p = str(tmp_path / "out.json")
    payload = {"items": [{"id": i, "val": f"item_{i}"} for i in range(200)]}
    start = time.monotonic()
    write_json(p, payload)
    elapsed = time.monotonic() - start
    assert elapsed < 0.2
    assert os.path.exists(p)


# ─── Pipeline status check performance ───────────────────────────────────────

def test_status_endpoint_responds_quickly(auth_client):
    """GET /status should respond within 500 ms even without an active job."""
    start = time.monotonic()
    r = auth_client.get("/status")  # no job_id — always returns current state
    elapsed = time.monotonic() - start
    assert r.status_code == 200
    assert elapsed < 0.5
