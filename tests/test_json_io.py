"""tests/test_json_io.py — Unit tests for utils/json_io.py."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import threading
import tempfile
import pytest

from utils.json_io import read_json, write_json, locked_update


# ─── read_json ────────────────────────────────────────────────────────────────

def test_read_json_returns_dict(tmp_path):
    p = tmp_path / "data.json"
    p.write_text('{"key": "value"}', encoding="utf-8")
    assert read_json(str(p)) == {"key": "value"}


def test_read_json_missing_file_returns_default(tmp_path):
    result = read_json(str(tmp_path / "nonexistent.json"))
    assert result == {}


def test_read_json_missing_file_custom_default(tmp_path):
    result = read_json(str(tmp_path / "nonexistent.json"), default=[])
    assert result == []


def test_read_json_corrupted_file_returns_default(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json{{{{", encoding="utf-8")
    result = read_json(str(p))
    assert result == {}
    # File should be renamed to .corrupt
    assert (tmp_path / "bad.json.corrupt").exists()


def test_read_json_corrupted_file_custom_default(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("NOT JSON", encoding="utf-8")
    result = read_json(str(p), default={"fallback": True})
    assert result == {"fallback": True}


def test_read_json_list(tmp_path):
    p = tmp_path / "list.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    result = read_json(str(p), default=[])
    assert result == [1, 2, 3]


def test_read_json_empty_file_returns_default(tmp_path):
    p = tmp_path / "empty.json"
    p.write_bytes(b"")
    result = read_json(str(p), default={"empty": True})
    assert result == {"empty": True}


# ─── write_json ───────────────────────────────────────────────────────────────

def test_write_json_creates_file(tmp_path):
    p = str(tmp_path / "out.json")
    write_json(p, {"hello": "world"})
    with open(p, encoding="utf-8") as f:
        assert json.load(f) == {"hello": "world"}


def test_write_json_overwrites(tmp_path):
    p = str(tmp_path / "out.json")
    write_json(p, {"v": 1})
    write_json(p, {"v": 2})
    assert read_json(p) == {"v": 2}


def test_write_json_creates_parent_dirs(tmp_path):
    p = str(tmp_path / "nested" / "dir" / "file.json")
    write_json(p, {"x": 1})
    assert json.loads(open(p).read()) == {"x": 1}


def test_write_json_atomic(tmp_path):
    """write_json must leave no .tmp file behind on success."""
    p = tmp_path / "out.json"
    write_json(str(p), {"ok": True})
    tmp_files = list(tmp_path.glob("*.tmp"))
    assert tmp_files == []


def test_write_json_list(tmp_path):
    p = str(tmp_path / "list.json")
    write_json(p, [1, 2, 3])
    assert read_json(p, default=[]) == [1, 2, 3]


def test_write_read_roundtrip_unicode(tmp_path):
    data = {"msg": "héllo wörld — données 中文"}
    p = str(tmp_path / "unicode.json")
    write_json(p, data)
    assert read_json(p) == data


# ─── locked_update ────────────────────────────────────────────────────────────

def test_locked_update_transforms_data(tmp_path):
    p = str(tmp_path / "counter.json")
    write_json(p, {"count": 0})
    result = locked_update(p, lambda d: {**d, "count": d["count"] + 1})
    assert result == {"count": 1}
    assert read_json(p) == {"count": 1}


def test_locked_update_missing_file_uses_default(tmp_path):
    p = str(tmp_path / "new.json")
    result = locked_update(p, lambda d: {**d, "x": 1}, default={"x": 0})
    assert result == {"x": 1}


def test_locked_update_persists_new_data(tmp_path):
    p = str(tmp_path / "data.json")
    locked_update(p, lambda _: {"created": True})
    assert read_json(p) == {"created": True}


def test_locked_update_concurrent_safety(tmp_path):
    """Multiple threads incrementing a counter must not lose updates."""
    p = str(tmp_path / "counter.json")
    write_json(p, {"n": 0})
    errors = []

    def increment():
        try:
            locked_update(p, lambda d: {"n": d["n"] + 1})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=increment) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    final = read_json(p)
    assert final["n"] == 20


def test_locked_update_returns_new_data(tmp_path):
    p = str(tmp_path / "d.json")
    returned = locked_update(p, lambda _: {"tag": "new"})
    assert returned == {"tag": "new"}
