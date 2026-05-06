"""
Shared JSON I/O helpers — atomic writes, per-file locking, safe reads.

Public API
----------
read_json(path, default=None)          -> any
write_json(path, data)                 -> None
locked_update(path, update_fn, default=None) -> any
"""
import json
import os
import threading
import tempfile

# ── Per-file lock registry ────────────────────────────────────────────────────
_locks: dict = {}
_locks_mutex = threading.Lock()


def _get_lock(path: str) -> threading.Lock:
    """Return (creating if needed) the per-canonical-path write lock."""
    canonical = os.path.realpath(path)
    with _locks_mutex:
        if canonical not in _locks:
            _locks[canonical] = threading.Lock()
        return _locks[canonical]


def read_json(path: str, default=None):
    """
    Read and return JSON from *path*.

    Returns *default* (empty dict if omitted) when the file is missing.
    On JSON corruption the file is renamed to *.corrupt* and *default* is
    returned, preventing a single bad write from permanently breaking reads.
    """
    if default is None:
        default = {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, ValueError):
        try:
            os.replace(path, path + '.corrupt')
        except OSError:
            pass
        return default
    except Exception:
        return default


def _write_locked(path: str, data) -> None:
    """
    Write *data* as JSON to *path* atomically (temp file + os.replace).
    Caller must already hold the per-file lock.
    """
    dir_ = os.path.dirname(os.path.realpath(path)) or '.'
    os.makedirs(dir_, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dir_, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: str, data) -> None:
    """Acquire the per-file lock and atomically write *data* as JSON."""
    lock = _get_lock(path)
    with lock:
        _write_locked(path, data)


def locked_update(path: str, update_fn, default=None):
    """
    Atomically read → transform → write under a single per-file lock.

    *update_fn* receives the current data (or *default* on miss/corruption)
    and must return the new data to persist.  Returns the new data.
    """
    if default is None:
        default = {}
    lock = _get_lock(path)
    with lock:
        data = read_json(path, default)
        new_data = update_fn(data)
        _write_locked(path, new_data)
        return new_data
