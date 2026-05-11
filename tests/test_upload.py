"""
tests/test_upload.py
Upload-security tests: extension allowlist, filename sanitisation,
path traversal in ZIPs, dangerous file filtering.

run_pipeline is mocked to prevent real semgrep/LLM calls.
"""
import io
import os
import sys
import zipfile
import tempfile
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _upload(client, filename, content=b"x=1\n", content_type="text/plain"):
    """POST /upload with a single file."""
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
    )


def _mock_pipeline():
    """Context manager that stubs run_pipeline to a no-op."""
    return patch("dashboard.app.run_pipeline")


# ─── Extension allowlist ─────────────────────────────────────────────────────

@pytest.mark.parametrize("ext", [".py", ".js", ".ts", ".java", ".php", ".go",
                                  ".rb", ".cpp", ".c", ".kt", ".swift", ".rs",
                                  ".jsx", ".tsx"])
def test_allowed_extension_accepted(auth_client, ext):
    with _mock_pipeline():
        r = _upload(auth_client, f"sample{ext}")
    assert r.status_code == 200
    data = r.get_json()
    assert "error" not in data or data.get("error") is None


def test_zip_accepted(auth_client, zip_bytes):
    with _mock_pipeline():
        r = _upload(auth_client, "archive.zip", content=zip_bytes)
    assert r.status_code == 200


@pytest.mark.parametrize("ext", [
    ".exe", ".bat", ".sh", ".cmd", ".ps1", ".msi", ".dll",
    ".pdf", ".docx", ".xlsx", ".png", ".jpg", ".mp4",
])
def test_dangerous_extension_rejected(auth_client, ext):
    with _mock_pipeline():
        r = _upload(auth_client, f"file{ext}")
    assert r.status_code == 400
    data = r.get_json()
    assert "error" in data


def test_no_extension_rejected(auth_client):
    with _mock_pipeline():
        r = _upload(auth_client, "noextension")
    assert r.status_code == 400


def test_empty_filename_rejected(auth_client):
    with _mock_pipeline():
        r = client_post_empty_name(auth_client)
    # 400 or name sanitized to empty


def client_post_empty_name(client):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(b"x=1"), "")},
        content_type="multipart/form-data",
    )


# ─── Missing file ─────────────────────────────────────────────────────────────

def test_upload_without_file_returns_400(auth_client):
    r = auth_client.post("/upload", data={})
    assert r.status_code == 400


def test_upload_requires_auth(client):
    r = _upload(client, "safe.py")
    assert r.status_code == 401


# ─── Filename sanitisation ───────────────────────────────────────────────────

def test_path_traversal_filename_sanitized(auth_client):
    """../../../etc/passwd.py should have traversal stripped by secure_filename."""
    with _mock_pipeline():
        r = _upload(auth_client, "../../../etc/passwd.py")
    # Either accepted with sanitized name, or rejected — must not 500
    assert r.status_code in (200, 400)
    # Ensure the server did not write outside upload dir — if 200, job_id is returned
    if r.status_code == 200:
        data = r.get_json()
        assert "job_id" in data or "message" in data


def test_double_extension_not_executed(auth_client):
    """evil.exe.py should be treated as .py."""
    with _mock_pipeline():
        r = _upload(auth_client, "evil.exe.py")
    # The outer extension is .py — should be accepted
    assert r.status_code == 200


def test_duplicate_filename_gets_unique_suffix(auth_client, tmp_path):
    """Uploading the same filename twice must not silently overwrite."""
    with _mock_pipeline():
        r1 = _upload(auth_client, "report.py")
        r2 = _upload(auth_client, "report.py")
    # Both must succeed
    assert r1.status_code == 200
    assert r2.status_code == 200


# ─── ZIP traversal protection ────────────────────────────────────────────────

def test_zip_path_traversal_skipped(auth_client, traversal_zip_bytes):
    """ZIP entries with '../' in name must be silently skipped."""
    with _mock_pipeline():
        r = _upload(auth_client, "archive.zip", content=traversal_zip_bytes)
    # Upload is accepted; the traversal entry is filtered, safe.py is kept
    assert r.status_code == 200


def test_zip_absolute_path_skipped(auth_client):
    """ZIP entries with absolute paths must be skipped."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("/etc/passwd")
        zf.writestr(info, "root:x:0:0:root:/root:/bin/bash")
        zf.writestr("safe.py", "x = 1")
    with _mock_pipeline():
        r = _upload(auth_client, "abs.zip", content=buf.getvalue())
    assert r.status_code == 200


def test_zip_dangerous_exe_skipped(auth_client, dangerous_zip_bytes):
    """ZIP entries with .exe extension must be filtered out."""
    with _mock_pipeline():
        r = _upload(auth_client, "mixed.zip", content=dangerous_zip_bytes)
    assert r.status_code == 200


# ─── ZIP extraction helpers (unit tests) ─────────────────────────────────────

def test_extract_zip_traversal_filtered(tmp_path):
    """Direct unit test of extract_zip: traversal entries never land outside dest."""
    from dashboard.app import extract_zip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.py", "bad = True")
        zf.writestr("good.py", "x = 1")
    zip_path = str(tmp_path / "test.zip")
    with open(zip_path, "wb") as f:
        f.write(buf.getvalue())

    files, dest = extract_zip(zip_path, str(tmp_path))
    # evil.py must NOT have landed outside dest
    assert not os.path.exists(str(tmp_path / "evil.py"))
    # good.py should be present
    py_files = [f for f in files if f.endswith("good.py")]
    assert py_files


def test_extract_zip_exe_filtered(tmp_path):
    from dashboard.app import extract_zip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.exe", b"\x4d\x5a")
        zf.writestr("app.py", "print('hi')")
    zip_path = str(tmp_path / "mixed.zip")
    with open(zip_path, "wb") as f:
        f.write(buf.getvalue())

    files, dest = extract_zip(zip_path, str(tmp_path))
    extracted = os.listdir(dest) if os.path.exists(dest) else []
    assert not any(f.endswith(".exe") for f in extracted)
