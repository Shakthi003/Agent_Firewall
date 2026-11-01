"""The secret scanner must catch real-looking secrets and ignore placeholders."""

from pathlib import Path

from scripts.secret_scan import scan_file


def test_detects_google_style_key(tmp_path: Path) -> None:
    f = tmp_path / "leak.txt"
    f.write_text("KEY=" + "AIza" + "B" * 35)
    assert scan_file(f)


def test_detects_private_key_block(tmp_path: Path) -> None:
    f = tmp_path / "leak.pem.txt"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\n")  # secret-scan: ignore
    assert scan_file(f)


def test_ignores_placeholder_values(tmp_path: Path) -> None:
    f = tmp_path / "ok.txt"
    f.write_text("POSTGRES_PASSWORD=change-me\nGEMINI_API_KEY=\n")
    assert scan_file(f) == []


def test_ignore_marker_allows_known_fake(tmp_path: Path) -> None:
    f = tmp_path / "fake.txt"
    f.write_text("token = abcdefghijklmnop1234  # secret-scan: ignore\n")
    assert scan_file(f) == []
