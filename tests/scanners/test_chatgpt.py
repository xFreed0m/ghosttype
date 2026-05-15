from pathlib import Path
from datetime import datetime, timezone

import pytest

from ghosttype.scanners.chatgpt import ChatGPTScanner


@pytest.fixture
def chatgpt_dir(tmp_path) -> Path:
    """Synthetic com.openai.chat directory with a fake conversation .data file."""
    uid = "6fe9ba45-4583-4e19-8779-1f05cb8db338"
    conv_dir = tmp_path / f"conversations-v3-{uid}"
    conv_dir.mkdir(parents=True)
    # Write a fake .data file (not real encrypted content - scanner should handle gracefully)
    (conv_dir / "69faed5a-49d8-83eb-aff3-c003fc3bffe2.data").write_bytes(b"\xed\x80\xb9\x88fake")
    return tmp_path


def test_scanner_name():
    assert ChatGPTScanner().name == "chatgpt"


def test_not_available_when_dir_missing(tmp_path, monkeypatch):
    s = ChatGPTScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path / "nonexistent"))
    assert s.is_available() is False


def test_discover_finds_data_files(chatgpt_dir, monkeypatch):
    s = ChatGPTScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: chatgpt_dir))
    records = s.discover()
    assert len(records) == 1
    assert records[0].tool == "chatgpt"
    assert records[0].source_path.suffix == ".data"


def test_extract_text_returns_empty_on_undecryptable_file(chatgpt_dir, monkeypatch):
    """When decryption fails, extract_text returns empty (graceful degradation)."""
    s = ChatGPTScanner()
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: chatgpt_dir))
    records = s.discover()
    chunks = s.extract_text(records[0])
    assert chunks == []


def test_extract_text_position_on_decrypted_content(tmp_path, monkeypatch):
    """When content is decrypted, position is 'line:N'."""
    import json
    # Simulate a scanner that successfully returns decrypted content
    # by patching _decrypt to return known plaintext
    s = ChatGPTScanner()
    conv_dir = tmp_path / "conversations-v3-test"
    conv_dir.mkdir()
    data_file = conv_dir / "conv-1.data"
    data_file.write_bytes(b"fake")
    monkeypatch.setattr(type(s), "_base_path", property(lambda self: tmp_path))

    fake_json = json.dumps({"mapping": {"msg1": {"message": {"content": {"parts": ["api_key = AKIAIOSFODNN7EXAMPLE"]}}}}})
    monkeypatch.setattr(s, "_decrypt", lambda path: fake_json)

    records = s.discover()
    chunks = s.extract_text(records[0])
    assert any("AKIAIOSFODNN7EXAMPLE" in c.text for c in chunks)
