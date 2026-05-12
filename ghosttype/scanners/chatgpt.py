from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

_KEYCHAIN_SERVICES = [
    "ChatGPT Safe Storage",
    "com.openai.chat Safe Storage",
    "Electron Safe Storage",
]


class ChatGPTScanner(Scanner):
    name = "chatgpt"
    display_name = "ChatGPT Desktop"

    @property
    def _base_path(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "com.openai.chat"

    def discover(self) -> list[ConversationRecord]:
        if not self.is_available():
            return []
        records: list[ConversationRecord] = []
        for data_file in self._base_path.rglob("conversations-v3-*/*.data"):
            stat = data_file.stat()
            records.append(ConversationRecord(
                source_path=data_file,
                tool=self.name,
                conversation_id=data_file.stem,
                created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                raw=None,
            ))
        return records

    def _get_keychain_key(self) -> bytes | None:
        """Attempt to retrieve the Electron Safe Storage key from macOS Keychain."""
        for service in _KEYCHAIN_SERVICES:
            try:
                result = subprocess.run(
                    ["security", "find-generic-password", "-w", "-s", service],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip().encode()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return None

    def _decrypt(self, path: Path) -> str | None:
        """Attempt AES-256-GCM decryption of a ChatGPT .data file.

        Returns decrypted string on success, None on failure.
        Electron safeStorage on macOS: data is prefixed with b'v10' or b'v11',
        followed by AES-256-GCM ciphertext. Key is from Keychain via PBKDF2.
        """
        raw = path.read_bytes()
        key_bytes = self._get_keychain_key()
        if not key_bytes:
            return None

        # Chrome/Electron v10 prefix on macOS
        prefix = raw[:3]
        if prefix not in (b"v10", b"v11"):
            return None

        try:
            from hashlib import pbkdf2_hmac
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Derive 256-bit key: PBKDF2-HMAC-SHA1, salt=b'saltysalt', iterations=1003
            key = pbkdf2_hmac("sha1", key_bytes, b"saltysalt", 1003, dklen=32)
            # iv: 16 space bytes (Electron standard)
            iv = b" " * 16
            ciphertext = raw[3:]
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            return plaintext.decode("utf-8", errors="replace")
        except Exception:
            return None

    def extract_text(self, record: ConversationRecord) -> list[TextChunk]:
        plaintext = self._decrypt(record.source_path)
        if not plaintext:
            return []

        chunks: list[TextChunk] = []
        try:
            data = json.loads(plaintext)
        except json.JSONDecodeError:
            # Treat as plain text
            chunks.append(TextChunk(text=plaintext, position="line:1", record=record))
            return chunks

        # ChatGPT conversation JSON: {"mapping": {msg_id: {"message": {"content": {"parts": [...]}}}}}
        mapping = data.get("mapping", {})
        for i, (msg_id, node) in enumerate(mapping.items(), start=1):
            msg = node.get("message") or {}
            content = msg.get("content") or {}
            parts = content.get("parts", [])
            text = " ".join(str(p) for p in parts if p)
            if text.strip():
                chunks.append(TextChunk(
                    text=text,
                    position=f"line:{i}",
                    record=record,
                ))
        return chunks
