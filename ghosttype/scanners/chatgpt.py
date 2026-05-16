from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ghosttype.models import ConversationRecord, TextChunk
from ghosttype.scanners.base import Scanner

logger = logging.getLogger(__name__)

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
        """Attempt AES-128-CBC decryption of a ChatGPT .data file.

        Electron safeStorage on macOS uses Chrome OSCrypt: AES-128-CBC, key from
        Keychain via PBKDF2-HMAC-SHA1(salt=b'saltysalt', iterations=1003, dklen=16),
        IV = 16 space bytes, data prefixed with b'v10' or b'v11'.
        """
        key_bytes = self._get_keychain_key()
        if not key_bytes:
            return None

        try:
            raw = path.read_bytes()
        except OSError:
            return None

        prefix = raw[:3]
        if prefix not in (b"v10", b"v11"):
            return None

        try:
            from hashlib import pbkdf2_hmac
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding as sym_padding

            key = pbkdf2_hmac("sha1", key_bytes, b"saltysalt", 1003, dklen=16)
            iv = b" " * 16
            ciphertext = raw[3:]
            # SECURITY (SSCS B3, true-positive, evidence-based exception):
            # semgrep flags AES-CBC-without-authentication. This is a forensic
            # DECRYPTOR of Chromium/Electron OSCrypt files (ChatGPT app),
            # whose on-disk scheme is fixed AES-128-CBC by Chromium's design.
            # ghosttype did not encrypt this data and cannot add an auth tag;
            # an authenticated mode (GCM) would simply fail to decrypt the
            # target's existing files. Read-only, authorized-use forensic
            # interop — the scanner cannot model "matching an external fixed
            # format" vs "choosing a mode". Narrow line-scoped suppression,
            # logged in the SSCS ISA ## Decisions (no global/path ignore).
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # nosemgrep: python.cryptography.security.mode-without-authentication.crypto-mode-without-authentication
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext_bytes = unpadder.update(padded) + unpadder.finalize()
            return plaintext_bytes.decode("utf-8", errors="replace")
        except (ValueError, KeyError, UnicodeDecodeError, TypeError):
            logger.debug("Decryption failed for %s", path, exc_info=True)
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
