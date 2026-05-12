# Research: AI Tool Conversation Storage Locations

Per-tool findings on where conversation history is stored locally on macOS.
Verified against actual installations on macOS 15.x (Darwin 25.x).

---

## Cursor IDE

**Storage format:** SQLite (`state.vscdb`, VS Code LevelDB format)

**Primary path (macOS):**
```
~/Library/Application Support/Cursor/User/globalStorage/state.vscdb
```

**Secondary paths (workspace-specific):**
```
~/Library/Application Support/Cursor/User/workspaceStorage/<hash>/state.vscdb
```

**Database structure:**
- Table: `cursorDiskKV`
- Conversation keys: `composerData:<uuid>` (one row per conversation/composer session)
- Value: JSON blob with fields including:
  - `richText` - formatted conversation content
  - `text` - plain text version
  - `conversationMap` - full message history keyed by message ID
  - `createdAt` - creation timestamp
  - `composerId` - unique conversation identifier

**Table: `ItemTable`**
- Key `composer.composerHeaders` - index of all composer sessions
- Other keys: settings, state, but no conversation content

**Discovery strategy:**
1. Glob `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb`
2. Also glob `~/Library/Application Support/Cursor/User/workspaceStorage/*/state.vscdb`
3. For each `.vscdb`, query `SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'`
4. Parse JSON value, extract conversation text from `conversationMap` and `text` fields

**Notes:**
- The `cursorDiskKV` table is Cursor-specific; the `ItemTable` is shared VS Code storage
- Composer sessions (Ctrl+I) and chat sessions may be stored separately - needs further investigation for chat panel history
- Workspace storage requires knowing workspace hashes; enumerate all subdirs

---

## ChatGPT Desktop (macOS)

**Storage format:** Proprietary binary `.data` files (encrypted)

**Primary path (macOS):**
```
~/Library/Application Support/com.openai.chat/conversations-v3-<user-uuid>/<conversation-uuid>.data
```

**Encryption status:** CONFIRMED ENCRYPTED
- Files are not zlib, gzip, lzma, or raw JSON
- No readable ASCII strings present
- Likely encrypted with a key from macOS Keychain (standard pattern for Electron apps using `safeStorage` API)
- Keychain service name likely: `ChatGPT` or `com.openai.chat`

**Discovery strategy (v1):**
- Enumerate `.data` files under the `conversations-v3-*` directory
- Attempt macOS Keychain extraction via `security find-generic-password` to get the decryption key
- If Keychain key unavailable, report file paths only (no content extraction)

**Decryption research needed:**
- Identify Keychain entry: `security find-generic-password -s "ChatGPT" -g`
- Electron `safeStorage` on macOS uses AES-256-GCM with a key derived from Keychain
- The key is prefixed with `v10` or `v11` in the data file (same pattern as Chrome cookies)
- Decryption: `AES-256-GCM`, key from PBKDF2 of Keychain password + fixed salt

**Status:** Partial - file discovery works; decryption requires Keychain access (needs macOS authorization or elevated privileges)

---

## Codex CLI (OpenAI)

**Storage format:** SQLite databases

**Primary paths (macOS):**
```
~/.codex/state_5.sqlite      # conversation threads and metadata
~/.codex/logs_2.sqlite       # execution logs
~/.codex/memories/           # persistent memory files
```

**Database structure (`state_5.sqlite`):**
- Table: `threads` - conversation sessions with metadata
  - Fields: `id`, `title`, `first_user_message`, `model`, `cwd`, `created_at`, `updated_at`
  - `first_user_message` contains the opening prompt (useful for triage)
- Table: `stage1_outputs` - conversation summaries (may be empty if feature unused)
- Table: `agent_jobs` / `agent_job_items` - task execution records

**Note:** The actual full conversation turn-by-turn content may be in a separate location not yet identified. The `threads` table has metadata only; full message logs may be in `logs_2.sqlite` (`feedback_log_body` field) or in per-thread files.

**Follow-up research needed:**
- Inspect `logs_2.sqlite` `logs` table `feedback_log_body` column for conversation content
- Check `~/.codex/memories/` for extracted memory content
- Check if full rollout/conversation is stored in `rollout_path` field (points to a file path)

**Discovery strategy:**
1. Check `~/.codex/state_5.sqlite` exists
2. Query `threads` for session metadata
3. Query `logs_2.sqlite` for log content with `feedback_log_body`
4. Scan `memories/` directory for plain text memory files

---

## Claude Desktop App

**Status:** NOT INSTALLED on test machine

**Expected paths (macOS):**
```
~/Library/Application Support/Claude/           # primary app data
~/Library/Application Support/Claude/claude_desktop_config.json  # config (confirmed from docs)
```

**Research needed:**
- Install Claude desktop and identify conversation storage format
- Likely SQLite or JSON/JSONL based on Electron app patterns
- May use similar encrypted storage to ChatGPT desktop

**Known:** `claude_desktop_config.json` exists and contains MCP server configurations, which may include credentials (API keys, connection strings) - high value target even without conversation content.

---

## Claude Code CLI

**Storage format:** JSONL files (one per conversation session)

**Primary paths (macOS):**
```
~/.claude/projects/<path-slug>/<session-uuid>.jsonl
```

Where `<path-slug>` is the working directory path with `/` replaced by `-`, e.g.:
```
~/.claude/projects/-Users-<username>-Documents-<project>/42fcd508-1aa8-4c93-b7af-05f69be3e313.jsonl
```

**Additional paths:**
```
~/.claude/history.jsonl    # global command history
~/.claude/sessions/        # session metadata JSON files
~/.claude/tasks/           # task tracking JSON files
```

**JSONL record types:**
- `user` - user messages: `message.content` contains the text (may be string or content block array)
- `assistant` - AI responses: `message.content` contains the response
- `system` - tool call results, hook output, errors
- `attachment` - file attachments
- `file-history-snapshot` - file state snapshots
- `last-prompt`, `permission-mode`, `ai-title`, `pr-link`, `queue-operation` - metadata

**High-value fields:**
- `message.content` in `user` and `assistant` records
- `cwd` field present on all records (reveals project path)
- `gitBranch` field (reveals repo context)

**Discovery strategy:**
1. Glob `~/.claude/projects/**/*.jsonl`
2. Parse each line as JSON
3. Filter for `type in ("user", "assistant")`
4. Extract `message.content` (handle both string and content-block-array forms)
5. Run pattern engine on extracted text

**Notes:**
- Conversation files can be large (MB+) for long sessions
- The `cwd` field leaks the full path of the project being worked on
- `history.jsonl` may contain standalone commands with credentials passed as arguments

---

## Cross-platform notes

| Tool | macOS | Linux | Windows |
|------|-------|-------|---------|
| Cursor | `~/Library/Application Support/Cursor/` | `~/.config/Cursor/` | `%APPDATA%\Cursor\` |
| ChatGPT | `~/Library/Application Support/com.openai.chat/` | N/A (no Linux app) | `%APPDATA%\ChatGPT\` |
| Codex CLI | `~/.codex/` | `~/.codex/` | `%USERPROFILE%\.codex\` |
| Claude desktop | `~/Library/Application Support/Claude/` | N/A | `%APPDATA%\Claude\` |
| Claude Code | `~/.claude/` | `~/.claude/` | `%USERPROFILE%\.claude\` |

---

## References

- Cursor storage: observed directly from `state.vscdb` on macOS 15.x, Cursor 0.50+
- ChatGPT Electron encryption: consistent with Chrome `safeStorage` v10/v11 AES-256-GCM pattern
- Codex CLI: observed directly from `~/.codex/` on macOS 15.x
- Claude Code: observed directly from `~/.claude/projects/` on macOS 15.x
