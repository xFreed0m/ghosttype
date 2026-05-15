from ghosttype.scanners.claude_code import ClaudeCodeScanner
from ghosttype.scanners.cursor import CursorScanner
from ghosttype.scanners.codex import CodexScanner
from ghosttype.scanners.chatgpt import ChatGPTScanner
from ghosttype.scanners.claude import ClaudeScanner

SCANNERS = [
    ClaudeCodeScanner(),
    CursorScanner(),
    CodexScanner(),
    ChatGPTScanner(),
    ClaudeScanner(),
]
