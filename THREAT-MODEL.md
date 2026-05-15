# Threat Model

## Intended Use Cases

ghosttype is a forensic tool for authorized security engagements. Intended operators:

1. **Red teams** - running on compromised machines during authorized pentests to harvest credentials pasted into AI tools by the target user. The output (findings + source files) is loot for the engagement report and for simulation/replay.

2. **Blue teams / DLP** - running on employee machines (with consent/policy) to audit what credentials have been shared with AI tools. Feeds into credential rotation workflows.

3. **Security engineers** - running on their own machines to understand their own exposure surface.

## Explicitly Out of Scope

- Unauthorized access to any system
- Mass deployment or automated targeting
- Use as a component in malware or automated attack tooling
- Exfiltration of data to external services (ghosttype is local-only by design)

## Attacker Model (Who We Simulate)

A post-compromise attacker with local user access (no root required) who wants to harvest credentials from AI conversation history. They have:

- Read access to the user's home directory
- The ability to run a Python script
- No elevated privileges needed for most scanners (SQLite, JSONL)
- macOS Keychain access may require user interaction (TouchID/password prompt) for ChatGPT decryption

## Sensitivity of ghosttype's Own Output

The `findings.json` output contains plaintext credentials. Treat it as:
- Highest sensitivity - equivalent to a credentials dump
- Encrypted at rest if storing longer term
- Transmitted only over encrypted channels
- Deleted after the engagement or after rotation is confirmed

## Design Choices That Reduce Misuse Risk

- No network calls; no exfiltration built in
- No persistence mechanism; runs once and exits
- No ability to modify or delete conversation files
- Requires Python runtime and explicit invocation; not a self-contained dropper

## Legal Notice

Use of ghosttype against systems you do not own or have explicit written authorization to test is illegal in most jurisdictions. The authors are not responsible for unauthorized use. Always obtain written authorization before running security tools on any system.
