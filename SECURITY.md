# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.4.x   | ✅ Yes    |
| < 0.4   | ❌ No     |

Only the `0.4.x` line receives security fixes. Older versions should upgrade.

## Reporting a Vulnerability

Report privately via GitHub Security Advisories — **do not open a public issue**:

➡️ https://github.com/p4gs/ghosttype/security/advisories/new

Service levels:

- **Acknowledgement:** within **72 hours** of report.
- **Coordinated disclosure:** within **90 days**, or sooner once a fix ships.

Please include reproduction steps, affected version, and impact assessment.

## Scope

ghosttype is an **authorized-use-only forensic tool**. It is built for red
teams, blue/DLP teams, and security engineers operating on systems they own or
are explicitly authorized to test. See
[THREAT-MODEL.md](./THREAT-MODEL.md) for the full intended-use, attacker model,
and out-of-scope boundaries.

Reports about *use of ghosttype against unauthorized systems* are out of scope:
that is misuse, not a vulnerability. In-scope reports concern defects in
ghosttype itself (e.g. unintended data egress, unsafe subprocess handling,
credential mishandling in its own output).

## Network Behavior

ghosttype performs **no network I/O** of its own. The single exception is the
pinned TruffleHog subprocess it invokes for detection and live verification;
all other operation is local-only by design (no telemetry, no exfiltration, no
auto-update). Any observed outbound connection originating from ghosttype's own
code — rather than from the TruffleHog child process — should be treated as a
security defect and reported via the advisory link above.
