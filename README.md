# GhostHound

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JVBotelho/ghosthound/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/ghosthound)

GhostHound is a set of modular Rust crates for interacting with AD Tombstones and generating BloodHound-compatible JSON graphs.

## Workspace Layout
GhostHound is built as a library-first workspace:
- `bloodhound-opengraph`: BloodHound OpenGraph JSON builder.
- `ad-secdesc`: Parser for `ntSecurityDescriptor` and ACEs.
- `ad-tombstone`: LDAP `SHOW_DELETED` enumeration and tombstone modeling.
- `ghosthound`: The CLI orchestrating the crates.

## Supply-Chain Posture
This project prioritizes high-confidence security from day 1, utilizing:
- `cargo deny` for strict copyleft/GPL bans and vulnerability auditing.
- OpenSSF Scorecard workflows.
- `cargo fuzz` for panic safety in parsing raw binary descriptors.
- No `unsafe` in foundational libraries.
