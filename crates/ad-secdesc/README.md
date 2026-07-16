# ad-secdesc

[![Crates.io](https://img.shields.io/crates/v/ad-secdesc.svg)](https://crates.io/crates/ad-secdesc)
[![docs.rs](https://img.shields.io/docsrs/ad-secdesc)](https://docs.rs/ad-secdesc)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JVBotelho/ghosthound/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/ghosthound)

A from-scratch, permissively-licensed (MIT/Apache-2.0) parser for Active Directory's
`nTSecurityDescriptor` attribute: security descriptors, SIDs, ACLs, and ACEs, per
[MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/).

## Why this exists

The only other Rust implementation of this format (`sddl`) is GPL-3.0-licensed, which is a
non-starter for a permissively-licensed tool that wants to be freely embeddable elsewhere. This
crate is an independent, from-scratch implementation with no GPL code or lineage. See
[GhostHound's ADR-0003](https://github.com/JVBotelho/ghosthound/blob/main/docs/adr/0003-security-descriptor-parsing-strategy.md)
for the full reasoning, including how `sddl` is still used — quarantined, dev-only, `publish =
false` — purely as a differential-testing oracle to cross-check this crate's output, never as a
runtime dependency.

## Security posture

- `#![forbid(unsafe_code)]`.
- Every read is bounds-checked; no panics on malformed/truncated input (the security descriptor
  bytes ultimately come from a directory service response, not a fully trusted source).
- Fuzzed with `cargo-fuzz` (`cargo fuzz run fuzz_target_1` under `fuzz/`), run as part of CI on
  every push, not just type-checked.

## Usage

```rust
use ad_secdesc::SecurityDescriptor;

let sd = SecurityDescriptor::parse(&nt_security_descriptor_bytes)?;

if let Some(owner) = &sd.owner {
    println!("Owner SID: {owner}");
}

if let Some(dacl) = &sd.dacl {
    for ace in &dacl.aces {
        println!("{} -> access_mask {:#x}", ace.sid, ace.access_mask);
    }
}
```

`Sid::parse` is also exposed directly, for parsing a standalone `objectSid`-style attribute value
(not embedded in a full security descriptor):

```rust
use ad_secdesc::Sid;
use std::io::Cursor;

let mut cursor = Cursor::new(object_sid_bytes.as_slice());
let sid = Sid::parse(&mut cursor)?;
```

## License

MIT OR Apache-2.0.
