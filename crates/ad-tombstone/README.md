# ad-tombstone

[![Crates.io](https://img.shields.io/crates/v/ad-tombstone.svg)](https://crates.io/crates/ad-tombstone)
[![docs.rs](https://img.shields.io/docsrs/ad-tombstone)](https://docs.rs/ad-tombstone)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JVBotelho/ghosthound/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/ghosthound)

Active Directory tombstone/Recycle Bin enumeration and reanimation-rights analysis over LDAP.

SharpHound and every other standard AD collector skip `CN=Deleted Objects` entirely, so deleted
objects (tombstones) are invisible to normal directory tooling — even though the AD Recycle Bin and
tombstone reanimation mechanisms can let a sufficiently-privileged principal restore one and take
over whatever identity it represents. This crate is the domain-logic layer behind
[GhostHound](https://github.com/JVBotelho/ghosthound)'s tombstone-reanimation attack-path analysis:
it enumerates tombstones, models their AD Recycle Bin state, and determines who holds the
Reanimate-Tombstones right. It's a plain library with no CLI or OpenGraph output of its own — see
the `ghosthound` crate for that.

## What it knows that a naive LDAP query doesn't

- **`SHOW_DELETED` isn't enough on its own.** Reading a tombstone's own linked-value attributes
  (like `memberOf`) also needs the `SHOW_DEACTIVATED_LINK` control — AD treats a link with one
  deleted endpoint as "deactivated" and hides it otherwise.
- **Deleted vs. Recycled are different states.** With the AD Recycle Bin feature enabled, a
  deleted object spends a window (default 180 days) in a full-fidelity `Deleted` state —
  `isRecycled=FALSE`, group membership intact — before being stripped to the ~60-attribute
  `Recycled` state. `group_membership_recoverable` on `TombstoneObject` reflects exactly this
  distinction, which matters for how valuable reanimating any given tombstone actually is.
- **Reanimate-Tombstones is evaluated at the domain naming-context root**, not on
  `CN=Deleted Objects` itself or on the tombstone — a detail that's easy to get wrong and produces
  a DACL read against the wrong object.
- **Every LDAP round-trip has a client-side timeout** (`with_timeout`), because
  `ldap3::SearchOptions::timelimit` is a server-side-only hint that does not protect against a
  wrong DC IP, a firewalled port, or a dead link.

## Usage

```rust
use ad_tombstone::{check_reanimate_rights, check_recycle_bin_enabled, fetch_tombstones, with_timeout};

const TIMEOUT_SECS: u64 = 30;

// `ldap`: an authenticated ldap3::Ldap handle, bound with rights to read CN=Deleted Objects
// (Administrators-equivalent -- an AD-enforced restriction, not something this crate can bypass).
// `domain_nc`: the domain naming context, e.g. from a RootDSE lookup of defaultNamingContext.

let recycle_bin_enabled = check_recycle_bin_enabled(&mut ldap, TIMEOUT_SECS).await?;

let tombstones = fetch_tombstones(&mut ldap, domain_nc, recycle_bin_enabled, TIMEOUT_SECS).await?;
for t in &tombstones {
    println!(
        "{}: recoverable={} lastknownparent={:?}",
        t.dn, t.group_membership_recoverable, t.lastknownparent
    );
}

let reanimators = check_reanimate_rights(&mut ldap, domain_nc, TIMEOUT_SECS).await?;
println!("{} principals can reanimate tombstones here", reanimators.len());
```

See `ghosthound`'s `main.rs` for the full orchestration, including turning `member_of`'s group DNs
back into SIDs via `resolve_object_sid` and assembling everything into an OpenGraph payload.

## License

MIT OR Apache-2.0.
