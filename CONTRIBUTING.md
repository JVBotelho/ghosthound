# Contributing to GhostHound

Thank you for contributing to GhostHound. Before making a change, review the architecture
decision records in [`docs/adr/`](docs/adr/) for the design context and constraints behind the
workspace.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability**, including one in the binary parsers
(`ad-secdesc`, `ad-tombstone`) or the LDAP client. Those parsers consume untrusted bytes from a
domain controller, so a parsing defect may be exploitable. Follow the private disclosure process in
[`SECURITY.md`](SECURITY.md) instead.

Ordinary bugs, crashes on your own lab data, and feature requests belong in public issues as usual.

## Before you start

- For anything beyond a typo, comment on the issue before you begin so work isn't duplicated. If no
  issue exists, open one first and describe the approach you have in mind.
- Every pull request needs a review from a code owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).
- Any change to behaviour needs a test that fails without it. Prefer tests that run without a live
  domain controller; see the existing unit tests for how parsing and CLI logic are covered offline.
- Keep pull requests focused on one concern. If a change turns out to need an unrelated fix, say so
  in the pull request rather than folding it in silently.

## Toolchain and local checks

The project uses the stable Rust toolchain and requires the `rustfmt` and `clippy` components. Every
crate is on `edition = "2024"`, so **Rust 1.85 or newer** is required; older stable toolchains fail
with an edition error rather than a clear message. If you manage Rust with `rustup`, install the
toolchain and components with:

```bash
rustup toolchain install stable --component rustfmt clippy
```

From the repository root, build and test the default workspace members with:

```bash
cargo build
cargo test --all-targets --all-features
```

CI enforces formatting and treats every Clippy warning as an error. Run the same checks before
submitting a change:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Run `cargo fmt` to apply formatting fixes.

### Platforms

The tool is used on both Linux and Windows, and the CLI has platform-specific path handling behind
`#[cfg(unix)]` and `#[cfg(windows)]`. A local `cargo test` therefore runs a different subset of
tests depending on your operating system — if you touch path or output handling, note which
platform you tested on in the pull request.

## Dependencies and supply chain

The supply-chain posture is deliberate and enforced in CI; see
[`docs/adr/0005-supply-chain-openssf-posture.md`](docs/adr/0005-supply-chain-openssf-posture.md).
Two rules catch contributors by surprise:

- **New dependencies are scrutinised.** `cargo-deny` bans copyleft licences in the published crates
  and fails on known advisories, and the OSV Scanner runs against `Cargo.lock`. Justify any new
  dependency in the pull request, and check it locally before pushing:

  ```bash
  cargo install cargo-deny --locked
  cargo deny check
  ```

- **GitHub Actions are pinned by commit SHA**, not by tag. If you edit a workflow, keep that style
  and leave the human-readable version in a trailing comment, as the existing entries do.

## Contribution licensing

Contributions are accepted under the same terms as the project: dual-licensed
[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). By submitting a pull request you agree that your
contribution may be distributed under both licences.

## Default workspace members and the oracle

The workspace's `default-members` deliberately exclude `ad-secdesc-oracle`. As a result, commands
such as `cargo build` and `cargo test --all-targets --all-features` run the four published crates
(three libraries plus the `ghosthound` binary) but skip the oracle crate.

`ad-secdesc-oracle` is an unpublished differential-test harness that depends on a GPL-3.0
implementation. It is kept separate so GPL code never enters the dependency graph of the
permissively licensed, published crates. See
[`docs/adr/0003-security-descriptor-parsing-strategy.md`](docs/adr/0003-security-descriptor-parsing-strategy.md)
for the full rationale.

When a change affects security-descriptor parsing or the oracle harness, run its tests explicitly:

```bash
cargo test -p ad-secdesc-oracle
```

## Fuzzing

The fuzz targets require the nightly Rust toolchain and `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Run the `ad-secdesc` target from its crate directory:

```bash
cd crates/ad-secdesc
cargo +nightly fuzz run fuzz_target_1
```

Run the `ad-tombstone` target from its crate directory:

```bash
cd crates/ad-tombstone
cargo +nightly fuzz run fuzz_target_1
```

Stop a local fuzzing campaign with `Ctrl-C`. For a CI-style 60-second smoke test, append
`-- -max_total_time=60` to either command.
