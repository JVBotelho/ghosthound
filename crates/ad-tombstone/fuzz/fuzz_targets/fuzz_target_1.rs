#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_data: &[u8]| {
    // ad-tombstone uses LDAP which is network-parsed by ldap3 crate.
    // The only custom parsing is via ad-secdesc which is fuzzed in its own crate.
});
