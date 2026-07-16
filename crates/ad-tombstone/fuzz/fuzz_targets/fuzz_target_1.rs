#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // ad-tombstone's own parsing surface beyond the LDAP protocol handling owned by ldap3 is
    // objectSid parsing in TombstoneObject::from_entry and resolve_object_sid, both of which
    // delegate directly to ad_secdesc::Sid::parse on raw bytes from an LDAP attribute value.
    // SecurityDescriptor parsing (which also parses SIDs internally) is fuzzed separately in
    // ad-secdesc/fuzz.
    let mut cursor = Cursor::new(data);
    let _ = ad_secdesc::Sid::parse(&mut cursor);
});
