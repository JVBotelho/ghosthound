#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ad_secdesc::SecurityDescriptor::parse(data);
});
