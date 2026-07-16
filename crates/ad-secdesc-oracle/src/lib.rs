use ad_secdesc::SecurityDescriptor as MySecDesc;
use sddl::SecurityDescriptor as SddlSecDesc;
use std::convert::TryFrom;

pub fn compare_parsers(data: &[u8]) {
    let my_parsed = MySecDesc::parse(data).ok();
    let sddl_parsed = SddlSecDesc::try_from(data).ok();

    match (my_parsed, sddl_parsed) {
        (Some(my_desc), Some(sddl_desc)) => {
            assert_eq!(my_desc.revision, *sddl_desc.revision(), "revision mismatch");

            // Owner/group SID: `sddl::Sid` and `ad_secdesc::Sid` both implement Display as
            // "S-{revision}-{identifier_authority}-{sub_authority}-...", so string comparison
            // is a valid cross-implementation check without depending on either crate's
            // internal field layout.
            assert_eq!(
                my_desc.owner.as_ref().map(|s| s.to_string()),
                sddl_desc.owner().as_ref().map(|s| s.to_string()),
                "owner SID mismatch"
            );
            assert_eq!(
                my_desc.group.as_ref().map(|s| s.to_string()),
                sddl_desc.group().as_ref().map(|s| s.to_string()),
                "group SID mismatch"
            );

            // DACL/SACL presence and ACE count. `sddl::Ace`'s per-ACE fields (mask, sid,
            // object_type) are private to that crate (only exposed via its Display/SDDL-string
            // rendering, which uses a different textual grammar than ours), so ACE-count and
            // presence is the deepest cross-implementation comparison available without also
            // implementing SDDL-string serialization in ad-secdesc.
            assert_eq!(
                my_desc.dacl.as_ref().map(|a| a.aces.len()),
                sddl_desc.dacl().as_ref().map(|a| a.ace_list().len()),
                "DACL ACE count mismatch"
            );
            assert_eq!(
                my_desc.sacl.is_some(),
                sddl_desc.sacl().is_some(),
                "SACL presence mismatch"
            );
        }
        (None, None) => {
            // Both parsers failed on invalid data, which is acceptable
        }
        (my, sddl) => {
            panic!(
                "Parsers disagree on data! my_parsed: {:?}, sddl_parsed: {:?}",
                my.is_some(),
                sddl.is_some()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_parsers_empty() {
        compare_parsers(&[]);
    }

    #[test]
    fn test_compare_parsers_valid() {
        // A simple valid security descriptor
        let data = [
            0x01, 0x00, 0x04, 0x80, // Revision, Sbz1, Control (0x8004)
            0x14, 0x00, 0x00, 0x00, // Owner offset (20)
            0x24, 0x00, 0x00, 0x00, // Group offset (36)
            0x00, 0x00, 0x00, 0x00, // SACL offset (0)
            0x30, 0x00, 0x00, 0x00, // DACL offset (48)
            // Owner SID (S-1-5-32-544) (starts at 20)
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
            0x00, 0x00, // Group SID (S-1-5-18) (starts at 36)
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
            // DACL (starts at 48)
            0x02, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, // ACE
            0x00, 0x00, 0x14, 0x00, 0xFF, 0x01, 0x1F, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];
        compare_parsers(&data);
    }
}
