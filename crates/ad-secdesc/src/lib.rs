#![forbid(unsafe_code)]

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Cursor, Read};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum SecDescError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid revision: {0}")]
    InvalidRevision(u8),
    #[error("Invalid ACL revision: {0}")]
    InvalidAclRevision(u8),
    #[error("Buffer too small")]
    BufferTooSmall,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub control: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub sacl: Option<Acl>,
    pub dacl: Option<Acl>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ace {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub access_mask: u32,
    pub object_type: Option<Uuid>,
    pub inherited_object_type: Option<Uuid>,
    pub sid: Sid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    pub fn parse(cursor: &mut Cursor<&[u8]>) -> Result<Self, SecDescError> {
        let revision = cursor.read_u8()?;
        if revision != 1 {
            return Err(SecDescError::InvalidRevision(revision));
        }
        let sub_auth_count = cursor.read_u8()?;
        let mut identifier_authority = [0u8; 6];
        cursor.read_exact(&mut identifier_authority)?;

        let mut sub_authorities = Vec::with_capacity(sub_auth_count as usize);
        for _ in 0..sub_auth_count {
            sub_authorities.push(cursor.read_u32::<LittleEndian>()?);
        }

        Ok(Sid {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut auth = 0u64;
        for i in 0..6 {
            auth = (auth << 8) | (self.identifier_authority[i] as u64);
        }
        write!(f, "S-{}-{}", self.revision, auth)?;
        for sub in &self.sub_authorities {
            write!(f, "-{}", sub)?;
        }
        Ok(())
    }
}

impl SecurityDescriptor {
    pub fn parse(data: &[u8]) -> Result<Self, SecDescError> {
        let mut cursor = Cursor::new(data);

        let revision = cursor.read_u8()?;
        if revision != 1 {
            return Err(SecDescError::InvalidRevision(revision));
        }
        let _sbz1 = cursor.read_u8()?;
        let control = cursor.read_u16::<LittleEndian>()?;

        let offset_owner = cursor.read_u32::<LittleEndian>()?;
        let offset_group = cursor.read_u32::<LittleEndian>()?;
        let offset_sacl = cursor.read_u32::<LittleEndian>()?;
        let offset_dacl = cursor.read_u32::<LittleEndian>()?;

        let parse_sid = |offset: u32| -> Result<Option<Sid>, SecDescError> {
            if offset == 0 {
                return Ok(None);
            }
            if offset as usize >= data.len() {
                return Err(SecDescError::BufferTooSmall);
            }
            let mut sid_cursor = Cursor::new(&data[offset as usize..]);
            Ok(Some(Sid::parse(&mut sid_cursor)?))
        };

        let owner = parse_sid(offset_owner)?;
        let group = parse_sid(offset_group)?;

        let parse_acl = |offset: u32| -> Result<Option<Acl>, SecDescError> {
            if offset == 0 {
                return Ok(None);
            }
            if offset as usize >= data.len() {
                return Err(SecDescError::BufferTooSmall);
            }
            let mut acl_cursor = Cursor::new(&data[offset as usize..]);

            let acl_rev = acl_cursor.read_u8()?;
            let _sbz1 = acl_cursor.read_u8()?;
            let acl_size = acl_cursor.read_u16::<LittleEndian>()?;
            let ace_count = acl_cursor.read_u16::<LittleEndian>()?;
            let _sbz2 = acl_cursor.read_u16::<LittleEndian>()?;

            if acl_size as usize > data.len() - offset as usize {
                return Err(SecDescError::BufferTooSmall);
            }

            // Bound the pre-allocation by how many ACEs could plausibly fit in the
            // already-validated acl_size (8 bytes is the smallest possible ACE header), rather
            // than trusting ace_count -- an attacker-controlled u16 -- directly, which could
            // otherwise reserve capacity for up to 65535 Aces regardless of how much data the
            // buffer actually holds.
            let max_plausible_aces = acl_size / 8;
            let mut aces = Vec::with_capacity(ace_count.min(max_plausible_aces) as usize);
            for _ in 0..ace_count {
                let ace_start = acl_cursor.position() as usize;
                let ace_type = acl_cursor.read_u8()?;
                let ace_flags = acl_cursor.read_u8()?;
                let ace_size = acl_cursor.read_u16::<LittleEndian>()?;

                if ace_size < 4 {
                    return Err(SecDescError::BufferTooSmall);
                }

                let access_mask = acl_cursor.read_u32::<LittleEndian>()?;

                let mut object_type = None;
                let mut inherited_object_type = None;

                // Object ACEs
                if ace_type == 0x05
                    || ace_type == 0x06
                    || ace_type == 0x07
                    || ace_type == 0x08
                    || ace_type == 0x0B
                    || ace_type == 0x0C
                {
                    let flags = acl_cursor.read_u32::<LittleEndian>()?;

                    if flags & 0x00000001 != 0 {
                        let mut guid_bytes = [0u8; 16];
                        acl_cursor.read_exact(&mut guid_bytes)?;
                        object_type = Some(Uuid::from_bytes_le(guid_bytes));
                    }

                    if flags & 0x00000002 != 0 {
                        let mut guid_bytes = [0u8; 16];
                        acl_cursor.read_exact(&mut guid_bytes)?;
                        inherited_object_type = Some(Uuid::from_bytes_le(guid_bytes));
                    }
                }

                let sid = Sid::parse(&mut acl_cursor)?;

                aces.push(Ace {
                    ace_type,
                    ace_flags,
                    access_mask,
                    object_type,
                    inherited_object_type,
                    sid,
                });

                // Move cursor to next ACE
                let next_pos = ace_start + ace_size as usize;
                if next_pos > acl_size as usize {
                    return Err(SecDescError::BufferTooSmall);
                }
                if next_pos < acl_cursor.position() as usize {
                    return Err(SecDescError::BufferTooSmall); // or a new Malformed data error
                }
                acl_cursor.set_position(next_pos as u64);
            }

            Ok(Some(Acl {
                revision: acl_rev,
                aces,
            }))
        };

        let sacl = parse_acl(offset_sacl)?;
        let dacl = parse_acl(offset_dacl)?;

        Ok(SecurityDescriptor {
            revision,
            control,
            owner,
            group,
            sacl,
            dacl,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_security_descriptor() {
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

        let sd = SecurityDescriptor::parse(&data).expect("Failed to parse valid SD");
        assert_eq!(sd.revision, 1);
        assert_eq!(sd.control, 0x8004);

        let owner = sd.owner.expect("Missing owner");
        assert_eq!(owner.to_string(), "S-1-5-32-544");

        let group = sd.group.expect("Missing group");
        assert_eq!(group.to_string(), "S-1-5-18");

        assert!(sd.sacl.is_none());

        let dacl = sd.dacl.expect("Missing DACL");
        assert_eq!(dacl.revision, 2);
        assert_eq!(dacl.aces.len(), 1);

        let ace = &dacl.aces[0];
        assert_eq!(ace.ace_type, 0); // ACCESS_ALLOWED_ACE_TYPE
        assert_eq!(ace.sid.to_string(), "S-1-5-18");
    }

    #[test]
    fn test_parse_invalid_revision() {
        let data = [0x02, 0x00, 0x04, 0x80]; // Revision 2 (invalid)
        let result = SecurityDescriptor::parse(&data);
        assert!(matches!(result, Err(SecDescError::InvalidRevision(2))));
    }

    #[test]
    fn test_parse_buffer_too_small() {
        let data = [0x01, 0x00, 0x04, 0x80]; // Truncated
        let result = SecurityDescriptor::parse(&data);
        assert!(matches!(result, Err(SecDescError::Io(_))));
    }
}
