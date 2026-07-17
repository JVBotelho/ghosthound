//! A from-scratch, permissively-licensed (MIT/Apache-2.0) parser for Active Directory's
//! `nTSecurityDescriptor` attribute: security descriptors, SIDs, ACLs, and ACEs, per
//! [MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/).
//!
//! Start at [`SecurityDescriptor::parse`] for a full `nTSecurityDescriptor` blob, or [`Sid::parse`]
//! for a standalone `objectSid`-style attribute value. Every read is bounds-checked and returns
//! [`SecDescError`] rather than panicking, since this data ultimately comes from a directory
//! service response, not a fully trusted source -- this crate is fuzzed with `cargo-fuzz`
//! accordingly, and forbids `unsafe` code entirely.

#![forbid(unsafe_code)]

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Cursor, Read};
use thiserror::Error;
use uuid::Uuid;

/// Errors returned while parsing a security descriptor, ACL, or SID.
#[derive(Error, Debug)]
pub enum SecDescError {
    /// The underlying byte cursor ran out of data (a truncated/malformed blob), or another I/O
    /// error occurred while reading.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    /// The security descriptor's or SID's revision byte wasn't the only value this format
    /// defines (`1`).
    #[error("Invalid revision: {0}")]
    InvalidRevision(u8),
    /// Reserved for an invalid ACL-specific revision value; currently unused since ACL revision
    /// isn't validated against a fixed set the way the top-level revision is.
    #[error("Invalid ACL revision: {0}")]
    InvalidAclRevision(u8),
    /// A length or offset field pointed past the end of the buffer that was actually provided.
    #[error("Buffer too small")]
    BufferTooSmall,
}

/// A parsed Windows/AD security descriptor: owner, primary group, and the two ACLs that
/// actually grant or audit access (`dacl`, `sacl`).
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityDescriptor {
    /// Always `1` -- the only revision this format defines. [`SecurityDescriptor::parse`]
    /// rejects any other value.
    pub revision: u8,
    /// The `SECURITY_DESCRIPTOR_CONTROL` bit flags (self-relative vs. absolute, whether the DACL
    /// is present/protected/defaulted, etc.), per MS-DTYP 2.4.6.
    pub control: u16,
    /// The SID of the object's owner, if present.
    pub owner: Option<Sid>,
    /// The SID of the object's primary group, if present.
    pub group: Option<Sid>,
    /// System ACL -- audit/alarm entries. Not access-control; see [`Ace::ace_type`] for how to
    /// tell an audit ACE apart from a real grant/deny.
    pub sacl: Option<Acl>,
    /// Discretionary ACL -- the actual access-control entries (grants and denies).
    pub dacl: Option<Acl>,
}

/// An access control list: a revision plus an ordered sequence of [`Ace`] entries. Order matters
/// for real AD evaluation semantics (deny-before-allow precedence, inheritance), which this crate
/// does not itself implement -- it only parses the structure faithfully.
#[derive(Debug, Clone, PartialEq)]
pub struct Acl {
    /// The ACL's own revision byte (distinct from the security descriptor's `revision`).
    pub revision: u8,
    /// The ACL's entries, in on-the-wire order.
    pub aces: Vec<Ace>,
}

/// A single access control entry.
///
/// **Callers must check `ace_type` themselves** before treating `access_mask`/`object_type` as a
/// grant: the same mask and object-type GUID can appear on an `ACCESS_DENIED_*` or
/// `SYSTEM_AUDIT_*` ACE, which mean the opposite of (or something unrelated to) a plain
/// `ACCESS_ALLOWED_*` grant. This crate parses the structure; it does not interpret it.
#[derive(Debug, Clone, PartialEq)]
pub struct Ace {
    /// The ACE type byte (`ACCESS_ALLOWED_ACE_TYPE = 0x00`, `ACCESS_DENIED_ACE_TYPE = 0x01`,
    /// `SYSTEM_AUDIT_ACE_TYPE = 0x02`, and their `_OBJECT`/`_CALLBACK` variants), per MS-DTYP 2.4.4.1.
    pub ace_type: u8,
    /// The ACE flags byte (inheritance behavior: `INHERIT_ONLY_ACE = 0x08`, etc.), per MS-DTYP 2.4.4.1.
    pub ace_flags: u8,
    /// The access mask this ACE grants, denies, or audits -- interpretation depends on `ace_type`.
    pub access_mask: u32,
    /// For an object ACE (`ace_type` one of the `_OBJECT`/`_CALLBACK_OBJECT` variants) with the
    /// `ACE_OBJECT_TYPE_PRESENT` flag set: the GUID scoping which right/property/extended-right
    /// this ACE applies to. `None` for a non-object ACE (which implicitly applies to all rights
    /// the access mask covers) or when that flag isn't set.
    pub object_type: Option<Uuid>,
    /// Like `object_type`, but the `ACE_INHERITED_OBJECT_TYPE_PRESENT` GUID: which class of
    /// child object this ACE propagates to via inheritance.
    pub inherited_object_type: Option<Uuid>,
    /// The trustee (principal) this ACE applies to.
    pub sid: Sid,
}

/// A Windows/AD security identifier, e.g. `S-1-5-21-<domain>-512` for a domain's Domain Admins
/// group.
#[derive(Debug, Clone, PartialEq)]
pub struct Sid {
    /// Always `1` -- the only SID revision this format defines. [`Sid::parse`] rejects any other
    /// value.
    pub revision: u8,
    /// The 6-byte identifier authority (`NT_AUTHORITY`, etc.), stored big-endian on the wire.
    pub identifier_authority: [u8; 6],
    /// The sub-authority values, in order (e.g. the domain SID components followed by the RID).
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Parses a SID from its binary form (`objectSid`-style bytes), advancing `cursor` past it.
    ///
    /// Use this directly for a standalone SID attribute value; [`SecurityDescriptor::parse`]
    /// calls it internally for the owner/group/trustee SIDs embedded in a full security
    /// descriptor.
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
    /// Parses a full `nTSecurityDescriptor` attribute value: the self-relative header, owner and
    /// group SIDs, and the SACL/DACL and their ACEs.
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
            // already-validated acl_size (8 bytes is the smallest possible ACE up to and
            // including its fixed access_mask, before the variable-length SID), rather than
            // trusting ace_count -- an attacker-controlled u16 -- directly, which could
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
