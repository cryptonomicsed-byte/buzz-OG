//! Individual delegation links and their canonical encoding.

use core::str::FromStr;
use std::fmt;

use nostr::hashes::sha256::Hash as Sha256Hash;
use nostr::hashes::Hash;
use nostr::secp256k1::schnorr::Signature;
use nostr::secp256k1::Message;
use nostr::{Keys, PublicKey, SECP256K1};
use serde::{Deserialize, Serialize};

use crate::caveat::Caveats;
use crate::error::{InvalidLinkId, MandateError};

/// Domain separator for the link signing preimage.
///
/// Distinct from NIP-OA's `nostr:agent-auth:` so that a signature produced for
/// one protocol can never be replayed as a signature for the other.
pub const DOMAIN: &str = "nostr:mandate:v1";

/// Placeholder written in place of a parent id by the root link.
pub const ROOT_PARENT: &str = "root";

/// The SHA-256 identifier of a link.
///
/// A link id commits to the link's parent, so ids are chain-position-specific:
/// a link cannot be spliced out of one chain and into another without changing
/// its id, which breaks both its own signature and every downstream link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId([u8; 32]);

impl LinkId {
    /// Wrap raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    /// Parse from 64 lowercase hex characters.
    ///
    /// Uppercase is rejected: link ids appear in signing preimages, so two
    /// spellings of one id would be two different signed messages.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidLinkId`] if the input is not exactly 64 lowercase hex
    /// characters.
    pub fn from_hex(s: &str) -> Result<Self, InvalidLinkId> {
        if s.len() != 64 {
            return Err(InvalidLinkId);
        }
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for (index, slot) in out.iter_mut().enumerate() {
            let high = hex_value(bytes[index * 2])?;
            let low = hex_value(bytes[index * 2 + 1])?;
            *slot = (high << 4) | low;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_value(byte: u8) -> Result<u8, InvalidLinkId> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(InvalidLinkId),
    }
}

fn is_lowercase_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One hop of delegated authority: `issuer` grants `subject` the authority
/// described by `caveats`, bounded by everything the parent link already
/// granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    parent: Option<LinkId>,
    issuer: PublicKey,
    subject: PublicKey,
    caveats: Caveats,
    signature: Signature,
}

impl Link {
    /// Build and sign a link.
    ///
    /// Pass `parent: None` for a root link. The signature is produced by
    /// `issuer_keys` over the link's id.
    ///
    /// # Errors
    ///
    /// Returns [`MandateError::SelfDelegation`] if the issuer would delegate to
    /// itself, which grants nothing and only lengthens the chain.
    pub fn sign(
        issuer_keys: &Keys,
        subject: &PublicKey,
        caveats: Caveats,
        parent: Option<LinkId>,
    ) -> Result<Self, MandateError> {
        let issuer = issuer_keys.public_key();
        if issuer == *subject {
            return Err(MandateError::SelfDelegation { index: 0 });
        }

        let id = compute_id(parent.as_ref(), &issuer, subject, &caveats);
        let signature = issuer_keys.sign_schnorr(&message_for(&id));

        Ok(Self {
            parent,
            issuer,
            subject: *subject,
            caveats,
            signature,
        })
    }

    /// Reassemble a link from already-signed parts, without verifying the
    /// signature. [`crate::MandateChain::verify`] performs the check.
    #[must_use]
    pub const fn from_parts(
        parent: Option<LinkId>,
        issuer: PublicKey,
        subject: PublicKey,
        caveats: Caveats,
        signature: Signature,
    ) -> Self {
        Self {
            parent,
            issuer,
            subject,
            caveats,
            signature,
        }
    }

    /// The parent link's id, or `None` for a root link.
    #[must_use]
    pub const fn parent(&self) -> Option<LinkId> {
        self.parent
    }

    /// The key that granted this link's authority.
    #[must_use]
    pub const fn issuer(&self) -> &PublicKey {
        &self.issuer
    }

    /// The key this link grants authority to.
    #[must_use]
    pub const fn subject(&self) -> &PublicKey {
        &self.subject
    }

    /// The constraints this link places on its subject.
    #[must_use]
    pub const fn caveats(&self) -> &Caveats {
        &self.caveats
    }

    /// The issuer's signature over [`Link::id`].
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The canonical signing preimage.
    ///
    /// ```text
    /// nostr:mandate:v1\n<parent-or-"root">\n<issuer>\n<subject>\n<caveats>
    /// ```
    #[must_use]
    pub fn preimage(&self) -> String {
        preimage_for(
            self.parent.as_ref(),
            &self.issuer,
            &self.subject,
            &self.caveats,
        )
    }

    /// `SHA256` of the preimage.
    #[must_use]
    pub fn id(&self) -> LinkId {
        compute_id(
            self.parent.as_ref(),
            &self.issuer,
            &self.subject,
            &self.caveats,
        )
    }

    /// Verify the issuer's signature over this link's id.
    ///
    /// # Errors
    ///
    /// Returns [`MandateError::BadSignature`] tagged with `index`.
    pub fn verify_signature(&self, index: usize) -> Result<(), MandateError> {
        let xonly = self
            .issuer
            .xonly()
            .map_err(|_| MandateError::InvalidField {
                index,
                field: "issuer",
            })?;

        SECP256K1
            .verify_schnorr(&self.signature, &message_for(&self.id()), &xonly)
            .map_err(|_| MandateError::BadSignature { index })
    }

    /// Convert to the JSON wire representation.
    #[must_use]
    pub fn to_wire(&self) -> WireLink {
        WireLink {
            parent: self.parent.map(LinkId::to_hex),
            issuer: self.issuer.to_hex(),
            subject: self.subject.to_hex(),
            caveats: self.caveats.to_canonical_string(),
            sig: self.signature.to_string(),
        }
    }

    /// Parse from the JSON wire representation.
    ///
    /// Validates encodings only — signature and chain checks happen in
    /// [`crate::MandateChain::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`MandateError::InvalidField`] for malformed hex, keys, or
    /// signatures, and [`MandateError::Caveat`] for a non-canonical caveat
    /// string, each tagged with `index`.
    pub fn from_wire(wire: &WireLink, index: usize) -> Result<Self, MandateError> {
        let invalid = |field: &'static str| MandateError::InvalidField { index, field };

        let parent = match &wire.parent {
            None => None,
            Some(hex) => Some(LinkId::from_hex(hex).map_err(|_| invalid("parent"))?),
        };

        if !is_lowercase_hex(&wire.issuer, 64) {
            return Err(invalid("issuer"));
        }
        if !is_lowercase_hex(&wire.subject, 64) {
            return Err(invalid("subject"));
        }
        if !is_lowercase_hex(&wire.sig, 128) {
            return Err(invalid("sig"));
        }

        let issuer = PublicKey::from_hex(&wire.issuer).map_err(|_| invalid("issuer"))?;
        let subject = PublicKey::from_hex(&wire.subject).map_err(|_| invalid("subject"))?;
        let signature = Signature::from_str(&wire.sig).map_err(|_| invalid("sig"))?;

        let caveats = Caveats::parse(&wire.caveats)
            .map_err(|source| MandateError::Caveat { index, source })?;

        Ok(Self {
            parent,
            issuer,
            subject,
            caveats,
            signature,
        })
    }
}

/// JSON representation of a [`Link`].
///
/// `parent` is `null` on the root link and a 64-character lowercase hex link id
/// on every other link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireLink {
    /// Parent link id, or `null` for the root.
    pub parent: Option<String>,
    /// Issuer pubkey, 64 lowercase hex characters.
    pub issuer: String,
    /// Subject pubkey, 64 lowercase hex characters.
    pub subject: String,
    /// Canonical caveat string; may be empty.
    pub caveats: String,
    /// BIP-340 Schnorr signature, 128 lowercase hex characters.
    pub sig: String,
}

fn preimage_for(
    parent: Option<&LinkId>,
    issuer: &PublicKey,
    subject: &PublicKey,
    caveats: &Caveats,
) -> String {
    let parent = parent.map_or_else(|| ROOT_PARENT.to_owned(), |id| id.to_hex());
    format!(
        "{DOMAIN}\n{parent}\n{}\n{}\n{}",
        issuer.to_hex(),
        subject.to_hex(),
        caveats.to_canonical_string()
    )
}

fn compute_id(
    parent: Option<&LinkId>,
    issuer: &PublicKey,
    subject: &PublicKey,
    caveats: &Caveats,
) -> LinkId {
    let preimage = preimage_for(parent, issuer, subject, caveats);
    LinkId(Sha256Hash::hash(preimage.as_bytes()).to_byte_array())
}

fn message_for(id: &LinkId) -> Message {
    Message::from_digest(id.0)
}
