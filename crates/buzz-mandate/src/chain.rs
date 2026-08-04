//! Chain assembly and verification.

use std::collections::BTreeSet;

use nostr::{Keys, PublicKey};
use serde::{Deserialize, Serialize};

use crate::caveat::{Caveats, Request, VerifyContext};
use crate::error::{DenyReason, MandateError};
use crate::link::{Link, LinkId, WireLink};
use crate::MAX_CHAIN_LEN;

/// Link ids that a verifier considers revoked.
///
/// Because every link commits to its parent's id, revoking a link
/// automatically invalidates every chain that passes through it — a verifier
/// never has to enumerate the descendants of a revoked grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationSet {
    ids: BTreeSet<LinkId>,
}

impl RevocationSet {
    /// An empty set — nothing revoked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a link id revoked. Returns `true` if it was not already present.
    pub fn insert(&mut self, id: LinkId) -> bool {
        self.ids.insert(id)
    }

    /// Whether a link id is revoked.
    #[must_use]
    pub fn contains(&self, id: &LinkId) -> bool {
        self.ids.contains(id)
    }

    /// Number of revoked ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

impl FromIterator<LinkId> for RevocationSet {
    fn from_iter<I: IntoIterator<Item = LinkId>>(iter: I) -> Self {
        Self {
            ids: iter.into_iter().collect(),
        }
    }
}

/// An ordered chain of delegation links, from a root authority to the agent
/// that will act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandateChain {
    links: Vec<Link>,
}

impl MandateChain {
    /// Start a chain: `root_keys` grants `subject` the authority in `caveats`.
    ///
    /// # Errors
    ///
    /// Returns [`MandateError::SelfDelegation`] if the root grants to itself.
    pub fn root(
        root_keys: &Keys,
        subject: &PublicKey,
        caveats: Caveats,
    ) -> Result<Self, MandateError> {
        Ok(Self {
            links: vec![Link::sign(root_keys, subject, caveats, None)?],
        })
    }

    /// Extend the chain by one hop.
    ///
    /// `issuer_keys` must be the current leaf's subject — the only key with
    /// authority to sub-delegate. The new caveats must narrow the leaf's.
    ///
    /// # Errors
    ///
    /// Returns [`MandateError::IssuerNotSubject`] if `issuer_keys` is not the
    /// current subject, [`MandateError::ChainTooLong`] if the chain is already
    /// at [`MAX_CHAIN_LEN`], [`MandateError::DepthExhausted`] if the leaf may
    /// not sub-delegate, [`MandateError::NotNarrowing`] if `caveats` would
    /// widen authority, or [`MandateError::SelfDelegation`].
    pub fn delegate(
        &self,
        issuer_keys: &Keys,
        subject: &PublicKey,
        caveats: Caveats,
    ) -> Result<Self, MandateError> {
        let index = self.links.len();
        let leaf = self.links.last().ok_or(MandateError::EmptyChain)?;

        if index >= MAX_CHAIN_LEN {
            return Err(MandateError::ChainTooLong {
                len: index + 1,
                max: MAX_CHAIN_LEN,
            });
        }
        if issuer_keys.public_key() != *leaf.subject() {
            return Err(MandateError::IssuerNotSubject { index });
        }
        if leaf.caveats().depth() == Some(0) {
            return Err(MandateError::DepthExhausted { index });
        }
        caveats
            .narrows(leaf.caveats())
            .map_err(|reason| MandateError::NotNarrowing { index, reason })?;

        let link = Link::sign(issuer_keys, subject, caveats, Some(leaf.id()))
            .map_err(|_| MandateError::SelfDelegation { index })?;

        let mut links = self.links.clone();
        links.push(link);
        Ok(Self { links })
    }

    /// Build from already-signed links, without verifying them.
    #[must_use]
    pub const fn from_links(links: Vec<Link>) -> Self {
        Self { links }
    }

    /// The links, root first.
    #[must_use]
    pub fn links(&self) -> &[Link] {
        &self.links
    }

    /// Verify the whole chain: linkage, authority flow, signatures,
    /// attenuation, depth, and revocation.
    ///
    /// Checks run link by link, and within a link in a fixed order, so a given
    /// malformed chain always produces the same error.
    ///
    /// Verification is deliberately independent of wall-clock time: a chain is
    /// structurally valid or it is not, and *liveness* is decided separately by
    /// [`VerifiedMandate::authorizes`] against a verifier-supplied clock. That
    /// split is what stops a subject from backdating its way past an expiry.
    ///
    /// # Errors
    ///
    /// Returns the first [`MandateError`] encountered, tagged with the index of
    /// the offending link.
    pub fn verify(&self, revoked: &RevocationSet) -> Result<VerifiedMandate<'_>, MandateError> {
        let (Some(root), Some(leaf)) = (self.links.first(), self.links.last()) else {
            return Err(MandateError::EmptyChain);
        };
        if self.links.len() > MAX_CHAIN_LEN {
            return Err(MandateError::ChainTooLong {
                len: self.links.len(),
                max: MAX_CHAIN_LEN,
            });
        }

        // A key that has already held authority in this chain must not receive
        // it again: a cycle would let two colluding keys pass a mandate back
        // and forth, burning depth without narrowing anything real.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        seen.insert(root.issuer().to_hex());

        for (index, link) in self.links.iter().enumerate() {
            if index == 0 {
                if link.parent().is_some() {
                    return Err(MandateError::BadLinkage { index });
                }
            } else {
                let previous = &self.links[index - 1];
                let Some(parent) = link.parent() else {
                    return Err(MandateError::BadLinkage { index });
                };
                if parent != previous.id() {
                    return Err(MandateError::ParentMismatch { index });
                }
                if link.issuer() != previous.subject() {
                    return Err(MandateError::IssuerNotSubject { index });
                }
            }

            if link.issuer() == link.subject() {
                return Err(MandateError::SelfDelegation { index });
            }
            if !seen.insert(link.subject().to_hex()) {
                return Err(MandateError::RepeatedSubject { index });
            }

            link.verify_signature(index)?;

            if revoked.contains(&link.id()) {
                return Err(MandateError::Revoked { index });
            }

            if index > 0 {
                let parent_caveats = self.links[index - 1].caveats();
                if parent_caveats.depth() == Some(0) {
                    return Err(MandateError::DepthExhausted { index });
                }
                link.caveats()
                    .narrows(parent_caveats)
                    .map_err(|reason| MandateError::NotNarrowing { index, reason })?;
            }
        }

        Ok(VerifiedMandate {
            root,
            leaf,
            hops: self.links.len(),
        })
    }

    /// Serialise to the JSON envelope carried in a kind:50001 event.
    ///
    /// # Errors
    ///
    /// Returns [`MandateError::MalformedEnvelope`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, MandateError> {
        let envelope = WireEnvelope {
            v: 1,
            links: self.links.iter().map(Link::to_wire).collect(),
        };
        serde_json::to_string(&envelope).map_err(|e| MandateError::MalformedEnvelope(e.to_string()))
    }

    /// Parse the JSON envelope. Does not verify — call
    /// [`MandateChain::verify`] on the result.
    ///
    /// # Errors
    ///
    /// Returns [`MandateError::MalformedEnvelope`] for invalid JSON or an
    /// unsupported version, or a per-link error for malformed fields.
    pub fn from_json(json: &str) -> Result<Self, MandateError> {
        let envelope: WireEnvelope = serde_json::from_str(json)
            .map_err(|e| MandateError::MalformedEnvelope(e.to_string()))?;

        if envelope.v != 1 {
            return Err(MandateError::MalformedEnvelope(format!(
                "unsupported envelope version {}",
                envelope.v
            )));
        }
        if envelope.links.is_empty() {
            return Err(MandateError::EmptyChain);
        }
        if envelope.links.len() > MAX_CHAIN_LEN {
            return Err(MandateError::ChainTooLong {
                len: envelope.links.len(),
                max: MAX_CHAIN_LEN,
            });
        }

        let links = envelope
            .links
            .iter()
            .enumerate()
            .map(|(index, wire)| Link::from_wire(wire, index))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { links })
    }
}

/// A chain that passed [`MandateChain::verify`].
///
/// Holding one is proof that the signatures, linkage, and attenuation all
/// checked out. It says nothing about whether the mandate is *live* — that is
/// [`VerifiedMandate::authorizes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedMandate<'a> {
    root: &'a Link,
    leaf: &'a Link,
    hops: usize,
}

impl<'a> VerifiedMandate<'a> {
    /// The key at the top of the chain, from which all authority below derives.
    #[must_use]
    pub const fn root_authority(&self) -> &'a PublicKey {
        self.root.issuer()
    }

    /// The key the mandate ultimately empowers.
    #[must_use]
    pub const fn subject(&self) -> &'a PublicKey {
        self.leaf.subject()
    }

    /// The authority the mandate conveys.
    ///
    /// This is the leaf link's caveat set verbatim. Because attenuation is
    /// verified as explicit restatement, the leaf already *is* the intersection
    /// of every link — no folding required, and a reader sees the whole grant
    /// on one line.
    #[must_use]
    pub const fn effective_caveats(&self) -> &'a Caveats {
        self.leaf.caveats()
    }

    /// Number of delegation hops, root included.
    #[must_use]
    pub const fn hops(&self) -> usize {
        self.hops
    }

    /// The leaf link's id, which identifies this mandate for revocation.
    #[must_use]
    pub fn leaf_id(&self) -> LinkId {
        self.leaf.id()
    }

    /// Decide whether this mandate authorizes `actor` to perform `request`
    /// under `context`.
    ///
    /// `actor` is the key actually taking the action — for a Nostr event, its
    /// `pubkey`. Stating it is mandatory rather than advisory because the check
    /// `actor == subject` is the only thing standing between the protocol and
    /// chain truncation: any holder of a chain can present a *prefix* of it,
    /// and prefixes are both valid and wider. A prefix names an earlier
    /// subject, so binding to the actor makes truncation useless — but an API
    /// that let a caller forget to bind would make it devastating.
    ///
    /// # Errors
    ///
    /// Returns the [`DenyReason`] that blocked the request.
    pub fn authorizes(
        &self,
        actor: &PublicKey,
        request: &Request<'_>,
        context: &VerifyContext,
    ) -> Result<(), DenyReason> {
        if actor != self.subject() {
            return Err(DenyReason::WrongSubject {
                actor: actor.to_hex(),
                subject: self.subject().to_hex(),
            });
        }
        self.effective_caveats().authorizes(request, context)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct WireEnvelope {
    v: u32,
    links: Vec<WireLink>,
}
