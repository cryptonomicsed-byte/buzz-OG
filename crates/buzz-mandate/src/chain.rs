//! Chain assembly and verification.

use std::collections::{BTreeMap, BTreeSet};

use nostr::{Keys, PublicKey};
use serde::{Deserialize, Serialize};

use crate::caveat::{Caveats, Request, VerifyContext};
use crate::error::{DenyReason, MandateError};
use crate::link::{Link, LinkId, WireLink};
use crate::MAX_CHAIN_LEN;

/// The set of root keys a verifier is willing to derive authority from.
///
/// A chain proves that authority flowed correctly *from its own root*. It says
/// nothing about whether that root was ever entitled to grant anything —
/// anyone can generate a keypair and self-issue an unconstrained mandate to
/// themselves. Checking the root is therefore not optional, and this type
/// exists so that a caller cannot silently forget it: it is a required
/// argument to [`MandateChain::verify`], and skipping the check requires
/// naming [`TrustAnchor::unchecked`] out loud.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchor {
    /// `None` means every root is admitted.
    roots: Option<BTreeSet<String>>,
}

impl TrustAnchor {
    /// Trust exactly one root key.
    #[must_use]
    pub fn root(key: &PublicKey) -> Self {
        Self {
            roots: Some([key.to_hex()].into_iter().collect()),
        }
    }

    /// Trust any of several root keys.
    #[must_use]
    pub fn any_of<'a, I: IntoIterator<Item = &'a PublicKey>>(keys: I) -> Self {
        Self {
            roots: Some(keys.into_iter().map(PublicKey::to_hex).collect()),
        }
    }

    /// Admit every root, checking only the chain's internal consistency.
    ///
    /// This is the right choice in exactly two situations: relaying or storing
    /// a chain without acting on it, and displaying one to a human who will
    /// judge the root themselves. It is the wrong choice anywhere a mandate
    /// decides whether an action may happen — a self-issued chain from a key
    /// invented five seconds ago passes every other rule in this module.
    #[must_use]
    pub fn unchecked() -> Self {
        Self { roots: None }
    }

    /// Whether this anchor admits `root` as a source of authority.
    #[must_use]
    pub fn admits(&self, root: &PublicKey) -> bool {
        self.roots
            .as_ref()
            .is_none_or(|roots| roots.contains(&root.to_hex()))
    }

    /// Whether this anchor admits every root.
    #[must_use]
    pub fn is_unchecked(&self) -> bool {
        self.roots.is_none()
    }
}

/// Revocations a verifier knows about: which link, and who revoked it.
///
/// The revoker is recorded because a revocation is only honoured from the
/// link's own issuer or the chain's root authority. That check needs the chain,
/// which is exactly what [`MandateChain::verify`] has in hand — so revocation
/// authority is decided there rather than being assumed at collection time,
/// where a kind:50002 event naming an opaque hash cannot be judged at all.
///
/// Because every link commits to its parent's id, revoking a link invalidates
/// every chain that passes through it: a verifier never has to enumerate the
/// descendants of a revoked grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationSet {
    revokers: BTreeMap<LinkId, BTreeSet<String>>,
}

impl RevocationSet {
    /// An empty set — nothing revoked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `revoker` revoked `id`.
    ///
    /// Whether that revocation is *honoured* depends on the chain it is checked
    /// against; see [`MandateChain::verify`].
    pub fn insert(&mut self, id: LinkId, revoker: &PublicKey) -> bool {
        self.revokers
            .entry(id)
            .or_default()
            .insert(revoker.to_hex())
    }

    /// Whether `id` was revoked by any of `authorized`.
    #[must_use]
    pub fn is_revoked_by_any(&self, id: &LinkId, authorized: &[&PublicKey]) -> bool {
        self.revokers.get(id).is_some_and(|revokers| {
            authorized
                .iter()
                .any(|key| revokers.contains(&key.to_hex()))
        })
    }

    /// Number of distinct revoked link ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revokers.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revokers.is_empty()
    }
}

impl FromIterator<(LinkId, PublicKey)> for RevocationSet {
    fn from_iter<I: IntoIterator<Item = (LinkId, PublicKey)>>(iter: I) -> Self {
        let mut out = Self::new();
        for (id, revoker) in iter {
            out.insert(id, &revoker);
        }
        out
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
    pub fn verify(
        &self,
        anchor: &TrustAnchor,
        revoked: &RevocationSet,
    ) -> Result<VerifiedMandate<'_>, MandateError> {
        let (Some(root), Some(leaf)) = (self.links.first(), self.links.last()) else {
            return Err(MandateError::EmptyChain);
        };
        if !anchor.admits(root.issuer()) {
            return Err(MandateError::UntrustedRoot {
                root: root.issuer().to_hex(),
            });
        }
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

            // A revocation counts only from the link's own issuer or from the
            // root authority. Anyone else naming the id is noise, and honouring
            // it would let a stranger disable a mandate they were never party
            // to.
            if revoked.is_revoked_by_any(&link.id(), &[link.issuer(), root.issuer()]) {
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

// Unknown fields are refused rather than ignored: a tolerated field is a place
// to hide bytes that change the event id while leaving the chain identical.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    v: u32,
    links: Vec<WireLink>,
}
