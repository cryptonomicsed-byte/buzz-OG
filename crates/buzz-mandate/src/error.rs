//! Error types for NIP-CM capability mandates.

use thiserror::Error;

/// A link id was not 64 lowercase hex characters.
///
/// Uppercase is rejected as well as non-hex: link ids appear verbatim inside
/// signing preimages, so two spellings of one id would be two signed messages.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
#[error("link id must be 64 lowercase hex characters")]
pub struct InvalidLinkId;

/// A caveat string was malformed, non-canonical, or semantically empty.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CaveatError {
    /// The encoded caveat set exceeded [`crate::caveat::MAX_CAVEATS_LEN`].
    #[error("caveats are {len} bytes, exceeding the maximum of {max}")]
    TooLong {
        /// Actual encoded length in bytes.
        len: usize,
        /// The protocol maximum.
        max: usize,
    },

    /// A set-valued dimension had more members than
    /// [`crate::caveat::MAX_SET_MEMBERS`].
    #[error("caveat dimension {dimension:?} has {count} members, exceeding the maximum of {max}")]
    TooManyMembers {
        /// The oversized dimension.
        dimension: String,
        /// Actual member count.
        count: usize,
        /// The protocol maximum.
        max: usize,
    },

    /// The caveat string contained a byte that is never legal (whitespace,
    /// control character, or non-ASCII).
    #[error("caveats contain an illegal byte at position {position}")]
    IllegalByte {
        /// Zero-based byte offset of the offending byte.
        position: usize,
    },

    /// A clause was empty — a leading, trailing, or doubled `&`.
    #[error("empty clause in caveats (leading, trailing, or doubled '&')")]
    EmptyClause,

    /// A clause did not contain the required `=` separator.
    #[error("clause {clause:?} is missing '='")]
    MissingSeparator {
        /// The offending clause.
        clause: String,
    },

    /// The dimension name is not one of the eight defined by NIP-CM.
    #[error("unknown caveat dimension {dimension:?}")]
    UnknownDimension {
        /// The unrecognised dimension name.
        dimension: String,
    },

    /// The same dimension appeared more than once.
    #[error("duplicate caveat dimension {dimension:?}")]
    DuplicateDimension {
        /// The repeated dimension name.
        dimension: String,
    },

    /// Dimensions were not in ascending lexicographic order. Canonical order is
    /// required so that a caveat set has exactly one encoding.
    #[error("caveat dimensions are not in canonical (ascending) order at {dimension:?}")]
    UnorderedDimensions {
        /// The dimension that appeared out of order.
        dimension: String,
    },

    /// A set-valued dimension had no members. An empty set grants nothing and
    /// must not be encoded; issue no mandate instead.
    #[error("caveat dimension {dimension:?} has an empty member set")]
    EmptySet {
        /// The dimension with no members.
        dimension: String,
    },

    /// Set members were not in ascending order, or contained duplicates.
    #[error("caveat dimension {dimension:?} members are unordered or duplicated")]
    UnorderedMembers {
        /// The dimension whose members were not canonical.
        dimension: String,
    },

    /// A member of a set-valued dimension was malformed.
    #[error("caveat dimension {dimension:?} has invalid member {member:?}")]
    InvalidMember {
        /// The dimension the member belongs to.
        dimension: String,
        /// The malformed member.
        member: String,
    },

    /// A scalar value was not a canonical base-10 integer in range.
    #[error("caveat dimension {dimension:?} has invalid scalar value {value:?}")]
    InvalidScalar {
        /// The dimension the value belongs to.
        dimension: String,
        /// The malformed value.
        value: String,
    },

    /// `not_before` was greater than or equal to `expires`, so the mandate is
    /// valid during no instant at all.
    #[error("caveats describe an empty time window: not_before {not_before} >= expires {expires}")]
    EmptyTimeWindow {
        /// The lower bound.
        not_before: u64,
        /// The upper bound.
        expires: u64,
    },
}

/// A link, or a chain of links, failed verification.
///
/// Every variant that can be attributed to a specific link carries its
/// zero-based index so callers can report precisely where a chain broke.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MandateError {
    /// A caveat set failed to parse.
    #[error("link {index}: {source}")]
    Caveat {
        /// Zero-based index of the offending link.
        index: usize,
        /// The underlying caveat failure.
        #[source]
        source: CaveatError,
    },

    /// The chain had no links.
    #[error("mandate chain is empty")]
    EmptyChain,

    /// The chain's root is not a key the verifier derives authority from.
    ///
    /// A structurally perfect chain proves only that authority flowed correctly
    /// from its own root. Anyone can invent a keypair and self-issue an
    /// unconstrained mandate, so a verifier that skips this check grants
    /// everything to everyone.
    #[error("mandate chain is rooted at untrusted key {root}")]
    UntrustedRoot {
        /// The root issuer the chain claims authority from.
        root: String,
    },

    /// The chain exceeded [`crate::MAX_CHAIN_LEN`].
    #[error("mandate chain has {len} links, exceeding the maximum of {max}")]
    ChainTooLong {
        /// Actual number of links.
        len: usize,
        /// The protocol maximum.
        max: usize,
    },

    /// The root link declared a parent, or a non-root link did not.
    #[error("link {index}: unexpected parent linkage")]
    BadLinkage {
        /// Zero-based index of the offending link.
        index: usize,
    },

    /// A link's `parent` did not equal the previous link's id, so the two links
    /// do not belong to the same chain.
    #[error("link {index}: parent does not match the previous link's id")]
    ParentMismatch {
        /// Zero-based index of the offending link.
        index: usize,
    },

    /// A link was issued by a key that was not the previous link's subject, so
    /// authority did not flow along the chain.
    #[error("link {index}: issuer is not the previous link's subject")]
    IssuerNotSubject {
        /// Zero-based index of the offending link.
        index: usize,
    },

    /// A link delegated authority to its own issuer.
    #[error("link {index}: issuer and subject are the same key")]
    SelfDelegation {
        /// Zero-based index of the offending link.
        index: usize,
    },

    /// A key appeared as the subject of more than one link, which would let a
    /// chain loop to inflate its length without adding real delegation.
    #[error("link {index}: subject already appears earlier in the chain")]
    RepeatedSubject {
        /// Zero-based index of the offending link.
        index: usize,
    },

    /// A link's signature did not verify against its issuer.
    #[error("link {index}: signature verification failed")]
    BadSignature {
        /// Zero-based index of the offending link.
        index: usize,
    },

    /// A link's caveats did not narrow its parent's caveats. This is the
    /// attenuation guarantee: authority may only shrink along a chain.
    #[error("link {index}: caveats do not narrow the parent link ({reason})")]
    NotNarrowing {
        /// Zero-based index of the offending link.
        index: usize,
        /// Which dimension broke monotonicity, and how.
        reason: String,
    },

    /// A link's parent had exhausted its delegation depth, so it could not
    /// legally issue a further link.
    #[error("link {index}: parent link has no remaining delegation depth")]
    DepthExhausted {
        /// Zero-based index of the offending link.
        index: usize,
    },

    /// A link id appeared in the revocation set supplied to the verifier.
    #[error("link {index}: revoked")]
    Revoked {
        /// Zero-based index of the revoked link.
        index: usize,
    },

    /// A field was not the expected hex encoding, or the encoded key or
    /// signature was invalid.
    #[error("link {index}: invalid {field}")]
    InvalidField {
        /// Zero-based index of the offending link.
        index: usize,
        /// Name of the malformed field.
        field: &'static str,
    },

    /// The serialised chain envelope was malformed.
    #[error("malformed mandate envelope: {0}")]
    MalformedEnvelope(String),
}

/// A verified chain did not authorize a specific request.
///
/// Distinct from [`MandateError`] on purpose: a chain can be cryptographically
/// perfect and still not permit the action being attempted.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DenyReason {
    /// The key attempting the action is not the mandate's subject.
    ///
    /// This is the check that defeats chain truncation. A holder of a chain
    /// `root → A → B` can always present the prefix `root → A`, which is
    /// perfectly valid and usually *wider* — but its subject is `A`, so it
    /// authorizes nothing for `B`.
    #[error("actor {actor} is not the mandate subject {subject}")]
    WrongSubject {
        /// The key that attempted the action.
        actor: String,
        /// The key the mandate actually empowers.
        subject: String,
    },

    /// The verifier's clock is before the mandate's `not_before` bound.
    #[error("mandate is not yet valid: now {now} < not_before {not_before}")]
    NotYetValid {
        /// The clock supplied by the verifier.
        now: u64,
        /// The mandate's lower time bound.
        not_before: u64,
    },

    /// The verifier's clock is at or past the mandate's `expires` bound.
    #[error("mandate has expired: now {now} >= expires {expires}")]
    Expired {
        /// The clock supplied by the verifier.
        now: u64,
        /// The mandate's upper time bound.
        expires: u64,
    },

    /// The mandate constrains a dimension the request left unspecified. NIP-CM
    /// fails closed: an unstated attribute is never assumed to be in scope.
    #[error("request does not state {dimension}, which the mandate constrains")]
    UnstatedDimension {
        /// The constrained dimension the request omitted.
        dimension: &'static str,
    },

    /// The request's value for a constrained dimension was outside the
    /// mandate's permitted set.
    #[error("request {dimension} {value:?} is outside the mandate's permitted set")]
    OutOfScope {
        /// The constrained dimension.
        dimension: &'static str,
        /// The value the request supplied.
        value: String,
    },

    /// The mandate's invocation budget has been spent.
    #[error("mandate use budget exhausted: {consumed} of {budget} used")]
    BudgetExhausted {
        /// How many invocations the verifier has already counted.
        consumed: u32,
        /// The budget the mandate allows.
        budget: u32,
    },
}
