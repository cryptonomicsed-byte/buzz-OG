//! The NIP-CM caveat algebra.
//!
//! A [`Caveats`] value is a set of constraints over eight independent
//! dimensions. Every dimension is either *present* (constrained) or *absent*
//! (unconstrained), and each has a decidable narrowing relation, which is what
//! lets a verifier *prove* that a delegation attenuates rather than trusting
//! the issuer to have attenuated honestly.
//!
//! # Canonical form
//!
//! A caveat set has exactly one legal encoding:
//!
//! ```text
//! channel=<ids>&depth=<n>&expires=<unix>&kind=<ns>&not_before=<unix>&peer=<keys>&tool=<names>&uses=<n>
//! ```
//!
//! Dimensions appear in ascending lexicographic order, only when present. Set
//! members are ascending and deduplicated — numerically for `kind`, bytewise
//! for the string-valued dimensions. Integers are canonical base-10 with no
//! leading zeroes. No whitespace appears anywhere.
//!
//! Canonicality is enforced on parse rather than repaired, because a link's id
//! is a hash of its encoded caveats: if two encodings could denote the same
//! set, one mandate would have two ids, and revoking one would not revoke the
//! other.

use std::collections::BTreeSet;
use std::fmt;

use crate::error::{CaveatError, DenyReason};

/// Maximum event kind permitted in a `kind` caveat, matching NIP-OA.
pub const MAX_KIND: u32 = 65535;

/// Maximum length of a `channel` or `tool` member, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// Maximum length of an encoded caveat set, in bytes.
///
/// Every verifier hashes and set-compares this string once per link per event,
/// so it needs a bound that does not depend on whatever body-size limit a
/// particular relay happens to run with.
pub const MAX_CAVEATS_LEN: usize = 2048;

/// Maximum number of members in one set-valued dimension.
pub const MAX_SET_MEMBERS: usize = 64;

/// Maximum `depth` value. Delegation depth is additionally capped by
/// [`crate::MAX_CHAIN_LEN`]; this bound only keeps the encoding small.
pub const MAX_DEPTH: u32 = 255;

const DIM_CHANNEL: &str = "channel";
const DIM_DEPTH: &str = "depth";
const DIM_EXPIRES: &str = "expires";
const DIM_KIND: &str = "kind";
const DIM_NOT_BEFORE: &str = "not_before";
const DIM_PEER: &str = "peer";
const DIM_TOOL: &str = "tool";
const DIM_USES: &str = "uses";

/// The concrete action a subject is attempting, checked against a mandate's
/// caveats by [`Caveats::authorizes`].
///
/// Every field is optional because not every action touches every dimension.
/// NIP-CM fails closed: if the mandate constrains a dimension the request
/// leaves `None`, the request is denied. A caller must therefore state
/// everything it knows about the action, not only what it expects to be
/// checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request<'a> {
    /// Event kind the subject wants to publish, if the action publishes one.
    /// An event has exactly one kind, so this stays singular.
    pub kind: Option<u32>,
    /// Channels the action targets — every NIP-29 `h` tag on the event.
    pub channels: &'a [&'a str],
    /// Counterparty pubkeys (lowercase hex) the action targets — every `p` tag.
    pub peers: &'a [&'a str],
    /// Tools or methods the action invokes.
    pub tools: &'a [&'a str],
}

/// Everything a verifier knows that is not in the mandate itself.
///
/// Kept separate from the chain so that verification is a pure function of
/// (chain, context): the subject never supplies its own clock or its own use
/// count, which is what closes the backdating hole that NIP-OA documents in its
/// security considerations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyContext {
    /// The verifier's wall-clock time, as a Unix timestamp in seconds.
    pub now: u64,
    /// How many invocations the verifier has already attributed to this
    /// mandate. Verifiers that do not track use counts pass `0`, which makes
    /// any `uses` caveat advisory rather than enforced.
    pub uses_consumed: u32,
}

impl VerifyContext {
    /// A context at `now` with a known invocation count.
    #[must_use]
    pub const fn new(now: u64, uses_consumed: u32) -> Self {
        Self { now, uses_consumed }
    }

    /// A context at `now` for a verifier that does not track invocations.
    ///
    /// Named for what it gives up: a `uses` caveat cannot be enforced without
    /// a count, so under this context it is advisory and a mandate with
    /// `uses=1` will authorize a thousand calls. Use
    /// [`VerifyContext::new`] wherever a budget is meant to bite.
    #[must_use]
    pub const fn at_untracked(now: u64) -> Self {
        Self::new(now, 0)
    }
}

/// A parsed, canonical NIP-CM caveat set.
///
/// Construct with [`Caveats::parse`] or [`Caveats::builder`]. An all-absent set
/// (`Caveats::default()`) is *unconstrained*: it permits any request at any
/// time. That is legal but rarely what an issuer wants — see
/// [`Caveats::is_unconstrained`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caveats {
    channels: Option<BTreeSet<String>>,
    depth: Option<u32>,
    expires: Option<u64>,
    kinds: Option<BTreeSet<u32>>,
    not_before: Option<u64>,
    peers: Option<BTreeSet<String>>,
    tools: Option<BTreeSet<String>>,
    uses: Option<u32>,
}

impl Caveats {
    /// Start building a caveat set.
    #[must_use]
    pub fn builder() -> CaveatsBuilder {
        CaveatsBuilder {
            caveats: Self::default(),
        }
    }

    /// Permitted channels, or `None` if any channel is permitted.
    #[must_use]
    pub fn channels(&self) -> Option<&BTreeSet<String>> {
        self.channels.as_ref()
    }

    /// Remaining sub-delegation hops, or `None` if unbounded.
    #[must_use]
    pub const fn depth(&self) -> Option<u32> {
        self.depth
    }

    /// Exclusive upper time bound, or `None` if the mandate never expires.
    #[must_use]
    pub const fn expires(&self) -> Option<u64> {
        self.expires
    }

    /// Permitted event kinds, or `None` if any kind is permitted.
    #[must_use]
    pub fn kinds(&self) -> Option<&BTreeSet<u32>> {
        self.kinds.as_ref()
    }

    /// Inclusive lower time bound, or `None` if the mandate is valid immediately.
    #[must_use]
    pub const fn not_before(&self) -> Option<u64> {
        self.not_before
    }

    /// Permitted counterparty pubkeys, or `None` if any peer is permitted.
    #[must_use]
    pub fn peers(&self) -> Option<&BTreeSet<String>> {
        self.peers.as_ref()
    }

    /// Permitted tool names, or `None` if any tool is permitted.
    #[must_use]
    pub fn tools(&self) -> Option<&BTreeSet<String>> {
        self.tools.as_ref()
    }

    /// Invocation budget, or `None` if unlimited.
    #[must_use]
    pub const fn uses(&self) -> Option<u32> {
        self.uses
    }

    /// True when no dimension is constrained, i.e. the set permits everything.
    #[must_use]
    pub const fn is_unconstrained(&self) -> bool {
        self.channels.is_none()
            && self.depth.is_none()
            && self.expires.is_none()
            && self.kinds.is_none()
            && self.not_before.is_none()
            && self.peers.is_none()
            && self.tools.is_none()
            && self.uses.is_none()
    }

    /// Parse a canonical caveat string.
    ///
    /// The empty string parses to the unconstrained set.
    ///
    /// # Errors
    ///
    /// Returns [`CaveatError`] if the string is malformed *or* merely
    /// non-canonical — unordered dimensions, duplicate members, leading zeroes,
    /// and empty member sets are all rejected rather than normalised.
    pub fn parse(s: &str) -> Result<Self, CaveatError> {
        if s.is_empty() {
            return Ok(Self::default());
        }

        if s.len() > MAX_CAVEATS_LEN {
            return Err(CaveatError::TooLong {
                len: s.len(),
                max: MAX_CAVEATS_LEN,
            });
        }

        if let Some(position) = s.bytes().position(|b| !(0x21..=0x7e).contains(&b)) {
            return Err(CaveatError::IllegalByte { position });
        }

        let mut out = Self::default();
        let mut previous_dimension: Option<&str> = None;

        for clause in s.split('&') {
            if clause.is_empty() {
                return Err(CaveatError::EmptyClause);
            }

            let (dimension, value) =
                clause
                    .split_once('=')
                    .ok_or_else(|| CaveatError::MissingSeparator {
                        clause: clause.to_owned(),
                    })?;

            let dimension = canonical_dimension(dimension)?;

            if let Some(previous) = previous_dimension {
                if dimension == previous {
                    return Err(CaveatError::DuplicateDimension {
                        dimension: dimension.to_owned(),
                    });
                }
                if dimension < previous {
                    return Err(CaveatError::UnorderedDimensions {
                        dimension: dimension.to_owned(),
                    });
                }
            }
            previous_dimension = Some(dimension);

            match dimension {
                DIM_CHANNEL => out.channels = Some(parse_name_set(DIM_CHANNEL, value)?),
                DIM_DEPTH => {
                    out.depth =
                        Some(parse_scalar(DIM_DEPTH, value, 0, u64::from(MAX_DEPTH))? as u32);
                }
                DIM_EXPIRES => {
                    out.expires = Some(parse_scalar(DIM_EXPIRES, value, 0, u64::from(u32::MAX))?);
                }
                DIM_KIND => out.kinds = Some(parse_kind_set(value)?),
                DIM_NOT_BEFORE => {
                    out.not_before =
                        Some(parse_scalar(DIM_NOT_BEFORE, value, 0, u64::from(u32::MAX))?);
                }
                DIM_PEER => out.peers = Some(parse_peer_set(value)?),
                DIM_TOOL => out.tools = Some(parse_name_set(DIM_TOOL, value)?),
                DIM_USES => {
                    out.uses = Some(parse_scalar(DIM_USES, value, 1, u64::from(u32::MAX))? as u32);
                }
                other => {
                    return Err(CaveatError::UnknownDimension {
                        dimension: other.to_owned(),
                    })
                }
            }
        }

        out.check_time_window()?;
        Ok(out)
    }

    fn check_time_window(&self) -> Result<(), CaveatError> {
        if let (Some(not_before), Some(expires)) = (self.not_before, self.expires) {
            if not_before >= expires {
                return Err(CaveatError::EmptyTimeWindow {
                    not_before,
                    expires,
                });
            }
        }
        Ok(())
    }

    /// Encode to the canonical string form.
    ///
    /// `Caveats::parse(&c.to_canonical_string())` round-trips to `c`, and
    /// parsing only ever accepts strings already in this form.
    #[must_use]
    pub fn to_canonical_string(&self) -> String {
        let mut clauses: Vec<String> = Vec::with_capacity(8);

        if let Some(channels) = &self.channels {
            clauses.push(format!("{DIM_CHANNEL}={}", join_strings(channels)));
        }
        if let Some(depth) = self.depth {
            clauses.push(format!("{DIM_DEPTH}={depth}"));
        }
        if let Some(expires) = self.expires {
            clauses.push(format!("{DIM_EXPIRES}={expires}"));
        }
        if let Some(kinds) = &self.kinds {
            let members: Vec<String> = kinds.iter().map(u32::to_string).collect();
            clauses.push(format!("{DIM_KIND}={}", members.join(",")));
        }
        if let Some(not_before) = self.not_before {
            clauses.push(format!("{DIM_NOT_BEFORE}={not_before}"));
        }
        if let Some(peers) = &self.peers {
            clauses.push(format!("{DIM_PEER}={}", join_strings(peers)));
        }
        if let Some(tools) = &self.tools {
            clauses.push(format!("{DIM_TOOL}={}", join_strings(tools)));
        }
        if let Some(uses) = self.uses {
            clauses.push(format!("{DIM_USES}={uses}"));
        }

        clauses.join("&")
    }

    /// Check that `self` grants no more authority than `parent` on any
    /// dimension — the attenuation guarantee at the heart of NIP-CM.
    ///
    /// The rule is *explicit restatement*: for every dimension `parent`
    /// constrains, `self` must constrain it too, at least as tightly. Dropping
    /// a constraint is rejected rather than silently re-inherited, so the last
    /// link of a chain is a complete statement of the chain's authority and a
    /// reader never has to intersect links in their head.
    ///
    /// `self` may constrain dimensions `parent` leaves open — that is
    /// narrowing, not widening.
    ///
    /// `depth` is special: a child must have *strictly less* remaining depth
    /// than its parent, which is what makes chain length self-limiting.
    ///
    /// # Errors
    ///
    /// Returns the offending dimension and the reason it widened.
    pub fn narrows(&self, parent: &Self) -> Result<(), String> {
        narrows_set(
            DIM_CHANNEL,
            self.channels.as_ref(),
            parent.channels.as_ref(),
        )?;
        narrows_set(DIM_KIND, self.kinds.as_ref(), parent.kinds.as_ref())?;
        narrows_set(DIM_PEER, self.peers.as_ref(), parent.peers.as_ref())?;
        narrows_set(DIM_TOOL, self.tools.as_ref(), parent.tools.as_ref())?;

        narrows_bound(DIM_EXPIRES, self.expires, parent.expires, Bound::Upper)?;
        narrows_bound(
            DIM_NOT_BEFORE,
            self.not_before,
            parent.not_before,
            Bound::Lower,
        )?;
        narrows_bound(
            DIM_USES,
            self.uses.map(u64::from),
            parent.uses.map(u64::from),
            Bound::Upper,
        )?;

        // Depth must strictly decrease. `parent_depth == 0` is caught by the
        // caller as `DepthExhausted`, which is a clearer diagnosis than
        // "0 does not narrow 0".
        match (self.depth, parent.depth) {
            (_, None) => {}
            (None, Some(_)) => {
                return Err(format!("{DIM_DEPTH}: parent constrains it, child does not"))
            }
            (Some(child), Some(parent_depth)) => {
                if parent_depth == 0 || child >= parent_depth {
                    return Err(format!(
                        "{DIM_DEPTH}: child {child} must be strictly less than parent {parent_depth}"
                    ));
                }
            }
        }

        Ok(())
    }

    /// Decide whether these caveats authorize `request` under `context`.
    ///
    /// Time bounds are checked against `context.now` — never against any
    /// timestamp the subject controls.
    ///
    /// # Errors
    ///
    /// Returns the specific [`DenyReason`]; dimensions are checked in a fixed
    /// order so the reason is deterministic for a given input.
    pub fn authorizes(
        &self,
        request: &Request<'_>,
        context: &VerifyContext,
    ) -> Result<(), DenyReason> {
        if let Some(not_before) = self.not_before {
            if context.now < not_before {
                return Err(DenyReason::NotYetValid {
                    now: context.now,
                    not_before,
                });
            }
        }
        if let Some(expires) = self.expires {
            if context.now >= expires {
                return Err(DenyReason::Expired {
                    now: context.now,
                    expires,
                });
            }
        }

        if let Some(kinds) = &self.kinds {
            let kind = request.kind.ok_or(DenyReason::UnstatedDimension {
                dimension: DIM_KIND,
            })?;
            if !kinds.contains(&kind) {
                return Err(DenyReason::OutOfScope {
                    dimension: DIM_KIND,
                    value: kind.to_string(),
                });
            }
        }

        check_membership(DIM_CHANNEL, self.channels.as_ref(), request.channels)?;
        check_membership(DIM_PEER, self.peers.as_ref(), request.peers)?;
        check_membership(DIM_TOOL, self.tools.as_ref(), request.tools)?;

        if let Some(budget) = self.uses {
            if context.uses_consumed >= budget {
                return Err(DenyReason::BudgetExhausted {
                    consumed: context.uses_consumed,
                    budget,
                });
            }
        }

        Ok(())
    }
}

impl fmt::Display for Caveats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

/// Fluent constructor for [`Caveats`].
///
/// Setters replace rather than accumulate, and set-valued setters sort and
/// deduplicate their input, so a builder cannot produce a non-canonical set.
#[derive(Debug, Clone, Default)]
pub struct CaveatsBuilder {
    caveats: Caveats,
}

impl CaveatsBuilder {
    /// Constrain to the given channel ids.
    #[must_use]
    pub fn channels<I, S>(mut self, channels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.caveats.channels = Some(channels.into_iter().map(Into::into).collect());
        self
    }

    /// Constrain to the given event kinds.
    #[must_use]
    pub fn kinds<I: IntoIterator<Item = u32>>(mut self, kinds: I) -> Self {
        self.caveats.kinds = Some(kinds.into_iter().collect());
        self
    }

    /// Constrain to the given counterparty pubkeys (lowercase hex).
    #[must_use]
    pub fn peers<I, S>(mut self, peers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.caveats.peers = Some(peers.into_iter().map(Into::into).collect());
        self
    }

    /// Constrain to the given tool names.
    #[must_use]
    pub fn tools<I, S>(mut self, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.caveats.tools = Some(tools.into_iter().map(Into::into).collect());
        self
    }

    /// Set the inclusive lower time bound.
    #[must_use]
    pub const fn not_before(mut self, not_before: u64) -> Self {
        self.caveats.not_before = Some(not_before);
        self
    }

    /// Set the exclusive upper time bound.
    #[must_use]
    pub const fn expires(mut self, expires: u64) -> Self {
        self.caveats.expires = Some(expires);
        self
    }

    /// Set the invocation budget.
    #[must_use]
    pub const fn uses(mut self, uses: u32) -> Self {
        self.caveats.uses = Some(uses);
        self
    }

    /// Set the remaining sub-delegation depth.
    #[must_use]
    pub const fn depth(mut self, depth: u32) -> Self {
        self.caveats.depth = Some(depth);
        self
    }

    /// Finish, validating the ranges and the time window.
    ///
    /// # Errors
    ///
    /// Returns [`CaveatError`] if any member is malformed, any set is empty,
    /// any scalar is out of range, or the time window is empty.
    pub fn build(self) -> Result<Caveats, CaveatError> {
        let caveats = self.caveats;

        validate_built_set(DIM_CHANNEL, caveats.channels.as_ref(), is_valid_name)?;
        validate_built_set(DIM_TOOL, caveats.tools.as_ref(), is_valid_name)?;
        validate_built_set(DIM_PEER, caveats.peers.as_ref(), is_valid_peer)?;

        if let Some(kinds) = &caveats.kinds {
            if kinds.is_empty() {
                return Err(CaveatError::EmptySet {
                    dimension: DIM_KIND.to_owned(),
                });
            }
            if let Some(kind) = kinds.iter().find(|k| **k > MAX_KIND) {
                return Err(CaveatError::InvalidMember {
                    dimension: DIM_KIND.to_owned(),
                    member: kind.to_string(),
                });
            }
        }

        check_scalar_range(
            DIM_DEPTH,
            caveats.depth.map(u64::from),
            0,
            u64::from(MAX_DEPTH),
        )?;
        check_scalar_range(
            DIM_USES,
            caveats.uses.map(u64::from),
            1,
            u64::from(u32::MAX),
        )?;
        check_scalar_range(DIM_EXPIRES, caveats.expires, 0, u64::from(u32::MAX))?;
        check_scalar_range(DIM_NOT_BEFORE, caveats.not_before, 0, u64::from(u32::MAX))?;

        caveats.check_time_window()?;
        Ok(caveats)
    }
}

enum Bound {
    Lower,
    Upper,
}

fn canonical_dimension(dimension: &str) -> Result<&str, CaveatError> {
    match dimension {
        DIM_CHANNEL | DIM_DEPTH | DIM_EXPIRES | DIM_KIND | DIM_NOT_BEFORE | DIM_PEER | DIM_TOOL
        | DIM_USES => Ok(dimension),
        other => Err(CaveatError::UnknownDimension {
            dimension: other.to_owned(),
        }),
    }
}

fn join_strings(set: &BTreeSet<String>) -> String {
    set.iter().map(String::as_str).collect::<Vec<_>>().join(",")
}

fn parse_scalar(dimension: &str, value: &str, min: u64, max: u64) -> Result<u64, CaveatError> {
    let invalid = || CaveatError::InvalidScalar {
        dimension: dimension.to_owned(),
        value: value.to_owned(),
    };

    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(invalid());
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let parsed: u64 = value.parse().map_err(|_| invalid())?;
    if parsed < min || parsed > max {
        return Err(invalid());
    }
    Ok(parsed)
}

fn check_scalar_range(
    dimension: &str,
    value: Option<u64>,
    min: u64,
    max: u64,
) -> Result<(), CaveatError> {
    if let Some(value) = value {
        if value < min || value > max {
            return Err(CaveatError::InvalidScalar {
                dimension: dimension.to_owned(),
                value: value.to_string(),
            });
        }
    }
    Ok(())
}

fn parse_kind_set(value: &str) -> Result<BTreeSet<u32>, CaveatError> {
    let mut out = BTreeSet::new();
    let mut previous: Option<u32> = None;

    for member in value.split(',') {
        let parsed = parse_scalar(DIM_KIND, member, 0, u64::from(MAX_KIND)).map_err(|_| {
            CaveatError::InvalidMember {
                dimension: DIM_KIND.to_owned(),
                member: member.to_owned(),
            }
        })? as u32;

        if let Some(previous) = previous {
            if parsed <= previous {
                return Err(CaveatError::UnorderedMembers {
                    dimension: DIM_KIND.to_owned(),
                });
            }
        }
        previous = Some(parsed);
        out.insert(parsed);
    }

    if out.is_empty() {
        return Err(CaveatError::EmptySet {
            dimension: DIM_KIND.to_owned(),
        });
    }
    if out.len() > MAX_SET_MEMBERS {
        return Err(CaveatError::TooManyMembers {
            dimension: DIM_KIND.to_owned(),
            count: out.len(),
            max: MAX_SET_MEMBERS,
        });
    }
    Ok(out)
}

fn parse_string_set(
    dimension: &str,
    value: &str,
    is_valid: fn(&str) -> bool,
) -> Result<BTreeSet<String>, CaveatError> {
    let mut out = BTreeSet::new();
    let mut previous: Option<&str> = None;

    for member in value.split(',') {
        if !is_valid(member) {
            return Err(CaveatError::InvalidMember {
                dimension: dimension.to_owned(),
                member: member.to_owned(),
            });
        }
        if let Some(previous) = previous {
            if member <= previous {
                return Err(CaveatError::UnorderedMembers {
                    dimension: dimension.to_owned(),
                });
            }
        }
        previous = Some(member);
        out.insert(member.to_owned());
    }

    if out.is_empty() {
        return Err(CaveatError::EmptySet {
            dimension: dimension.to_owned(),
        });
    }
    if out.len() > MAX_SET_MEMBERS {
        return Err(CaveatError::TooManyMembers {
            dimension: dimension.to_owned(),
            count: out.len(),
            max: MAX_SET_MEMBERS,
        });
    }
    Ok(out)
}

fn parse_name_set(dimension: &str, value: &str) -> Result<BTreeSet<String>, CaveatError> {
    parse_string_set(dimension, value, is_valid_name)
}

fn parse_peer_set(value: &str) -> Result<BTreeSet<String>, CaveatError> {
    parse_string_set(DIM_PEER, value, is_valid_peer)
}

/// Channel ids and tool names: 1–64 bytes of `[A-Za-z0-9._:/-]`.
///
/// The charset deliberately excludes `&`, `,`, and `=` so that a member can
/// never forge a clause boundary, and excludes whitespace so that the encoding
/// has no ambiguous forms.
fn is_valid_name(member: &str) -> bool {
    !member.is_empty()
        && member.len() <= MAX_NAME_LEN
        && member
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

/// Peers are 64 lowercase hex characters — a BIP-340 x-only public key.
fn is_valid_peer(member: &str) -> bool {
    member.len() == 64
        && member
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_built_set(
    dimension: &str,
    set: Option<&BTreeSet<String>>,
    is_valid: fn(&str) -> bool,
) -> Result<(), CaveatError> {
    let Some(set) = set else { return Ok(()) };

    if set.is_empty() {
        return Err(CaveatError::EmptySet {
            dimension: dimension.to_owned(),
        });
    }
    if let Some(member) = set.iter().find(|m| !is_valid(m)) {
        return Err(CaveatError::InvalidMember {
            dimension: dimension.to_owned(),
            member: member.clone(),
        });
    }
    Ok(())
}

fn narrows_set<T: Ord>(
    dimension: &str,
    child: Option<&BTreeSet<T>>,
    parent: Option<&BTreeSet<T>>,
) -> Result<(), String> {
    let Some(parent) = parent else { return Ok(()) };

    let Some(child) = child else {
        return Err(format!("{dimension}: parent constrains it, child does not"));
    };

    if child.is_subset(parent) {
        Ok(())
    } else {
        Err(format!(
            "{dimension}: child admits members the parent does not"
        ))
    }
}

fn narrows_bound(
    dimension: &str,
    child: Option<u64>,
    parent: Option<u64>,
    bound: Bound,
) -> Result<(), String> {
    let Some(parent) = parent else { return Ok(()) };

    let Some(child) = child else {
        return Err(format!("{dimension}: parent constrains it, child does not"));
    };

    let ok = match bound {
        Bound::Upper => child <= parent,
        Bound::Lower => child >= parent,
    };

    if ok {
        Ok(())
    } else {
        let relation = match bound {
            Bound::Upper => "at most",
            Bound::Lower => "at least",
        };
        Err(format!(
            "{dimension}: child {child} must be {relation} parent {parent}"
        ))
    }
}

/// Check every value a request states on one dimension.
///
/// A Nostr event carries as many `h` and `p` tags as its author chose, and an
/// action that touches two channels touches both of them. So *every* stated
/// value must be permitted, not merely the first: a verifier that checked one
/// and stopped would authorize an event tagged `h=engineering` and `h=secrets`
/// under a mandate scoped to `engineering` alone.
///
/// Stating nothing on a constrained dimension is still a denial, for the same
/// fail-closed reason silence has always been one here.
fn check_membership(
    dimension: &'static str,
    permitted: Option<&BTreeSet<String>>,
    values: &[&str],
) -> Result<(), DenyReason> {
    let Some(permitted) = permitted else {
        return Ok(());
    };

    if values.is_empty() {
        return Err(DenyReason::UnstatedDimension { dimension });
    }

    for value in values {
        if !permitted.contains(*value) {
            return Err(DenyReason::OutOfScope {
                dimension,
                value: (*value).to_owned(),
            });
        }
    }
    Ok(())
}
