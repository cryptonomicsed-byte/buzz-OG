//! NIP-CM — Capability Mandates.
//!
//! A capability mandate is a signed chain of delegation links that proves an
//! agent may take a specific action, and that every key between the root
//! authority and that agent narrowed the authority rather than widened it.
//!
//! # Why this exists
//!
//! Buzz already gives agents their own keypairs, and [NIP-OA] lets an owner
//! attest that an agent may publish. That attestation is a single hop with a
//! three-clause condition language, and it is deliberately scoped that way: it
//! answers "did a human authorize this agent to speak?"
//!
//! Agents ask a harder question of each other. A planner agent that fans work
//! out to four workers needs to hand each worker *less* authority than it
//! holds, prove the reduction to a third party that trusts neither of them, and
//! have the whole grant lapse in ten minutes whether or not anyone remembers to
//! clean up. NIP-OA cannot express that: it has no second hop, no channel or
//! tool scope, no budget, no revocation, and — as its own security section
//! notes — its time clauses constrain a timestamp the agent itself writes, so a
//! misbehaving agent can backdate past an expiry.
//!
//! NIP-CM closes exactly those gaps and nothing else. It does not replace
//! NIP-OA; an agent typically holds both, the attestation proving *who owns me*
//! and a mandate proving *what I may do right now*.
//!
//! # The four properties
//!
//! **Attenuation is proved, not promised.** Each link must restate every
//! dimension its parent constrained, at least as tightly. A verifier computes
//! that relation ([`Caveats::narrows`]) instead of trusting the issuer to have
//! attenuated honestly.
//!
//! **The leaf is the whole story.** Because narrowing is explicit restatement
//! rather than accumulation, the last link's caveats already *are* the
//! intersection of the chain. Nobody has to fold four links in their head to
//! learn what an agent may do — which matters most at 3am, in a log line.
//!
//! **Time comes from the verifier.** [`VerifyContext::now`] is supplied by the
//! party enforcing the mandate. The subject never gets a vote on what time it
//! is, so backdating buys nothing.
//!
//! **Revoking a link revokes its subtree.** Every link commits to its parent's
//! id, so a revoked link invalidates every chain that passes through it. A
//! revocation list holds ids, not closures over descendants.
//!
//! # Wire format
//!
//! A chain is published as a kind:[`KIND_MANDATE_GRANT`] event whose content is
//! the JSON envelope from [`MandateChain::to_json`]. Revocation is a
//! kind:[`KIND_MANDATE_REVOKE`] event naming a link id. Any other event may
//! then *present* a mandate by carrying a `mandate` tag holding the grant
//! event's id — mandates ride along with existing Buzz traffic instead of
//! needing a transport of their own.
//!
//! # Example
//!
//! ```
//! use buzz_mandate::{Caveats, MandateChain, Request, RevocationSet, VerifyContext};
//! use nostr::Keys;
//!
//! let owner = Keys::generate();
//! let planner = Keys::generate();
//! let worker = Keys::generate();
//!
//! // The owner lets the planner post to two channels for an hour, and
//! // sub-delegate at most twice.
//! let broad = Caveats::builder()
//!     .kinds([9, 40002])
//!     .channels(["engineering", "general"])
//!     .expires(1_800_000_000)
//!     .depth(2)
//!     .build()?;
//! let chain = MandateChain::root(&owner, &planner.public_key(), broad)?;
//!
//! // The planner hands the worker strictly less: one channel, one kind,
//! // three invocations, and one remaining hop.
//! let narrow = Caveats::builder()
//!     .kinds([9])
//!     .channels(["engineering"])
//!     .expires(1_800_000_000)
//!     .uses(3)
//!     .depth(1)
//!     .build()?;
//! let chain = chain.delegate(&planner, &worker.public_key(), narrow)?;
//!
//! let mandate = chain.verify(&RevocationSet::new())?;
//! assert_eq!(mandate.subject(), &worker.public_key());
//!
//! let request = Request {
//!     kind: Some(9),
//!     channel: Some("engineering"),
//!     ..Request::default()
//! };
//! let now = VerifyContext::at(1_799_999_000);
//! let actor = worker.public_key();
//! assert!(mandate.authorizes(&actor, &request, &now).is_ok());
//!
//! // The channel the planner kept for itself was never delegated onward.
//! let out_of_scope = Request { channel: Some("general"), ..request.clone() };
//! assert!(mandate.authorizes(&actor, &out_of_scope, &now).is_err());
//!
//! // And the mandate is bound to the worker: nobody else can present it.
//! assert!(mandate.authorizes(&planner.public_key(), &request, &now).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [NIP-OA]: https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod caveat;
pub mod chain;
pub mod error;
pub mod link;

pub use caveat::{Caveats, CaveatsBuilder, Request, VerifyContext};
pub use chain::{MandateChain, RevocationSet, VerifiedMandate};
pub use error::{CaveatError, DenyReason, InvalidLinkId, MandateError};
pub use link::{Link, LinkId, WireLink, DOMAIN, ROOT_PARENT};

/// Maximum number of links in a chain: a root grant plus at most three
/// sub-delegations.
///
/// This matches the `depth ≤ 3` bound the Buzz agent job protocol already
/// assumes (see the kind 43001 comment in `buzz-core`). The cap is a hard
/// protocol limit; an issuer can impose a tighter one per-chain with a `depth`
/// caveat.
///
/// Breadth — how many sub-delegations a single link issues — is deliberately
/// *not* checked here. A chain proves one path from root to subject and carries
/// no evidence about its siblings, so breadth is only enforceable by a party
/// that sees all grants (the relay, or the issuer itself). Claiming otherwise
/// in a chain verifier would be security theatre.
pub const MAX_CHAIN_LEN: usize = 4;

/// Event kind carrying a mandate chain (see [`MandateChain::to_json`]), and the
/// kind revoking a link id along with every chain through it.
///
/// Re-exported from `buzz-core`, which is the single registry for every Buzz
/// event kind — defining them twice is how two integers drift apart.
pub use buzz_core::kind::{KIND_MANDATE_GRANT, KIND_MANDATE_REVOKE};

/// Tag name by which an ordinary event presents a mandate: `["mandate", "<grant-event-id>"]`.
pub const MANDATE_TAG: &str = "mandate";
