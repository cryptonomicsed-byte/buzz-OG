//! Chain assembly, verification, tampering, and the attenuation guarantee.

use std::collections::BTreeSet;

use buzz_mandate::{
    Caveats, MandateChain, MandateError, Request, RevocationSet, TrustAnchor, VerifyContext,
    MAX_CHAIN_LEN,
};
use nostr::{Keys, PublicKey};
use serde_json::Value;

fn caveats(s: &str) -> Caveats {
    Caveats::parse(s).unwrap_or_else(|e| panic!("expected {s:?} to parse, got {e}"))
}

/// Root grant used by most tests: two channels, two kinds, one hour, two hops.
fn broad() -> Caveats {
    caveats("channel=engineering,general&depth=2&expires=2000&kind=9,40002")
}

fn narrow() -> Caveats {
    caveats("channel=engineering&depth=1&expires=1500&kind=9")
}

struct Cast {
    owner: Keys,
    planner: Keys,
    worker: Keys,
}

impl Cast {
    fn new() -> Self {
        Self {
            owner: Keys::generate(),
            planner: Keys::generate(),
            worker: Keys::generate(),
        }
    }

    /// The owner is the only root this cast's verifiers trust.
    fn anchor(&self) -> TrustAnchor {
        TrustAnchor::root(&self.owner.public_key())
    }

    /// owner → planner → worker.
    fn two_hop(&self) -> MandateChain {
        MandateChain::root(&self.owner, &self.planner.public_key(), broad())
            .expect("root")
            .delegate(&self.planner, &self.worker.public_key(), narrow())
            .expect("delegate")
    }
}

// --- happy path ----------------------------------------------------------

#[test]
fn a_two_hop_chain_verifies() {
    let cast = Cast::new();
    let chain = cast.two_hop();
    let mandate = chain
        .verify(&cast.anchor(), &RevocationSet::new())
        .expect("verify");

    assert_eq!(mandate.root_authority(), &cast.owner.public_key());
    assert_eq!(mandate.subject(), &cast.worker.public_key());
    assert_eq!(mandate.hops(), 2);
    assert_eq!(mandate.effective_caveats(), &narrow());
}

#[test]
fn a_root_only_chain_verifies() {
    let cast = Cast::new();
    let chain = MandateChain::root(&cast.owner, &cast.planner.public_key(), broad()).expect("root");
    let mandate = chain
        .verify(&cast.anchor(), &RevocationSet::new())
        .expect("verify");
    assert_eq!(mandate.hops(), 1);
    assert_eq!(mandate.subject(), &cast.planner.public_key());
}

#[test]
fn the_json_envelope_round_trips() {
    let chain = Cast::new().two_hop();
    let json = chain.to_json().expect("serialise");
    assert_eq!(MandateChain::from_json(&json).expect("parse"), chain);
}

#[test]
fn a_verified_mandate_authorizes_only_what_the_leaf_permits() {
    let cast = Cast::new();
    let chain = cast.two_hop();
    let mandate = chain
        .verify(&cast.anchor(), &RevocationSet::new())
        .expect("verify");
    let context = VerifyContext::at_untracked(1000);

    let permitted = Request {
        kind: Some(9),
        channels: &["engineering"],
        ..Request::default()
    };
    assert!(mandate
        .authorizes(&cast.worker.public_key(), &permitted, &context)
        .is_ok());

    // The root allowed `general` and kind 40002; the planner kept both for
    // itself, so the worker never received them.
    let wrong_channel = Request {
        channels: &["general"],
        ..permitted.clone()
    };
    assert!(mandate
        .authorizes(&cast.worker.public_key(), &wrong_channel, &context)
        .is_err());

    let wrong_kind = Request {
        kind: Some(40002),
        ..permitted
    };
    assert!(mandate
        .authorizes(&cast.worker.public_key(), &wrong_kind, &context)
        .is_err());
}

// --- the attenuation guarantee -------------------------------------------

/// Independently intersect every link's caveats, dimension by dimension, and
/// compare against the leaf.
///
/// This is the load-bearing claim of the design — that explicit restatement
/// makes the leaf a complete statement of the chain's authority, so nothing has
/// to fold links at read time. If narrowing were ever accepted where it should
/// not be, the leaf and the intersection would diverge here.
fn assert_leaf_equals_intersection(chain: &MandateChain) {
    let links = chain.links();
    let leaf = links.last().expect("non-empty chain").caveats();

    let intersect_set = |get: &dyn Fn(&Caveats) -> Option<BTreeSet<String>>| {
        links.iter().fold(None, |accumulated, link| {
            match (accumulated, get(link.caveats())) {
                (None, current) => current,
                (Some(previous), None) => Some(previous),
                (Some(previous), Some(current)) => {
                    Some(previous.intersection(&current).cloned().collect())
                }
            }
        })
    };

    let channels = intersect_set(&|c: &Caveats| c.channels().cloned());
    assert_eq!(channels.as_ref(), leaf.channels(), "channel");

    let tools = intersect_set(&|c: &Caveats| c.tools().cloned());
    assert_eq!(tools.as_ref(), leaf.tools(), "tool");

    let peers = intersect_set(&|c: &Caveats| c.peers().cloned());
    assert_eq!(peers.as_ref(), leaf.peers(), "peer");

    let kinds = links.iter().fold(None, |accumulated, link| {
        match (accumulated, link.caveats().kinds().cloned()) {
            (None, current) => current,
            (Some(previous), None) => Some(previous),
            (Some(previous), Some(current)) => {
                Some(previous.intersection(&current).copied().collect())
            }
        }
    });
    assert_eq!(kinds.as_ref(), leaf.kinds(), "kind");

    let expires = links.iter().filter_map(|l| l.caveats().expires()).min();
    assert_eq!(expires, leaf.expires(), "expires");

    let not_before = links.iter().filter_map(|l| l.caveats().not_before()).max();
    assert_eq!(not_before, leaf.not_before(), "not_before");

    let uses = links.iter().filter_map(|l| l.caveats().uses()).min();
    assert_eq!(uses, leaf.uses(), "uses");
}

#[test]
fn the_leaf_is_the_intersection_of_the_whole_chain() {
    let cast = Cast::new();
    let fourth = Keys::generate();

    let chains = [
        MandateChain::root(&cast.owner, &cast.planner.public_key(), broad()).expect("root"),
        cast.two_hop(),
        cast.two_hop()
            .delegate(
                &cast.worker,
                &fourth.public_key(),
                caveats("channel=engineering&depth=0&expires=1200&kind=9&uses=3"),
            )
            .expect("third hop"),
        MandateChain::root(&cast.owner, &cast.planner.public_key(), caveats("uses=10"))
            .expect("root")
            .delegate(
                &cast.planner,
                &cast.worker.public_key(),
                caveats("channel=general&kind=1&uses=4"),
            )
            .expect("second hop"),
    ];

    for chain in &chains {
        chain
            .verify(&cast.anchor(), &RevocationSet::new())
            .expect("verify");
        assert_leaf_equals_intersection(chain);
    }
}

#[test]
fn delegating_wider_authority_is_refused_at_issue_time() {
    let cast = Cast::new();
    let chain = MandateChain::root(&cast.owner, &cast.planner.public_key(), broad()).expect("root");

    // A channel the root never granted.
    let error = chain
        .delegate(
            &cast.planner,
            &cast.worker.public_key(),
            caveats("channel=engineering,secrets&depth=1&expires=1500&kind=9"),
        )
        .expect_err("widening must be refused");
    assert!(
        matches!(error, MandateError::NotNarrowing { index: 1, .. }),
        "{error:?}"
    );

    // A later expiry than the root allowed.
    let error = chain
        .delegate(
            &cast.planner,
            &cast.worker.public_key(),
            caveats("channel=engineering&depth=1&expires=9999&kind=9"),
        )
        .expect_err("extending expiry must be refused");
    assert!(
        matches!(error, MandateError::NotNarrowing { index: 1, .. }),
        "{error:?}"
    );
}

#[test]
fn a_widened_chain_cannot_be_forged_after_the_fact() {
    // Refusing to *issue* a widened link is only half the guarantee. The other
    // half is that a subject cannot edit the caveats of a link it already
    // holds, because the caveats are inside the hashed, signed preimage.
    let cast = Cast::new();
    let chain = cast.two_hop();

    let mut envelope: Value =
        serde_json::from_str(&chain.to_json().expect("serialise")).expect("json");
    envelope["links"][1]["caveats"] =
        Value::String("channel=engineering,general&depth=1&expires=1500&kind=9,40002".into());

    let forged = MandateChain::from_json(&envelope.to_string()).expect("parse");
    let error = forged
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect_err("forged caveats must not verify");
    assert!(
        matches!(error, MandateError::BadSignature { index: 1 }),
        "{error:?}"
    );
}

#[test]
fn depth_bounds_sub_delegation() {
    let cast = Cast::new();
    let fourth = Keys::generate();

    // depth=1 at the worker permits exactly one more hop, which must be depth=0.
    let three_hop = cast
        .two_hop()
        .delegate(
            &cast.worker,
            &fourth.public_key(),
            caveats("channel=engineering&depth=0&expires=1500&kind=9"),
        )
        .expect("third hop");
    three_hop
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect("verify");

    // A fourth hop is refused: the third link has no depth left to give.
    let fifth = Keys::generate();
    let error = three_hop
        .delegate(
            &fourth,
            &fifth.public_key(),
            caveats("channel=engineering&depth=0&expires=1500&kind=9"),
        )
        .expect_err("depth exhausted");
    assert!(
        matches!(error, MandateError::DepthExhausted { index: 3 }),
        "{error:?}"
    );
}

#[test]
fn the_protocol_caps_chain_length_even_without_a_depth_caveat() {
    let cast = Cast::new();
    let mut chain = MandateChain::root(&cast.owner, &cast.planner.public_key(), Caveats::default())
        .expect("root");
    let mut issuer = cast.planner.clone();

    for _ in 1..MAX_CHAIN_LEN {
        let next = Keys::generate();
        chain = chain
            .delegate(&issuer, &next.public_key(), Caveats::default())
            .expect("hop");
        issuer = next;
    }
    assert_eq!(chain.links().len(), MAX_CHAIN_LEN);
    chain
        .verify(&cast.anchor(), &RevocationSet::new())
        .expect("verify");

    let error = chain
        .delegate(&issuer, &Keys::generate().public_key(), Caveats::default())
        .expect_err("chain is full");
    assert!(
        matches!(
            error,
            MandateError::ChainTooLong {
                len: 5,
                max: MAX_CHAIN_LEN
            }
        ),
        "{error:?}"
    );
}

// --- forgery and misuse --------------------------------------------------

#[test]
fn only_the_current_subject_may_sub_delegate() {
    let cast = Cast::new();
    let chain = MandateChain::root(&cast.owner, &cast.planner.public_key(), broad()).expect("root");

    // The worker holds no authority yet and cannot grant any.
    let error = chain
        .delegate(&cast.worker, &Keys::generate().public_key(), narrow())
        .expect_err("wrong issuer");
    assert!(
        matches!(error, MandateError::IssuerNotSubject { index: 1 }),
        "{error:?}"
    );
}

#[test]
fn truncating_a_chain_yields_authority_the_truncator_cannot_use() {
    // The sharpest attack on any delegation chain: a holder of
    // owner → planner → worker simply drops the last link and presents
    // owner → planner, which is a genuinely valid, genuinely *wider* mandate.
    //
    // Nothing stops the worker from presenting it — and nothing needs to,
    // because a mandate names its subject. The prefix empowers the planner, and
    // the worker cannot sign as the planner.
    let cast = Cast::new();
    let full = cast.two_hop();

    let truncated = MandateChain::from_links(vec![full.links()[0].clone()]);
    let wider = truncated
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect("a prefix is a valid chain");

    // It really is wider: the channel the planner withheld is back.
    let withheld = Request {
        kind: Some(9),
        channels: &["general"],
        ..Request::default()
    };
    let context = VerifyContext::at_untracked(1000);
    assert!(wider
        .authorizes(&cast.planner.public_key(), &withheld, &context)
        .is_ok());

    // And it is useless to the worker, who is not its subject.
    assert!(matches!(
        wider
            .authorizes(&cast.worker.public_key(), &withheld, &context)
            .expect_err("truncation must not empower the truncator"),
        buzz_mandate::DenyReason::WrongSubject { .. }
    ));
}

#[test]
fn a_link_cannot_be_spliced_into_another_chain() {
    let cast = Cast::new();

    // Two roots grant the same planner the same authority, so the planner's
    // links look interchangeable — but each commits to its own parent id.
    let other_owner = Keys::generate();
    let mine = cast.two_hop();
    let theirs = MandateChain::root(&other_owner, &cast.planner.public_key(), broad())
        .expect("root")
        .delegate(&cast.planner, &cast.worker.public_key(), narrow())
        .expect("delegate");

    let mut envelope: Value =
        serde_json::from_str(&mine.to_json().expect("serialise")).expect("json");
    let their_envelope: Value =
        serde_json::from_str(&theirs.to_json().expect("serialise")).expect("json");
    envelope["links"][1] = their_envelope["links"][1].clone();

    let spliced = MandateChain::from_json(&envelope.to_string()).expect("parse");
    let error = spliced
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect_err("splice must not verify");
    assert!(
        matches!(error, MandateError::ParentMismatch { index: 1 }),
        "{error:?}"
    );
}

#[test]
fn a_chain_may_not_loop_back_to_a_key_it_already_passed_through() {
    let cast = Cast::new();

    // owner → planner → worker → planner would burn a hop while returning
    // authority to a key that already held more of it.
    let looped = cast
        .two_hop()
        .delegate(
            &cast.worker,
            &cast.planner.public_key(),
            caveats("channel=engineering&depth=0&expires=1500&kind=9"),
        )
        .expect("issue-time checks do not catch cycles");

    let error = looped
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect_err("cycle must not verify");
    assert!(
        matches!(error, MandateError::RepeatedSubject { index: 2 }),
        "{error:?}"
    );
}

#[test]
fn a_chain_may_not_delegate_back_to_its_root_authority() {
    let cast = Cast::new();
    let looped = MandateChain::root(&cast.owner, &cast.planner.public_key(), broad())
        .expect("root")
        .delegate(&cast.planner, &cast.owner.public_key(), narrow())
        .expect("issue-time checks do not catch cycles");

    let error = looped
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect_err("cycle must not verify");
    assert!(
        matches!(error, MandateError::RepeatedSubject { index: 1 }),
        "{error:?}"
    );
}

#[test]
fn self_delegation_is_refused() {
    let cast = Cast::new();
    let error = MandateChain::root(&cast.owner, &cast.owner.public_key(), broad())
        .expect_err("self-delegation must be refused");
    assert!(
        matches!(error, MandateError::SelfDelegation { .. }),
        "{error:?}"
    );
}

#[test]
fn a_root_link_may_not_declare_a_parent() {
    let cast = Cast::new();
    let chain = cast.two_hop();

    let mut envelope: Value =
        serde_json::from_str(&chain.to_json().expect("serialise")).expect("json");
    envelope["links"][0]["parent"] = envelope["links"][1]["parent"].clone();

    let malformed = MandateChain::from_json(&envelope.to_string()).expect("parse");
    let error = malformed
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect_err("root with a parent must not verify");
    assert!(
        matches!(error, MandateError::BadLinkage { index: 0 }),
        "{error:?}"
    );
}

#[test]
fn malformed_wire_fields_are_rejected_before_verification() {
    let chain = Cast::new().two_hop();
    let json = chain.to_json().expect("serialise");

    let uppercase_issuer = {
        let mut envelope: Value = serde_json::from_str(&json).expect("json");
        let issuer = envelope["links"][0]["issuer"].as_str().expect("issuer");
        envelope["links"][0]["issuer"] = Value::String(issuer.to_uppercase());
        envelope.to_string()
    };
    assert!(matches!(
        MandateChain::from_json(&uppercase_issuer).expect_err("uppercase hex"),
        MandateError::InvalidField {
            index: 0,
            field: "issuer"
        }
    ));

    let bad_caveats = {
        let mut envelope: Value = serde_json::from_str(&json).expect("json");
        envelope["links"][0]["caveats"] = Value::String("kind=40002,9".into());
        envelope.to_string()
    };
    assert!(matches!(
        MandateChain::from_json(&bad_caveats).expect_err("non-canonical caveats"),
        MandateError::Caveat { index: 0, .. }
    ));

    assert!(matches!(
        MandateChain::from_json(r#"{"v":2,"links":[]}"#).expect_err("bad version"),
        MandateError::MalformedEnvelope(_)
    ));
    assert!(matches!(
        MandateChain::from_json(r#"{"v":1,"links":[]}"#).expect_err("empty chain"),
        MandateError::EmptyChain
    ));
}

// --- revocation ----------------------------------------------------------

#[test]
fn revoking_a_link_invalidates_everything_below_it() {
    let cast = Cast::new();
    let chain = cast.two_hop();

    let root_id = chain.links()[0].id();
    let revoked: RevocationSet = [(root_id, cast.owner.public_key())].into_iter().collect();

    let error = chain
        .verify(&cast.anchor(), &revoked)
        .expect_err("revoked root must not verify");
    assert!(
        matches!(error, MandateError::Revoked { index: 0 }),
        "{error:?}"
    );
}

#[test]
fn revoking_a_leaf_leaves_its_parent_usable() {
    let cast = Cast::new();
    let chain = cast.two_hop();

    let leaf_id = chain.links()[1].id();
    let revoked: RevocationSet = [(leaf_id, cast.planner.public_key())].into_iter().collect();
    assert!(chain.verify(&cast.anchor(), &revoked).is_err());

    // The planner's own grant is untouched by revoking what it handed onward.
    let parent_only = MandateChain::from_links(vec![chain.links()[0].clone()]);
    parent_only
        .verify(&cast.anchor(), &revoked)
        .expect("parent still valid");
}

// --- time ----------------------------------------------------------------

#[test]
fn expiry_is_decided_by_the_verifiers_clock_alone() {
    // NIP-OA's documented weakness is that its time clauses constrain a
    // timestamp the agent writes. Here the subject has no input to the clock:
    // the chain is structurally valid forever, and liveness is a separate
    // question asked of `VerifyContext`.
    let cast = Cast::new();
    let chain = cast.two_hop();
    let mandate = chain
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect("structure is time-independent");
    let subject = cast.worker.public_key();

    let request = Request {
        kind: Some(9),
        channels: &["engineering"],
        ..Request::default()
    };

    assert!(mandate
        .authorizes(&subject, &request, &VerifyContext::at_untracked(1499))
        .is_ok());
    assert!(mandate
        .authorizes(&subject, &request, &VerifyContext::at_untracked(1500))
        .is_err());
    assert!(mandate
        .authorizes(
            &subject,
            &request,
            &VerifyContext::at_untracked(u64::from(u32::MAX))
        )
        .is_err());
}

#[test]
fn link_ids_are_stable_and_distinct() {
    let cast = Cast::new();
    let chain = cast.two_hop();

    let first = chain.links()[0].id();
    assert_eq!(first, chain.links()[0].id(), "id is deterministic");
    assert_ne!(first, chain.links()[1].id(), "links have distinct ids");

    let hex = first.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    assert_eq!(
        buzz_mandate::LinkId::from_hex(&hex).expect("round trip"),
        first
    );
}

#[test]
fn the_preimage_is_domain_separated() {
    let chain = Cast::new().two_hop();
    let preimage = chain.links()[0].preimage();
    assert!(preimage.starts_with("nostr:mandate:v1\n"), "{preimage}");
    assert!(preimage.contains("\nroot\n"), "{preimage}");

    // A NIP-OA signature is over a different domain string, so neither
    // protocol's signatures can be replayed as the other's.
    assert!(!preimage.contains("nostr:agent-auth:"));
}

#[test]
fn subject_and_issuer_are_recoverable_for_audit() {
    let cast = Cast::new();
    let chain = cast.two_hop();
    let expected: Vec<(PublicKey, PublicKey)> = vec![
        (cast.owner.public_key(), cast.planner.public_key()),
        (cast.planner.public_key(), cast.worker.public_key()),
    ];
    let actual: Vec<(PublicKey, PublicKey)> = chain
        .links()
        .iter()
        .map(|l| (*l.issuer(), *l.subject()))
        .collect();
    assert_eq!(actual, expected);
}

// --- trust anchoring -----------------------------------------------------

#[test]
fn a_chain_rooted_at_an_untrusted_key_does_not_verify() {
    // The attack this closes: nothing stops an attacker generating a fresh
    // keypair and granting itself everything. Such a chain is internally
    // flawless — signatures, linkage, attenuation all check out — so a verifier
    // that only asks "is this chain well-formed?" hands over full authority.
    let cast = Cast::new();
    let impostor = Keys::generate();

    let self_issued = MandateChain::root(
        &impostor,
        &cast.worker.public_key(),
        Caveats::default(), // unconstrained: any kind, any channel, forever
    )
    .expect("root");

    // Structurally perfect...
    self_issued
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .expect("internally consistent");

    // ...and worth nothing against a real anchor.
    let error = self_issued
        .verify(&cast.anchor(), &RevocationSet::new())
        .expect_err("untrusted root must not verify");
    assert!(
        matches!(error, MandateError::UntrustedRoot { ref root } if *root == impostor.public_key().to_hex()),
        "{error:?}"
    );
}

#[test]
fn an_anchor_may_trust_several_roots() {
    let cast = Cast::new();
    let other = Keys::generate();
    let anchor = TrustAnchor::any_of([&cast.owner.public_key(), &other.public_key()]);

    cast.two_hop()
        .verify(&anchor, &RevocationSet::new())
        .expect("owner is one of the trusted roots");

    let stranger = Keys::generate();
    let theirs = MandateChain::root(&stranger, &cast.worker.public_key(), broad()).expect("root");
    assert!(theirs.verify(&anchor, &RevocationSet::new()).is_err());
}

// --- revocation authority ------------------------------------------------

#[test]
fn a_revocation_counts_only_from_the_issuer_or_the_root() {
    let cast = Cast::new();
    let chain = cast.two_hop();
    let leaf_id = chain.links()[1].id();

    // The planner issued the leaf, so it may revoke it.
    let by_issuer: RevocationSet = [(leaf_id, cast.planner.public_key())].into_iter().collect();
    assert!(chain.verify(&cast.anchor(), &by_issuer).is_err());

    // So may the root authority, over the whole chain beneath it.
    let by_root: RevocationSet = [(leaf_id, cast.owner.public_key())].into_iter().collect();
    assert!(chain.verify(&cast.anchor(), &by_root).is_err());

    // A stranger naming the same id is noise. Honouring it would let anyone
    // disable a mandate they were never party to.
    let stranger = Keys::generate();
    let by_stranger: RevocationSet = [(leaf_id, stranger.public_key())].into_iter().collect();
    chain
        .verify(&cast.anchor(), &by_stranger)
        .expect("a stranger cannot revoke");

    // Nor may the subject revoke the grant it holds — only the keys above it.
    let by_subject: RevocationSet = [(leaf_id, cast.worker.public_key())].into_iter().collect();
    chain
        .verify(&cast.anchor(), &by_subject)
        .expect("the subject is not an issuer of its own link");
}

// --- envelope strictness -------------------------------------------------

#[test]
fn unknown_envelope_fields_are_refused() {
    // A tolerated field is a place to hide bytes that change the grant event's
    // id while leaving the chain identical — which would hand a subject a fresh
    // `uses` budget for free if a verifier keyed its counter on the event id.
    let chain = Cast::new().two_hop();
    let mut envelope: Value =
        serde_json::from_str(&chain.to_json().expect("serialise")).expect("json");
    envelope["pad"] = Value::String("x".into());
    assert!(MandateChain::from_json(&envelope.to_string()).is_err());

    let mut padded_link: Value =
        serde_json::from_str(&chain.to_json().expect("serialise")).expect("json");
    padded_link["links"][0]["pad"] = Value::String("x".into());
    assert!(MandateChain::from_json(&padded_link.to_string()).is_err());
}

#[test]
fn the_leaf_id_is_the_stable_identity_of_a_mandate() {
    // `uses` accounting has to key on something the subject cannot change by
    // re-encoding. The leaf link id is a hash over canonical fields and commits
    // to the whole chain above it; a grant event id is neither.
    let cast = Cast::new();
    let chain = cast.two_hop();
    let json = chain.to_json().expect("serialise");

    let reparsed = MandateChain::from_json(&json).expect("parse");
    let a = chain
        .verify(&cast.anchor(), &RevocationSet::new())
        .expect("verify");
    let b = reparsed
        .verify(&cast.anchor(), &RevocationSet::new())
        .expect("verify");
    assert_eq!(a.leaf_id(), b.leaf_id());
}
