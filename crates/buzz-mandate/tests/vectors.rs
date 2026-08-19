//! Run the Rust implementation against the shared cross-implementation
//! vectors in `tests/vectors.json`.
//!
//! The file is the contract any second implementation must satisfy — it fixes
//! canonical encoding, rejection, narrowing, authorization, and link ids, which
//! are the parts two implementations are most likely to disagree about without
//! noticing. Regenerate with
//! `cargo run -p buzz-mandate --example mandate-vectors`.

use buzz_mandate::{
    Caveats, DenyReason, MandateChain, Request, RevocationSet, TrustAnchor, VerifyContext,
};
use nostr::PublicKey;
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("vectors.json");
    serde_json::from_str(raw).expect("vectors.json is valid JSON")
}

fn array<'a>(vectors: &'a Value, key: &str) -> &'a Vec<Value> {
    vectors[key]
        .as_array()
        .unwrap_or_else(|| panic!("vectors.json is missing array {key:?}"))
}

/// Pull a JSON array of strings, defaulting to empty when the key is absent.
fn string_list(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn borrow(items: &[String]) -> Vec<&str> {
    items.iter().map(String::as_str).collect()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("expected string field {key:?} in {value}"))
}

#[test]
fn every_signed_chain_vector_verifies_to_its_recorded_state() {
    let vectors = vectors();

    for chain_vector in array(&vectors, "chains") {
        let name = text(chain_vector, "name");
        let envelope = chain_vector["envelope"].to_string();

        let chain = MandateChain::from_json(&envelope)
            .unwrap_or_else(|e| panic!("{name}: envelope must parse: {e}"));
        let mandate = chain
            .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
            .unwrap_or_else(|e| panic!("{name}: chain must verify: {e}"));

        assert_eq!(
            mandate.subject().to_hex(),
            text(chain_vector, "subject"),
            "{name}: subject"
        );
        assert_eq!(
            mandate.root_authority().to_hex(),
            text(chain_vector, "root_authority"),
            "{name}: root authority"
        );
        assert_eq!(
            mandate.effective_caveats().to_canonical_string(),
            text(chain_vector, "effective_caveats"),
            "{name}: effective caveats"
        );
        assert_eq!(
            mandate.hops(),
            chain_vector["hops"].as_u64().expect("hops") as usize,
            "{name}: hops"
        );

        // Link ids and preimages are the parts a second implementation is most
        // likely to get subtly wrong — byte for byte, or not at all.
        let expected_ids = chain_vector["link_ids"].as_array().expect("link_ids");
        let expected_preimages = chain_vector["preimages"].as_array().expect("preimages");
        assert_eq!(
            chain.links().len(),
            expected_ids.len(),
            "{name}: link count"
        );

        for (index, link) in chain.links().iter().enumerate() {
            assert_eq!(
                link.id().to_hex(),
                expected_ids[index].as_str().expect("link id"),
                "{name}: link {index} id"
            );
            assert_eq!(
                link.preimage(),
                expected_preimages[index].as_str().expect("preimage"),
                "{name}: link {index} preimage"
            );
        }
    }
}

#[test]
fn canonical_caveat_vectors_parse_and_round_trip() {
    for case in array(&vectors(), "canonical_caveats") {
        let input = case.as_str().expect("canonical case is a string");
        let parsed = Caveats::parse(input).unwrap_or_else(|e| panic!("{input:?} must parse: {e}"));
        assert_eq!(
            parsed.to_canonical_string(),
            input,
            "{input:?} must round-trip"
        );
    }
}

#[test]
fn invalid_caveat_vectors_are_rejected() {
    for case in array(&vectors(), "invalid_caveats") {
        let input = text(case, "input");
        let reason = text(case, "reason");
        assert!(
            Caveats::parse(input).is_err(),
            "{input:?} must be rejected ({reason})"
        );
    }
}

#[test]
fn narrowing_vectors_agree_with_the_implementation() {
    for case in array(&vectors(), "narrowing") {
        let parent_text = text(case, "parent");
        let child_text = text(case, "child");
        let expected = case["narrows"].as_bool().expect("narrows is a bool");

        let parent = Caveats::parse(parent_text).expect("parent parses");
        let child = Caveats::parse(child_text).expect("child parses");

        assert_eq!(
            child.narrows(&parent).is_ok(),
            expected,
            "{child_text:?} narrows {parent_text:?} should be {expected}"
        );
    }
}

#[test]
fn authorization_vectors_agree_with_the_implementation() {
    for case in array(&vectors(), "authorization") {
        let caveat_text = text(case, "caveats");
        let caveats = Caveats::parse(caveat_text).expect("caveats parse");

        let context = VerifyContext::new(
            case["now"].as_u64().expect("now"),
            case["uses_consumed"].as_u64().expect("uses_consumed") as u32,
        );

        let request_json = &case["request"];
        let channels = string_list(request_json, "channels");
        let peers = string_list(request_json, "peers");
        let tools = string_list(request_json, "tools");
        let request = Request {
            kind: request_json["kind"].as_u64().map(|k| k as u32),
            channels: &borrow(&channels),
            peers: &borrow(&peers),
            tools: &borrow(&tools),
        };

        let outcome = caveats.authorizes(&request, &context);
        let expected = case["allowed"].as_bool().expect("allowed is a bool");
        assert_eq!(
            outcome.is_ok(),
            expected,
            "{caveat_text:?} vs {request_json} at {} should be allowed={expected}, got {outcome:?}",
            context.now
        );

        if let (Err(reason), Some(expected_reason)) = (&outcome, case["reason"].as_str()) {
            let actual = match reason {
                DenyReason::WrongSubject { .. } => "wrong_subject",
                DenyReason::NotYetValid { .. } => "not_yet_valid",
                DenyReason::Expired { .. } => "expired",
                DenyReason::UnstatedDimension { .. } => "unstated_dimension",
                DenyReason::OutOfScope { .. } => "out_of_scope",
                DenyReason::BudgetExhausted { .. } => "budget_exhausted",
            };
            assert_eq!(actual, expected_reason, "{caveat_text:?}: deny reason");
        }
    }
}

#[test]
fn every_invalid_chain_vector_is_rejected() {
    // The spec lists these in prose. Keeping them machine-readable is what
    // stops a second implementation from passing the caveat vectors while
    // happily accepting spliced, over-long, or edited chains.
    for case in array(&vectors(), "invalid_chains") {
        let name = text(case, "name");
        let reason = text(case, "reason");
        let envelope = case["envelope"].to_string();

        let outcome = MandateChain::from_json(&envelope).and_then(|chain| {
            chain
                .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
                .map(|_| ())
        });

        assert!(outcome.is_err(), "{name} must be rejected ({reason})");
    }
}

#[test]
fn actor_binding_vectors_agree_with_the_implementation() {
    for case in array(&vectors(), "actor_binding") {
        let name = text(case, "name");
        let chain = MandateChain::from_json(&case["envelope"].to_string())
            .unwrap_or_else(|e| panic!("{name}: envelope must parse: {e}"));
        let mandate = chain
            .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
            .unwrap_or_else(|e| panic!("{name}: chain must verify: {e}"));

        let actor = PublicKey::from_hex(text(case, "actor"))
            .unwrap_or_else(|e| panic!("{name}: actor must parse: {e}"));
        let context = VerifyContext::at_untracked(case["now"].as_u64().expect("now"));

        let request_json = &case["request"];
        let channels = string_list(request_json, "channels");
        let peers = string_list(request_json, "peers");
        let tools = string_list(request_json, "tools");
        let request = Request {
            kind: request_json["kind"].as_u64().map(|k| k as u32),
            channels: &borrow(&channels),
            peers: &borrow(&peers),
            tools: &borrow(&tools),
        };

        let outcome = mandate.authorizes(&actor, &request, &context);
        let expected = case["allowed"].as_bool().expect("allowed is a bool");
        assert_eq!(
            outcome.is_ok(),
            expected,
            "{name}: expected allowed={expected}, got {outcome:?}"
        );

        if let (Err(reason), Some(expected_reason)) = (&outcome, case["reason"].as_str()) {
            let actual = match reason {
                DenyReason::WrongSubject { .. } => "wrong_subject",
                DenyReason::NotYetValid { .. } => "not_yet_valid",
                DenyReason::Expired { .. } => "expired",
                DenyReason::UnstatedDimension { .. } => "unstated_dimension",
                DenyReason::OutOfScope { .. } => "out_of_scope",
                DenyReason::BudgetExhausted { .. } => "budget_exhausted",
            };
            assert_eq!(actual, expected_reason, "{name}: deny reason");
        }
    }
}

#[test]
fn trust_anchor_vectors_agree_with_the_implementation() {
    for case in array(&vectors(), "trust_anchor") {
        let name = text(case, "name");
        let chain = MandateChain::from_json(&case["envelope"].to_string())
            .unwrap_or_else(|e| panic!("{name}: envelope must parse: {e}"));

        let anchor = match case["trusted_roots"].as_array() {
            None => TrustAnchor::unchecked(),
            Some(roots) => {
                let keys: Vec<PublicKey> = roots
                    .iter()
                    .filter_map(|r| r.as_str())
                    .map(|r| PublicKey::from_hex(r).expect("root pubkey parses"))
                    .collect();
                TrustAnchor::any_of(keys.iter())
            }
        };

        let outcome = chain.verify(&anchor, &RevocationSet::new());
        let expected = case["valid"].as_bool().expect("valid is a bool");
        assert_eq!(
            outcome.is_ok(),
            expected,
            "{name}: expected valid={expected}, got {outcome:?}"
        );
    }
}
