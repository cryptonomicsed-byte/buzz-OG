//! Caveat parsing, canonicality, narrowing, and authorization.

use buzz_mandate::{CaveatError, Caveats, DenyReason, Request, VerifyContext};

const PEER_A: &str = "0000000000000000000000000000000000000000000000000000000000000aaa";
const PEER_B: &str = "0000000000000000000000000000000000000000000000000000000000000bbb";

fn parse(s: &str) -> Caveats {
    Caveats::parse(s).unwrap_or_else(|e| panic!("expected {s:?} to parse, got {e}"))
}

fn reject(s: &str) -> CaveatError {
    Caveats::parse(s).expect_err(&format!("expected {s:?} to be rejected"))
}

// --- canonical form ------------------------------------------------------

#[test]
fn empty_string_is_the_unconstrained_set() {
    let caveats = parse("");
    assert!(caveats.is_unconstrained());
    assert_eq!(caveats.to_canonical_string(), "");
}

#[test]
fn canonical_string_round_trips() {
    let canonical = format!(
        "channel=engineering,general&depth=2&expires=1800000000&kind=9,40002&not_before=1700000000&peer={PEER_A},{PEER_B}&tool=shell,str_replace&uses=5"
    );
    let caveats = parse(&canonical);
    assert_eq!(caveats.to_canonical_string(), canonical);
}

#[test]
fn builder_output_is_always_canonical() {
    let built = Caveats::builder()
        // Deliberately unsorted and duplicated input.
        .kinds([40002, 9, 9])
        .channels(["general", "engineering", "general"])
        .tools(["str_replace", "shell"])
        .build()
        .expect("valid caveats");

    let canonical = built.to_canonical_string();
    assert_eq!(
        canonical,
        "channel=engineering,general&kind=9,40002&tool=shell,str_replace"
    );
    assert_eq!(parse(&canonical), built);
}

#[test]
fn dimensions_must_be_ordered_and_unique() {
    assert!(matches!(
        reject("kind=9&channel=general"),
        CaveatError::UnorderedDimensions { .. }
    ));
    assert!(matches!(
        reject("kind=9&kind=10"),
        CaveatError::DuplicateDimension { .. }
    ));
}

#[test]
fn set_members_must_be_ordered_and_unique() {
    assert!(matches!(
        reject("kind=40002,9"),
        CaveatError::UnorderedMembers { .. }
    ));
    assert!(matches!(
        reject("kind=9,9"),
        CaveatError::UnorderedMembers { .. }
    ));
    assert!(matches!(
        reject("channel=general,engineering"),
        CaveatError::UnorderedMembers { .. }
    ));
}

#[test]
fn kind_members_order_numerically_not_bytewise() {
    // "40002" sorts before "9" bytewise; canonical order is numeric.
    let caveats = parse("kind=9,40002");
    let kinds: Vec<u32> = caveats
        .kinds()
        .expect("kinds present")
        .iter()
        .copied()
        .collect();
    assert_eq!(kinds, vec![9, 40002]);
}

#[test]
fn malformed_structure_is_rejected() {
    assert!(matches!(reject("&kind=9"), CaveatError::EmptyClause));
    assert!(matches!(reject("kind=9&"), CaveatError::EmptyClause));
    assert!(matches!(
        reject("kind=9&&tool=shell"),
        CaveatError::EmptyClause
    ));
    assert!(matches!(
        reject("kind"),
        CaveatError::MissingSeparator { .. }
    ));
    assert!(matches!(
        reject("realm=block"),
        CaveatError::UnknownDimension { .. }
    ));
}

#[test]
fn whitespace_and_non_ascii_are_rejected() {
    assert!(matches!(reject("kind=9 "), CaveatError::IllegalByte { .. }));
    assert!(matches!(
        reject("kind=9&tool=sh ell"),
        CaveatError::IllegalByte { .. }
    ));
    assert!(matches!(
        reject("tool=café"),
        CaveatError::IllegalByte { .. }
    ));
}

#[test]
fn scalars_must_be_canonical_decimals_in_range() {
    assert!(matches!(
        reject("expires=01700000000"),
        CaveatError::InvalidScalar { .. }
    ));
    assert!(matches!(
        reject("kind=09"),
        CaveatError::InvalidMember { .. }
    ));
    assert!(matches!(
        reject("kind=65536"),
        CaveatError::InvalidMember { .. }
    ));
    assert!(matches!(
        reject("depth=256"),
        CaveatError::InvalidScalar { .. }
    ));
    // A budget of zero grants nothing; issue no mandate instead of a dead one.
    assert!(matches!(
        reject("uses=0"),
        CaveatError::InvalidScalar { .. }
    ));
}

#[test]
fn empty_member_sets_are_rejected() {
    assert!(matches!(reject("kind="), CaveatError::InvalidMember { .. }));
    assert!(matches!(
        reject("channel="),
        CaveatError::InvalidMember { .. }
    ));
}

#[test]
fn peers_must_be_lowercase_hex_pubkeys() {
    assert!(Caveats::parse(&format!("peer={PEER_A}")).is_ok());
    assert!(matches!(
        reject(&format!("peer={}", PEER_A.to_uppercase())),
        CaveatError::InvalidMember { .. }
    ));
    assert!(matches!(
        reject("peer=deadbeef"),
        CaveatError::InvalidMember { .. }
    ));
}

#[test]
fn names_reject_clause_delimiters_and_overlong_members() {
    // `=` inside a member would let it forge a clause boundary.
    assert!(matches!(
        reject("tool=sh=ell"),
        CaveatError::InvalidMember { .. }
    ));
    let overlong = "a".repeat(65);
    assert!(matches!(
        reject(&format!("tool={overlong}")),
        CaveatError::InvalidMember { .. }
    ));
}

#[test]
fn an_empty_time_window_is_rejected() {
    assert!(matches!(
        reject("expires=100&not_before=100"),
        CaveatError::EmptyTimeWindow { .. }
    ));
    assert!(matches!(
        reject("expires=100&not_before=200"),
        CaveatError::EmptyTimeWindow { .. }
    ));
    assert!(Caveats::parse("expires=200&not_before=100").is_ok());
    assert!(matches!(
        Caveats::builder()
            .not_before(200)
            .expires(100)
            .build()
            .expect_err("empty window"),
        CaveatError::EmptyTimeWindow { .. }
    ));
}

// --- narrowing -----------------------------------------------------------

#[test]
fn a_subset_narrows_a_superset() {
    let parent = parse("kind=9,40002");
    assert!(parse("kind=9").narrows(&parent).is_ok());
    assert!(parse("kind=9,40002").narrows(&parent).is_ok());
}

#[test]
fn a_superset_does_not_narrow() {
    let parent = parse("kind=9");
    let error = parse("kind=9,40002")
        .narrows(&parent)
        .expect_err("widening must be rejected");
    assert!(error.contains("kind"), "{error}");
}

#[test]
fn dropping_a_constraint_does_not_narrow() {
    // The core of explicit restatement: silence is not inheritance.
    let parent = parse("channel=engineering");
    let error = parse("")
        .narrows(&parent)
        .expect_err("dropping a constraint must be rejected");
    assert!(error.contains("channel"), "{error}");
}

#[test]
fn adding_a_constraint_narrows() {
    let parent = parse("kind=9");
    assert!(parse("channel=engineering&kind=9").narrows(&parent).is_ok());
}

#[test]
fn an_unconstrained_parent_admits_anything() {
    let parent = parse("");
    assert!(parse("channel=engineering&kind=9&uses=1")
        .narrows(&parent)
        .is_ok());
}

#[test]
fn time_bounds_narrow_from_both_ends() {
    let parent = parse("expires=2000&not_before=1000");

    assert!(parse("expires=1500&not_before=1200")
        .narrows(&parent)
        .is_ok());
    assert!(parse("expires=2000&not_before=1000")
        .narrows(&parent)
        .is_ok());
    // Later expiry widens.
    assert!(parse("expires=2001&not_before=1000")
        .narrows(&parent)
        .is_err());
    // Earlier start widens.
    assert!(parse("expires=2000&not_before=999")
        .narrows(&parent)
        .is_err());
}

#[test]
fn budgets_only_shrink() {
    let parent = parse("uses=5");
    assert!(parse("uses=5").narrows(&parent).is_ok());
    assert!(parse("uses=1").narrows(&parent).is_ok());
    assert!(parse("uses=6").narrows(&parent).is_err());
}

#[test]
fn depth_must_strictly_decrease() {
    let parent = parse("depth=2");
    assert!(parse("depth=1").narrows(&parent).is_ok());
    assert!(parse("depth=0").narrows(&parent).is_ok());
    // Equal depth would let a chain delegate forever.
    assert!(parse("depth=2").narrows(&parent).is_err());
    assert!(parse("depth=3").narrows(&parent).is_err());
    // A parent at zero can hand out nothing at all.
    assert!(parse("depth=0").narrows(&parse("depth=0")).is_err());
}

// --- authorization -------------------------------------------------------

fn request() -> Request<'static> {
    Request {
        kind: Some(9),
        channel: Some("engineering"),
        peer: None,
        tool: None,
    }
}

#[test]
fn an_in_scope_request_is_authorized() {
    let caveats = parse("channel=engineering&kind=9");
    assert!(caveats
        .authorizes(&request(), &VerifyContext::at(1000))
        .is_ok());
}

#[test]
fn an_out_of_scope_value_is_denied() {
    let caveats = parse("channel=general&kind=9");
    assert_eq!(
        caveats.authorizes(&request(), &VerifyContext::at(1000)),
        Err(DenyReason::OutOfScope {
            dimension: "channel",
            value: "engineering".to_owned(),
        })
    );
}

#[test]
fn an_unstated_dimension_fails_closed() {
    // The mandate constrains `tool`; the request says nothing about tools.
    // Silence must not read as "no tool involved, therefore fine".
    let caveats = parse("tool=shell");
    assert_eq!(
        caveats.authorizes(&request(), &VerifyContext::at(1000)),
        Err(DenyReason::UnstatedDimension { dimension: "tool" })
    );
}

#[test]
fn time_bounds_are_inclusive_below_and_exclusive_above() {
    let caveats = parse("expires=2000&not_before=1000");

    assert_eq!(
        caveats.authorizes(&request(), &VerifyContext::at(999)),
        Err(DenyReason::NotYetValid {
            now: 999,
            not_before: 1000
        })
    );
    assert!(caveats
        .authorizes(&request(), &VerifyContext::at(1000))
        .is_ok());
    assert!(caveats
        .authorizes(&request(), &VerifyContext::at(1999))
        .is_ok());
    assert_eq!(
        caveats.authorizes(&request(), &VerifyContext::at(2000)),
        Err(DenyReason::Expired {
            now: 2000,
            expires: 2000
        })
    );
}

#[test]
fn a_spent_budget_denies() {
    let caveats = parse("uses=3");
    let spent = VerifyContext {
        now: 1000,
        uses_consumed: 3,
    };
    assert_eq!(
        caveats.authorizes(&request(), &spent),
        Err(DenyReason::BudgetExhausted {
            consumed: 3,
            budget: 3
        })
    );

    let partly_spent = VerifyContext {
        now: 1000,
        uses_consumed: 2,
    };
    assert!(caveats.authorizes(&request(), &partly_spent).is_ok());
}

#[test]
fn the_unconstrained_set_authorizes_everything() {
    let caveats = parse("");
    assert!(caveats
        .authorizes(&Request::default(), &VerifyContext::at(0))
        .is_ok());
}
