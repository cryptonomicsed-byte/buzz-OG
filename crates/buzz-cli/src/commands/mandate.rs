//! `buzz mandate` subcommands — NIP-CM capability mandates.
//!
//! Lets an agent issue a bounded capability to another agent, narrow one it
//! already holds and pass it on, check what a chain permits, and publish or
//! revoke a grant on the relay. See `docs/nips/NIP-CM.md`.
//!
//! `issue`, `delegate`, and `verify` are pure local crypto and never touch the
//! network. They still run through the normal CLI path, so `BUZZ_PRIVATE_KEY`
//! is required as it is everywhere else — the keypair is the identity. Code
//! that needs to verify without holding an identity should use the
//! `buzz-mandate` crate directly.

use buzz_mandate::{
    Caveats, LinkId, MandateChain, Request, RevocationSet, TrustAnchor, VerifyContext,
    KIND_MANDATE_GRANT, KIND_MANDATE_REVOKE,
};
use nostr::{EventBuilder, Kind, PublicKey, Tag};
use serde_json::json;

use crate::client::BuzzClient;
use crate::commands::parse_write_response;
use crate::error::CliError;
use crate::MandateCmd;

/// Tag naming the revoked link on a kind:50002 event.
const LINK_TAG: &str = "link";

pub async fn dispatch(cmd: MandateCmd, client: &BuzzClient) -> Result<(), CliError> {
    match cmd {
        MandateCmd::Issue { subject, caveats } => cmd_issue(client, &subject, &caveats),
        MandateCmd::Delegate {
            chain,
            subject,
            caveats,
        } => cmd_delegate(client, &chain, &subject, &caveats),
        MandateCmd::Verify {
            chain,
            trusted_root,
            actor,
            now,
            kind,
            channel,
            peer,
            tool,
            uses_consumed,
            revoked,
        } => cmd_verify(VerifyArgs {
            chain: &chain,
            trusted_roots: &trusted_root,
            actor: actor.as_deref(),
            now,
            kind,
            channels: &channel,
            peers: &peer,
            tools: &tool,
            uses_consumed,
            revoked: &revoked,
        }),
        MandateCmd::Publish { chain } => cmd_publish(client, &chain).await,
        MandateCmd::Revoke { link } => cmd_revoke(client, &link).await,
    }
}

/// Read a chain argument: either inline JSON or `@path` to read from a file.
fn read_chain(input: &str) -> Result<MandateChain, CliError> {
    let json = match input.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| CliError::Usage(format!("cannot read chain from {path:?}: {e}")))?,
        None => input.to_owned(),
    };

    MandateChain::from_json(json.trim())
        .map_err(|e| CliError::Usage(format!("invalid mandate chain: {e}")))
}

fn parse_caveats(input: &str) -> Result<Caveats, CliError> {
    Caveats::parse(input).map_err(|e| CliError::Usage(format!("invalid caveats: {e}")))
}

fn parse_pubkey(label: &str, input: &str) -> Result<PublicKey, CliError> {
    PublicKey::from_hex(input).map_err(|e| CliError::Usage(format!("invalid {label}: {e}")))
}

/// Parse `--trusted-root` values into an anchor.
///
/// No roots means [`TrustAnchor::unchecked`], which checks a chain's internals
/// and nothing else. That is honest for inspection, and wrong for a permission
/// decision: anyone can mint a keypair and grant themselves everything. The
/// verdict says which mode ran so a caller cannot mistake one for the other.
fn anchor_from(roots: &[String]) -> Result<TrustAnchor, CliError> {
    if roots.is_empty() {
        return Ok(TrustAnchor::unchecked());
    }
    let keys = roots
        .iter()
        .map(|root| parse_pubkey("trusted root", root))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TrustAnchor::any_of(keys.iter()))
}

/// Summarise a chain the same way for every command that emits one.
///
/// Issuing and delegating check structure only — the caller is the issuer, so
/// the root is their own concern, not a claim to be audited here.
fn describe(chain: &MandateChain) -> Result<serde_json::Value, CliError> {
    let mandate = chain
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .map_err(|e| CliError::Other(format!("chain did not verify: {e}")))?;

    Ok(json!({
        "chain": serde_json::from_str::<serde_json::Value>(&chain.to_json()?)
            .map_err(|e| CliError::Other(format!("chain is not JSON: {e}")))?,
        "leaf_id": mandate.leaf_id().to_hex(),
        "root_authority": mandate.root_authority().to_hex(),
        "subject": mandate.subject().to_hex(),
        "effective_caveats": mandate.effective_caveats().to_canonical_string(),
        "hops": mandate.hops(),
    }))
}

fn print_json(value: &serde_json::Value) -> Result<(), CliError> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|e| CliError::Other(format!("cannot render output: {e}")))?;
    println!("{rendered}");
    Ok(())
}

/// `buzz mandate issue --subject <hex> --caveats <string>`
///
/// Signs a root grant with the CLI's own key.
fn cmd_issue(client: &BuzzClient, subject: &str, caveats: &str) -> Result<(), CliError> {
    let subject = parse_pubkey("subject", subject)?;
    let caveats = parse_caveats(caveats)?;

    let chain = MandateChain::root(client.keys(), &subject, caveats)
        .map_err(|e| CliError::Usage(format!("cannot issue mandate: {e}")))?;

    print_json(&describe(&chain)?)
}

/// `buzz mandate delegate --chain <json|@file> --subject <hex> --caveats <string>`
///
/// Extends a chain the CLI's key is the current subject of. The new caveats
/// must narrow the current leaf's, or the command fails rather than producing
/// a chain that no verifier would accept.
fn cmd_delegate(
    client: &BuzzClient,
    chain: &str,
    subject: &str,
    caveats: &str,
) -> Result<(), CliError> {
    let chain = read_chain(chain)?;
    let subject = parse_pubkey("subject", subject)?;
    let caveats = parse_caveats(caveats)?;

    let extended = chain
        .delegate(client.keys(), &subject, caveats)
        .map_err(|e| CliError::Usage(format!("cannot delegate: {e}")))?;

    print_json(&describe(&extended)?)
}

/// Arguments for `buzz mandate verify`, grouped so the function stays readable.
struct VerifyArgs<'a> {
    chain: &'a str,
    trusted_roots: &'a [String],
    actor: Option<&'a str>,
    now: Option<u64>,
    kind: Option<u32>,
    channels: &'a [String],
    peers: &'a [String],
    tools: &'a [String],
    uses_consumed: u32,
    revoked: &'a [String],
}

/// `buzz mandate verify --chain <json|@file> [request flags]`
///
/// Prints a verdict object and exits 0 only when the chain verifies and, if a
/// request was described, the request is authorized. Anything else exits
/// non-zero with the reason in both the JSON and the error.
fn cmd_verify(args: VerifyArgs<'_>) -> Result<(), CliError> {
    let chain = read_chain(args.chain)?;
    let anchor = anchor_from(args.trusted_roots)?;

    let mut revocations = RevocationSet::new();
    for entry in args.revoked {
        // `<link-id>:<revoker-pubkey>` — a revocation counts only from the
        // link's issuer or the chain's root, so the revoker is not optional.
        let (id, revoker) = entry.split_once(':').ok_or_else(|| {
            CliError::Usage(format!(
                "--revoked expects <link-id>:<revoker-pubkey>, got {entry:?}"
            ))
        })?;
        let id = LinkId::from_hex(id)
            .map_err(|e| CliError::Usage(format!("invalid revoked link id {id:?}: {e}")))?;
        revocations.insert(id, &parse_pubkey("revoker", revoker)?);
    }

    let mandate = match chain.verify(&anchor, &revocations) {
        Ok(mandate) => mandate,
        Err(error) => {
            print_json(&json!({
                "valid": false,
                "root_trust": if anchor.is_unchecked() { "unchecked" } else { "anchored" },
                "reason": error.to_string(),
            }))?;
            return Err(CliError::Usage(format!("mandate did not verify: {error}")));
        }
    };

    let mut verdict = json!({
        "valid": true,
        "root_trust": if anchor.is_unchecked() { "unchecked" } else { "anchored" },
        "leaf_id": mandate.leaf_id().to_hex(),
        "root_authority": mandate.root_authority().to_hex(),
        "subject": mandate.subject().to_hex(),
        "effective_caveats": mandate.effective_caveats().to_canonical_string(),
        "hops": mandate.hops(),
    });

    if anchor.is_unchecked() {
        verdict["warning"] = json!(
            "no --trusted-root given: the chain's internals check out, but its root \
             is whoever signed it. Do not grant on this verdict."
        );
    }

    // Authorization is only evaluated when the caller says who is acting.
    // Without an actor there is nothing to bind the mandate to, and reporting
    // "authorized" on that basis is exactly the truncation mistake NIP-CM
    // warns about.
    let Some(actor) = args.actor else {
        verdict["authorized"] = json!(null);
        verdict["note"] =
            json!("pass --actor to evaluate a request; a chain alone authorizes nobody");
        return print_json(&verdict);
    };

    let actor = parse_pubkey("actor", actor)?;
    let context = VerifyContext::new(args.now.unwrap_or_else(now_secs), args.uses_consumed);
    let channels = borrow(args.channels);
    let peers = borrow(args.peers);
    let tools = borrow(args.tools);
    let request = Request {
        kind: args.kind,
        channels: &channels,
        peers: &peers,
        tools: &tools,
    };

    match mandate.authorizes(&actor, &request, &context) {
        Ok(()) => {
            verdict["authorized"] = json!(true);
            verdict["now"] = json!(context.now);
            print_json(&verdict)
        }
        Err(reason) => {
            verdict["authorized"] = json!(false);
            verdict["now"] = json!(context.now);
            verdict["deny_reason"] = json!(reason.to_string());
            print_json(&verdict)?;
            Err(CliError::Usage(format!("request denied: {reason}")))
        }
    }
}

fn borrow(items: &[String]) -> Vec<&str> {
    items.iter().map(String::as_str).collect()
}

/// `buzz mandate publish --chain <json|@file>`
///
/// Publishes the chain as a kind:50001 event, p-tagged to the subject so the
/// holder can find mandates issued to it.
async fn cmd_publish(client: &BuzzClient, chain: &str) -> Result<(), CliError> {
    let chain = read_chain(chain)?;
    let mandate = chain
        .verify(&TrustAnchor::unchecked(), &RevocationSet::new())
        .map_err(|e| CliError::Usage(format!("refusing to publish an invalid chain: {e}")))?;

    let subject = *mandate.subject();
    let builder = EventBuilder::new(Kind::Custom(KIND_MANDATE_GRANT as u16), chain.to_json()?)
        .tags(vec![Tag::public_key(subject)]);

    let event = client.sign_event(builder)?;
    let raw = client.submit_event(event).await?;
    println!(
        "{}",
        parse_write_response(&raw, "mandate already published")?
    );
    Ok(())
}

/// `buzz mandate revoke --link <link-id>`
///
/// Publishes a kind:50002 event naming one link id. Every chain through that
/// link becomes unverifiable, including ones the revoker has never seen.
async fn cmd_revoke(client: &BuzzClient, link: &str) -> Result<(), CliError> {
    let id = LinkId::from_hex(link)
        .map_err(|e| CliError::Usage(format!("invalid link id {link:?}: {e}")))?;

    let builder =
        EventBuilder::new(Kind::Custom(KIND_MANDATE_REVOKE as u16), "").tags(vec![Tag::parse(
            vec![LINK_TAG.to_string(), id.to_hex()],
        )
        .map_err(|e| CliError::Other(format!("cannot build link tag: {e}")))?]);

    let event = client.sign_event(builder)?;
    let raw = client.submit_event(event).await?;
    println!("{}", parse_write_response(&raw, "link already revoked")?);
    Ok(())
}

/// Wall-clock seconds, used only as the default for `--now`.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl From<buzz_mandate::MandateError> for CliError {
    fn from(error: buzz_mandate::MandateError) -> Self {
        Self::Other(error.to_string())
    }
}
