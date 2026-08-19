NIP-CM
======

Capability Mandates
-------------------

`draft` `optional`

This NIP defines a chain of signed delegation links by which a root authority grants an agent key a bounded capability, and by which that agent may sub-delegate a strictly smaller capability onward.

## Motivation

[NIP-OA](NIP-OA.md) defines a single-hop attestation by which an owner authorizes an agent key to publish events under its own authorship.
That credential answers whether a human authorized an agent to speak.
It is one hop, its condition language has three clauses, and it has no revocation.

Agents delegate to each other.
A planner agent that fans work out to several workers must hand each worker less authority than it holds, must prove the reduction to a verifier that trusts neither party, and must have the grant lapse on a schedule rather than on a promise.
NIP-OA cannot express this: it defines no second hop, no scope beyond event kind, no invocation budget, and no revocation.
NIP-OA further documents that its `created_at` clauses constrain a field the agent itself writes, so an agent that backdates an event satisfies an expired window.

This NIP defines the multi-hop case and nothing else.
A mandate does not replace a NIP-OA attestation.
An agent MAY hold both: the attestation establishes ownership provenance, and the mandate establishes present authority.

## Non-Goals

This NIP does not define impersonation, key derivation, or relay-side author rewriting.
This NIP does not define how a verifier discovers revocations.
This NIP does not define delegation breadth limits; see Security Properties.

## Terminology

A **link** is one hop of delegation.
A **chain** is an ordered sequence of links, root first.
The **issuer** of a link is the key that signs it.
The **subject** of a link is the key it grants authority to.
The **root authority** is the issuer of the first link.
The **leaf** is the last link, and its subject is the key the chain empowers.
A **caveat set** is the constraint the link places on its subject.

## Caveats

A caveat set constrains eight independent dimensions.
Each dimension is either present or absent.
An absent dimension is unconstrained.
A caveat set in which every dimension is absent is the **unconstrained set** and permits any action at any time.

| Dimension | Value | Meaning |
|---|---|---|
| `channel` | set of names | Permitted NIP-29 `h` tag values |
| `depth` | integer `0`–`255` | Remaining sub-delegation hops |
| `expires` | integer `0`–`4294967295` | Exclusive upper time bound |
| `kind` | set of integers `0`–`65535` | Permitted event kinds |
| `not_before` | integer `0`–`4294967295` | Inclusive lower time bound |
| `peer` | set of pubkeys | Permitted counterparty keys |
| `tool` | set of names | Permitted tool or method names |
| `uses` | integer `1`–`4294967295` | Invocation budget |

### Encoding

A caveat set MUST have exactly one encoding.
The encoding is the empty string, or one or more clauses joined by `&`.
Each clause is `<dimension>=<value>`.

Present dimensions MUST appear in ascending lexicographic order of dimension name, which is `channel`, `depth`, `expires`, `kind`, `not_before`, `peer`, `tool`, `uses`.
A dimension MUST NOT appear more than once.
Whitespace MUST NOT appear anywhere.
Every byte MUST be in the range `0x21`–`0x7E`.

Set-valued dimensions encode their members joined by `,`.
A member set MUST NOT be empty.
Members MUST be unique and in ascending order — numerically for `kind`, and by byte value for `channel`, `peer`, and `tool`.
Members of `channel` and `tool` MUST be 1 to 64 bytes of `[A-Za-z0-9._:/-]`.
Members of `peer` MUST be 64 lowercase hexadecimal characters.

Integers MUST be canonical base-10 with no leading zeroes except `0` itself.
A `uses` value of `0` MUST be rejected; a budget of zero grants nothing and MUST be expressed by not issuing a mandate.

If both `not_before` and `expires` are present, `not_before` MUST be strictly less than `expires`.

An encoded caveat set MUST NOT exceed 2048 bytes, and a single set-valued dimension MUST NOT have more than 64 members.
Every verifier hashes and set-compares this string once per link per event, so the bound belongs here rather than in whatever body-size limit a particular relay happens to run.

Verifiers MUST reject a caveat string that is malformed **or** merely non-canonical.
Verifiers MUST NOT reorder, deduplicate, or normalise a caveat string before use.
This is required because a link's identifier is a hash over its encoded caveats: two encodings of one set would give a mandate two identifiers, and revoking one would not revoke the other.

## Narrowing

For caveat sets `child` and `parent`, `child` **narrows** `parent` if and only if, for every dimension present in `parent`:

- the dimension is also present in `child`; and
- for `channel`, `kind`, `peer`, and `tool`: the child's member set is a subset of the parent's; and
- for `expires` and `uses`: the child's value is less than or equal to the parent's; and
- for `not_before`: the child's value is greater than or equal to the parent's; and
- for `depth`: the parent's value is greater than `0` and the child's value is strictly less than the parent's.

A dimension absent from `parent` places no requirement on `child`.
A `child` MAY constrain dimensions that `parent` leaves absent.

A `child` that omits a dimension its `parent` constrains does **not** narrow it.
Constraints are restated explicitly at every hop rather than inherited silently.
The consequence, which verifiers and clients MAY rely on, is that the leaf link's caveat set is equal to the intersection of every link's caveat set in the chain.
A reader therefore needs only the leaf to know what a chain permits.

`depth` decrements strictly so that chain length is bounded by the root's own declaration, independently of the protocol maximum below.

## Links

A link has five fields.

| Field | Value |
|---|---|
| `parent` | The parent link's identifier as 64 lowercase hex characters, or `null` on the root link |
| `issuer` | 64 lowercase hex characters, a BIP-340 x-only public key |
| `subject` | 64 lowercase hex characters, a BIP-340 x-only public key |
| `caveats` | A canonical caveat string, possibly empty |
| `sig` | 128 lowercase hex characters, a BIP-340 Schnorr signature |

### Identifier and signature

The link preimage is the UTF-8 byte sequence:

```text
"nostr:mandate:v1" || LF || <parent> || LF || <issuer> || LF || <subject> || LF || <caveats>
```

where `LF` is `0x0A`, and `<parent>` is the literal string `root` on the root link and the parent's identifier otherwise.
The domain separator string is exactly `nostr:mandate:v1`.
It differs from NIP-OA's `nostr:agent-auth:` so that a signature produced for one NIP can never verify under the other.

The link identifier is `SHA256(preimage)`.
The issuer MUST produce `sig` as a BIP-340 Schnorr signature over the 32-byte link identifier, used directly as the signed message.

Because the preimage contains the parent identifier, a link identifier is specific to its position in one chain.
A link cannot be moved between chains without changing its identifier, which invalidates its own signature and every link below it.

## Chain Verification

A verifier is given a chain, a set of trusted root keys, and a set of revocations.
Verification MUST NOT depend on the current time; see Time.

A chain is valid if and only if all of the following hold.

0. The root link's `issuer` is a key the verifier independently trusts as a source of authority for the resource in question.
1. The chain has at least one link and at most **four**.
2. The root link's `parent` is `null`, and every other link's `parent` equals the previous link's identifier.
3. Every non-root link's `issuer` equals the previous link's `subject`.
4. On every link, `issuer` and `subject` differ.
5. No key appears as the `subject` of more than one link, and no link's `subject` equals the root link's `issuer`.
6. Every link's `sig` verifies against its `issuer` over its identifier.
7. No link's identifier is revoked by a key entitled to revoke it: that is, by the link's own `issuer` or by the root link's `issuer`.
8. For every non-root link, the previous link's `depth` caveat, if present, is greater than `0`, and the link's caveats narrow the previous link's caveats.

Rule 0 is not optional and not a formality.
A chain proves that authority flowed correctly *from its own root*; it says nothing about whether that root was entitled to grant anything.
Anyone can generate a keypair, self-issue an unconstrained mandate to their own agent, and produce a chain that satisfies rules 1 through 8 perfectly.
A verifier that omits rule 0 therefore grants full authority to any key that asks.
Implementations SHOULD make the trusted set a required argument rather than an optional one, so that declining to check it is visible in the calling code.

A verifier MAY admit every root when it is storing, relaying, or displaying a chain rather than acting on one — see Relay Behavior.
It MUST NOT do so when a mandate decides whether an action may happen.

The maximum chain length of four — a root grant plus at most three sub-delegations — matches the `depth ≤ 3` bound the Buzz agent job protocol already assumes for kind `43001`.

Verifiers SHOULD report the zero-based index of the link at which verification failed.

## Authorization

A verified chain conveys the authority in its leaf caveat set.

To decide a concrete action, a verifier supplies:

- the **actor**: the key taking the action, which for a Nostr event is its `pubkey`;
- the **request**: an event kind, and every channel, peer, and tool the action touches;
- the **clock**: the verifier's own Unix timestamp;
- the **use count**: how many invocations the verifier has already attributed to the mandate.

The action is authorized if and only if all of the following hold.

1. The actor equals the leaf's `subject`.
2. If `not_before` is present, the clock is greater than or equal to it.
3. If `expires` is present, the clock is strictly less than it.
4. For `kind` present in the leaf caveats, the request states a kind and it is a member of the permitted set. For each of `channel`, `peer`, and `tool` present in the leaf caveats, the request states at least one value and **every** value it states is a member of the permitted set.
5. If `uses` is present, the use count is strictly less than it.

Rule 1 is mandatory and is what defeats chain truncation; see Security Properties.

Rule 4 fails closed in both directions.
A request that does not state an attribute the mandate constrains MUST be denied; a verifier MUST NOT treat an unstated attribute as evidence that the action does not touch that dimension.
A request that states several values for one dimension MUST have all of them in scope.
A Nostr event may carry many `h` and `p` tags, and an action that targets two channels targets both: a verifier that checked the first tag and stopped would authorize an event tagged `h=engineering` and `h=secrets` under a mandate scoped to `engineering` alone.

A mandate's identity for `uses` accounting is the **leaf link identifier**.
It MUST NOT be the kind:50001 event id: the same chain can be republished in a different JSON encoding, or by a different party, yielding a new event id and — for a verifier that counted per event id — a fresh budget on demand.
The leaf link identifier is a hash over canonical fields that commits to the whole chain above it, so a subject cannot mint a new one without a new grant.

A verifier that does not track invocation counts treats `uses` as advisory rather than enforced, and SHOULD say so where it reports mandate scope.
Implementations SHOULD name that mode explicitly rather than defaulting to it silently.

## Events

A chain is published as a **kind:50001** event whose content is the JSON envelope:

```json
{ "v": 1, "links": [ { "parent": null, "issuer": "…", "subject": "…", "caveats": "…", "sig": "…" } ] }
```

`v` MUST be `1`.
Verifiers MUST reject an envelope with an unrecognised version.
Verifiers MUST reject an envelope or link object carrying any field not defined here.
A tolerated unknown field is a place to hide bytes that change the event id while leaving the chain identical.

A link identifier is revoked by a **kind:50002** event carrying exactly one tag:

```json
["link", "<link-id>"]
```

A revocation MUST be honoured only when its author is the `issuer` of the named link or the root authority of the chain being verified.
This is decidable because it is applied *during* chain verification, where the chain is in hand — a kind:50002 event names an opaque hash and cannot be judged on its own.
A verifier therefore records revocations as (link identifier, revoker) pairs and resolves entitlement per chain, rather than treating any event naming an identifier as authoritative.
Honouring a revocation from an unrelated key would let a stranger disable a mandate they were never party to.

Revoking a link revokes every chain that passes through it, because every descendant link commits to that identifier.

A kind:50001 event MUST be published by a party to the chain: the `issuer` of one of its links, or the leaf subject.
It SHOULD carry a `p` tag naming the leaf subject, so the holder can find mandates issued to it with an ordinary p-filtered query.
That tag is not required when the leaf subject is itself the publisher, since such an event is already discoverable by its author, and some Nostr implementations strip a `p` tag equal to the event's own pubkey while signing.

An event presents a mandate by carrying exactly one `mandate` tag:

```json
["mandate", "<kind:50001-event-id>"]
```

An event carrying more than one `mandate` tag MUST be treated as carrying none.
An event that presents a mandate remains authored by `event.pubkey`, exactly as under NIP-OA.
Verifiers MUST NOT reinterpret a mandate as an identity override.

## Relay Behavior

Relays require no changes to support this NIP.
Relays MAY store, index, and forward kind:50001, kind:50002, and the `mandate` tag as any other event and tag.
Relays MUST NOT rewrite event authorship on the basis of a mandate.
Relays MUST NOT be required to verify a mandate.
A relay that validates kind:50001 at ingest MAY admit any root, because storing a chain is not acting on one and a relay has no view of which roots a given reader trusts.
A relay that *enforces* mandates MUST supply a real trusted root set per Chain Verification rule 0, MUST use its own clock, MUST apply the actor check in Authorization rule 1 against `event.pubkey`, and SHOULD maintain revocations from kind:50002 events within its own community boundary.

## Client Behavior

Clients MUST validate the event against the core Nostr event rules, including that `id` and `sig` are valid for `event.pubkey`, before treating a mandate as meaningful.
Clients that display mandate scope SHOULD display the leaf caveat set, which is complete on its own.
Clients MUST NOT display a mandate as conveying authority to any key other than the leaf subject.
Clients SHOULD ignore an invalid or unverifiable mandate for protocol purposes.

## Security Properties

**A chain is only worth what its root is worth.**
Every other property below is conditional on Chain Verification rule 0.
A self-issued chain from a key invented moments ago satisfies attenuation, truncation-resistance, expiry, and revocation perfectly, and grants its holder everything.
The trusted root set is the whole of the trust decision; the chain is only evidence that authority was not widened on the way down.

**Attenuation is verified, not trusted.**
A verifier computes the narrowing relation at every hop.
An issuer that attempts to grant more than it holds produces a chain that fails verification rather than a chain that must be believed.

**Truncation is useless rather than prevented.**
Any holder of a chain can present a prefix of it, and a prefix is both valid and generally wider.
A prefix names an earlier subject, so Authorization rule 1 makes it unusable by the truncator, who cannot sign as that subject.
Implementations MUST bind authorization to the actor.
An implementation that verifies a chain without checking the actor grants every subject in a chain the authority of the root.

**Expiry does not depend on the subject.**
Time bounds are evaluated against the verifier's clock.
The subject supplies no timestamp that participates in the decision, so the backdating weakness NIP-OA documents does not arise here.
Verifiers with badly skewed clocks will disagree about liveness; this is the same trust assumption as any expiring credential.

**Revocation cascades.**
Revoking one identifier invalidates its whole subtree without the revoker enumerating descendants.
Revocation is only as timely as a verifier's view of kind:50002 events, which this NIP does not specify.
Issuers SHOULD bound mandates with `expires` and treat revocation as a fast path rather than the only control.

**Breadth is not chain-verifiable.**
A chain proves one path from root to subject and carries no evidence about sibling delegations.
How many sub-delegations one link issued can only be enforced by a party that observes all of them, such as the relay or the issuer.
This NIP therefore defines no breadth limit, rather than defining one that a chain verifier could not check.

**Compromise is bounded by the leaf.**
Compromise of a subject key yields the authority in the leaf caveat set and no more, for as long as `expires` allows.
Compromise of an intermediate key additionally permits issuing further links, bounded by that link's `depth`.
Compromise of a subject key does not imply compromise of any issuer key.

**Use counts are local.**
`uses` is enforced against a count the verifier maintains.
Two verifiers that do not share state will each allow the budget independently.
Issuers that require a global budget MUST rely on a single enforcing party.

## Privacy Considerations

A chain discloses every key on the delegation path and the scope each was granted.
Verifiers MAY correlate all events presenting the same mandate.
Publishing a kind:50001 event makes that path visible to everyone who can read the event.

## Test Vectors

Machine-readable vectors are at `crates/buzz-mandate/tests/vectors.json`, covering canonical encoding, rejection, narrowing, authorization, signed chains, chains that MUST be rejected (`invalid_chains`), actor binding including truncated prefixes (`actor_binding`), and root trust (`trust_anchor`).
An implementation that passes only the caveat vectors is not conformant: the chain and actor sections are where the security properties live.
Regenerate them with `cargo run -p buzz-mandate --example mandate-vectors`.

The vectors use the same test secrets as NIP-OA: `0x…01` for the owner and `0x…02` for the planner, plus `0x…03` for the worker.

A root link:

```text
issuer=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
subject=c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
caveats=channel=engineering,general&depth=2&expires=1800000000&kind=9,40002
preimage=nostr:mandate:v1\nroot\n79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\nc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\nchannel=engineering,general&depth=2&expires=1800000000&kind=9,40002
link_id=f77f2295c43f2c1c3ac07fdaa8a840a12a360714e3cd32c31251c5bb1a981500
sig=7fe72b02b1f9e42e2546902e11681b341c5290e2cc59e8a99c1472a5477a03187c680e97c55ced9e2706da8474d3567fe5ad4384b1f0b91474f6430a74311fcc
```

A second link narrowing it, signed by the planner:

```text
parent=f77f2295c43f2c1c3ac07fdaa8a840a12a360714e3cd32c31251c5bb1a981500
issuer=c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
subject=f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
caveats=channel=engineering&depth=1&expires=1799990000&kind=9&uses=5
link_id=e6ccb95e845533465f11406000249be5cf56f8eabbd5cf58baaf5ef746983cf7
sig=4af78e878814ac1bd4d4d02c8ad1910234056f52434ada1b4fa5fe070ca1a7d3384d600735f9e269b50061164fb578f9c502c8d31e23888365d09fe6a85871eb
```

The resulting kind:50001 content:

```json
{
  "v": 1,
  "links": [
    {
      "parent": null,
      "issuer": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "subject": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "caveats": "channel=engineering,general&depth=2&expires=1800000000&kind=9,40002",
      "sig": "7fe72b02b1f9e42e2546902e11681b341c5290e2cc59e8a99c1472a5477a03187c680e97c55ced9e2706da8474d3567fe5ad4384b1f0b91474f6430a74311fcc"
    },
    {
      "parent": "f77f2295c43f2c1c3ac07fdaa8a840a12a360714e3cd32c31251c5bb1a981500",
      "issuer": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "subject": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
      "caveats": "channel=engineering&depth=1&expires=1799990000&kind=9&uses=5",
      "sig": "4af78e878814ac1bd4d4d02c8ad1910234056f52434ada1b4fa5fe070ca1a7d3384d600735f9e269b50061164fb578f9c502c8d31e23888365d09fe6a85871eb"
    }
  ]
}
```

This chain empowers `f9308a01…` and nobody else.
At clock `1799989999` it authorizes kind `9` in `engineering`.
At clock `1799990000` it authorizes nothing.

## Invalid Test Vectors

Verifiers MUST reject each of the following.

Caveat encodings:

- `kind=9&channel=general` — dimensions out of canonical order.
- `kind=9&kind=10` — duplicate dimension.
- `kind=40002,9` — `kind` members not in numeric order.
- `channel=general,engineering` — members not in byte order.
- `kind=9,9` — duplicate member.
- `&kind=9`, `kind=9&`, `kind=9&&tool=shell` — empty clause.
- `kind` — clause missing `=`.
- `realm=block` — unknown dimension.
- `kind=09`, `expires=01700000000` — leading zero.
- `kind=65536`, `depth=256` — value out of range.
- `uses=0` — a budget of zero.
- `kind=` — empty member set.
- `kind=9 `, `tool=café` — illegal byte.
- `tool=sh=ell` — `=` inside a member.
- `peer=deadbeef` — not a 64-hex pubkey.
- `expires=100&not_before=100`, `expires=100&not_before=200` — empty time window.

Chains:

- A root link whose `parent` is not `null`.
- A link whose `parent` is not the previous link's identifier.
- A link whose `issuer` is not the previous link's `subject`.
- A link whose `issuer` equals its `subject`.
- A chain in which one key is the `subject` of two links, or in which a `subject` equals the root `issuer`.
- A chain of five or more links.
- A link whose caveats do not narrow the previous link's.
- A link issued below a link whose `depth` is `0`.
- Any link whose caveats have been edited after signing.
- A link taken from one chain and inserted into another.

Authorization:

- A request by an actor that is not the leaf `subject`, on an otherwise valid chain.
- A request that omits an attribute the leaf caveats constrain.
