/**
 * NIP-CM caveat algebra — the client half of capability mandates.
 *
 * See `docs/nips/NIP-CM.md` for the protocol and `crates/buzz-mandate` for the
 * reference implementation. Both run against `crates/buzz-mandate/tests/
 * vectors.json`, so this file and the Rust crate cannot drift apart silently.
 *
 * Scope: parsing, canonical encoding, narrowing, and the caveat half of
 * authorization. Signature checking, chain linkage, attenuation across links,
 * and root trust all stay in Rust — on the relay and in the CLI — because the
 * client's job is to *show* a user what an agent may do.
 *
 * That boundary is load-bearing, so this module refuses to look like a full
 * verifier: `permits()` is named for what it actually checks, and `authorizes()`
 * demands the subject and actor so it cannot silently skip the binding that
 * defeats chain truncation. Neither knows whether the chain was signed, whether
 * each link narrows the last, or whether its root is trusted. Rendering scope
 * from an unverified chain is fine; granting on one is not.
 */

/** Dimension names, in the canonical (ascending lexicographic) order. */
const DIMENSIONS = [
  "channel",
  "depth",
  "expires",
  "kind",
  "not_before",
  "peer",
  "tool",
  "uses",
] as const;

export type Dimension = (typeof DIMENSIONS)[number];

const MAX_KIND = 65535;
const MAX_DEPTH = 255;
const MAX_U32 = 4294967295;
const MAX_NAME_LEN = 64;
const MAX_CAVEATS_LEN = 2048;
const MAX_SET_MEMBERS = 64;

/** A parsed caveat set. An absent field is unconstrained. */
export interface Caveats {
  channel?: string[];
  depth?: number;
  expires?: number;
  kind?: number[];
  not_before?: number;
  peer?: string[];
  tool?: string[];
  uses?: number;
}

/**
 * The action being attempted. Unstated attributes fail closed.
 *
 * The plural fields are plural on purpose: a Nostr event carries as many `h`
 * and `p` tags as its author chose, and *every* value it states must be in
 * scope. Checking one and stopping would authorize the rest.
 */
export interface MandateRequest {
  kind?: number;
  channels?: string[];
  peers?: string[];
  tools?: string[];
}

/** The part of a verified mandate this module can reason about. */
export interface MandateScope {
  /** Leaf subject — the only key the mandate empowers. */
  subject: string;
  /** Leaf caveats, which NIP-CM guarantees are the whole chain's authority. */
  caveats: Caveats;
}

/** What the verifier knows that the mandate does not. */
export interface VerifyContext {
  /** The verifier's clock, in Unix seconds. Never the subject's. */
  now: number;
  /** Invocations already attributed to this mandate. */
  usesConsumed?: number;
}

export type DenyReason =
  | "wrong_subject"
  | "not_yet_valid"
  | "expired"
  | "unstated_dimension"
  | "out_of_scope"
  | "budget_exhausted";

export class CaveatError extends Error {}

const NAME_PATTERN = /^[A-Za-z0-9._:/-]+$/;
const PEER_PATTERN = /^[0-9a-f]{64}$/;

function isCanonicalInteger(value: string): boolean {
  if (value.length === 0) return false;
  if (value.length > 1 && value.startsWith("0")) return false;
  return /^[0-9]+$/.test(value);
}

function parseScalar(
  dimension: string,
  value: string,
  min: number,
  max: number,
): number {
  if (!isCanonicalInteger(value)) {
    throw new CaveatError(
      `${dimension}: ${JSON.stringify(value)} is not a canonical integer`,
    );
  }
  const parsed = Number(value);
  if (parsed < min || parsed > max) {
    throw new CaveatError(
      `${dimension}: ${parsed} is out of range [${min}, ${max}]`,
    );
  }
  return parsed;
}

function parseNumberSet(dimension: string, value: string): number[] {
  const members = value.split(",").map((member) => {
    if (!isCanonicalInteger(member)) {
      throw new CaveatError(
        `${dimension}: invalid member ${JSON.stringify(member)}`,
      );
    }
    const parsed = Number(member);
    if (parsed > MAX_KIND) {
      throw new CaveatError(`${dimension}: member ${parsed} is out of range`);
    }
    return parsed;
  });

  for (let index = 1; index < members.length; index += 1) {
    if (members[index] <= members[index - 1]) {
      throw new CaveatError(
        `${dimension}: members are unordered or duplicated`,
      );
    }
  }
  if (members.length > MAX_SET_MEMBERS) {
    throw new CaveatError(
      `${dimension}: ${members.length} members exceeds the maximum of ${MAX_SET_MEMBERS}`,
    );
  }
  return members;
}

function parseStringSet(
  dimension: string,
  value: string,
  pattern: RegExp,
): string[] {
  const members = value.split(",");
  for (const member of members) {
    if (!pattern.test(member) || member.length > MAX_NAME_LEN) {
      throw new CaveatError(
        `${dimension}: invalid member ${JSON.stringify(member)}`,
      );
    }
  }
  for (let index = 1; index < members.length; index += 1) {
    if (members[index] <= members[index - 1]) {
      throw new CaveatError(
        `${dimension}: members are unordered or duplicated`,
      );
    }
  }
  if (members.length > MAX_SET_MEMBERS) {
    throw new CaveatError(
      `${dimension}: ${members.length} members exceeds the maximum of ${MAX_SET_MEMBERS}`,
    );
  }
  return members;
}

/**
 * Parse a canonical caveat string. The empty string is the unconstrained set.
 *
 * Non-canonical input is rejected rather than repaired: a link's id hashes its
 * encoded caveats, so a second spelling would be a second id.
 *
 * @throws {CaveatError} if the string is malformed or non-canonical.
 */
export function parseCaveats(input: string): Caveats {
  if (input === "") return {};

  if (input.length > MAX_CAVEATS_LEN) {
    throw new CaveatError(
      `caveats are ${input.length} bytes, exceeding the maximum of ${MAX_CAVEATS_LEN}`,
    );
  }

  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) {
      throw new CaveatError(`illegal byte at position ${index}`);
    }
  }

  const caveats: Caveats = {};
  let previous: string | undefined;

  for (const clause of input.split("&")) {
    if (clause === "") {
      throw new CaveatError("empty clause (leading, trailing, or doubled '&')");
    }

    const separator = clause.indexOf("=");
    if (separator < 0)
      throw new CaveatError(`clause ${JSON.stringify(clause)} is missing '='`);

    const dimension = clause.slice(0, separator);
    const value = clause.slice(separator + 1);

    if (!(DIMENSIONS as readonly string[]).includes(dimension)) {
      throw new CaveatError(`unknown dimension ${JSON.stringify(dimension)}`);
    }
    if (previous !== undefined) {
      if (dimension === previous)
        throw new CaveatError(`duplicate dimension ${dimension}`);
      if (dimension < previous)
        throw new CaveatError(`dimensions out of canonical order`);
    }
    previous = dimension;

    switch (dimension as Dimension) {
      case "channel":
        caveats.channel = parseStringSet("channel", value, NAME_PATTERN);
        break;
      case "depth":
        caveats.depth = parseScalar("depth", value, 0, MAX_DEPTH);
        break;
      case "expires":
        caveats.expires = parseScalar("expires", value, 0, MAX_U32);
        break;
      case "kind":
        caveats.kind = parseNumberSet("kind", value);
        break;
      case "not_before":
        caveats.not_before = parseScalar("not_before", value, 0, MAX_U32);
        break;
      case "peer":
        caveats.peer = parseStringSet("peer", value, PEER_PATTERN);
        break;
      case "tool":
        caveats.tool = parseStringSet("tool", value, NAME_PATTERN);
        break;
      case "uses":
        caveats.uses = parseScalar("uses", value, 1, MAX_U32);
        break;
    }
  }

  if (
    caveats.not_before !== undefined &&
    caveats.expires !== undefined &&
    caveats.not_before >= caveats.expires
  ) {
    throw new CaveatError(
      `empty time window: not_before ${caveats.not_before} >= expires ${caveats.expires}`,
    );
  }

  return caveats;
}

/**
 * Encode to the single legal string form.
 *
 * Sets are sorted and deduplicated here rather than trusted from the caller —
 * numerically for `kind`, bytewise otherwise — so a hand-built object cannot
 * produce a string that would fail `parseCaveats`. There is exactly one legal
 * encoding of a caveat set, and this function emits it or nothing.
 */
export function encodeCaveats(caveats: Caveats): string {
  const clauses: string[] = [];
  for (const dimension of DIMENSIONS) {
    const value = caveats[dimension];
    if (value === undefined) continue;

    if (Array.isArray(value)) {
      const members =
        dimension === "kind"
          ? [...new Set(value as number[])].sort((a, b) => a - b)
          : [...new Set(value as string[])].sort();
      clauses.push(`${dimension}=${members.join(",")}`);
    } else {
      clauses.push(`${dimension}=${value}`);
    }
  }
  return clauses.join("&");
}

function isSubset(
  child: readonly (string | number)[],
  parent: readonly (string | number)[],
) {
  const permitted = new Set(parent);
  return child.every((member) => permitted.has(member));
}

/**
 * Whether `child` grants no more than `parent` on any dimension.
 *
 * Returns `null` when it narrows, or the reason it widens. Dropping a
 * constraint the parent set is a widening, not an inheritance — that is what
 * makes the leaf link a complete statement of a chain's authority.
 */
export function narrows(child: Caveats, parent: Caveats): string | null {
  for (const dimension of ["channel", "kind", "peer", "tool"] as const) {
    const parentSet = parent[dimension];
    if (parentSet === undefined) continue;
    const childSet = child[dimension];
    if (childSet === undefined)
      return `${dimension}: parent constrains it, child does not`;
    if (!isSubset(childSet, parentSet)) {
      return `${dimension}: child admits members the parent does not`;
    }
  }

  for (const [dimension, direction] of [
    ["expires", "upper"],
    ["uses", "upper"],
    ["not_before", "lower"],
  ] as const) {
    const parentBound = parent[dimension];
    if (parentBound === undefined) continue;
    const childBound = child[dimension];
    if (childBound === undefined)
      return `${dimension}: parent constrains it, child does not`;
    const ok =
      direction === "upper"
        ? childBound <= parentBound
        : childBound >= parentBound;
    if (!ok) {
      return `${dimension}: child ${childBound} must be ${
        direction === "upper" ? "at most" : "at least"
      } parent ${parentBound}`;
    }
  }

  if (parent.depth !== undefined) {
    if (child.depth === undefined)
      return "depth: parent constrains it, child does not";
    if (parent.depth === 0 || child.depth >= parent.depth) {
      return `depth: child ${child.depth} must be strictly less than parent ${parent.depth}`;
    }
  }

  return null;
}

/**
 * Whether these caveats admit `request` at `context.now`.
 *
 * Returns `null` when they do, or the reason they do not. Time is read from
 * `context`, never from anything the subject supplies.
 *
 * This is the caveat check *only*. It says nothing about who is acting, so it
 * cannot answer "may this agent do this" on its own — use `authorizes()`.
 */
export function permits(
  caveats: Caveats,
  request: MandateRequest,
  context: VerifyContext,
): DenyReason | null {
  if (caveats.not_before !== undefined && context.now < caveats.not_before) {
    return "not_yet_valid";
  }
  if (caveats.expires !== undefined && context.now >= caveats.expires) {
    return "expired";
  }

  if (caveats.kind !== undefined) {
    if (request.kind === undefined) return "unstated_dimension";
    if (!caveats.kind.includes(request.kind)) return "out_of_scope";
  }

  const stated = {
    channel: request.channels,
    peer: request.peers,
    tool: request.tools,
  } as const;

  for (const dimension of ["channel", "peer", "tool"] as const) {
    const permitted = caveats[dimension];
    if (permitted === undefined) continue;

    const values = stated[dimension];
    if (values === undefined || values.length === 0)
      return "unstated_dimension";
    // Every stated value, not merely the first.
    if (values.some((value) => !permitted.includes(value)))
      return "out_of_scope";
  }

  if (
    caveats.uses !== undefined &&
    (context.usesConsumed ?? 0) >= caveats.uses
  ) {
    return "budget_exhausted";
  }

  return null;
}

/**
 * Whether `mandate` authorizes `actor` to perform `request` at `context.now`.
 *
 * The `actor === mandate.subject` check is mandatory and comes first: any
 * holder of a chain can present a *prefix* of it, and prefixes are both valid
 * and wider. A prefix names an earlier subject, so binding to the actor makes
 * truncation useless — and forgetting to bind makes it devastating.
 *
 * This still does not verify the chain. Callers must have obtained
 * `mandate.subject` and `mandate.caveats` from a source that did — the relay or
 * the CLI — because nothing here checks a signature or a root.
 */
export function authorizes(
  mandate: MandateScope,
  actor: string,
  request: MandateRequest,
  context: VerifyContext,
): DenyReason | null {
  if (actor !== mandate.subject) return "wrong_subject";
  return permits(mandate.caveats, request, context);
}

/**
 * A one-line, human-readable summary of what a mandate permits.
 *
 * Reads the leaf caveat set only, which NIP-CM guarantees is the intersection
 * of the whole chain.
 */
export function describeCaveats(caveats: Caveats): string {
  const parts: string[] = [];

  if (caveats.kind) parts.push(`kinds ${caveats.kind.join(", ")}`);
  if (caveats.channel)
    parts.push(`in ${caveats.channel.map((c) => `#${c}`).join(", ")}`);
  if (caveats.tool) parts.push(`tools ${caveats.tool.join(", ")}`);
  if (caveats.peer) parts.push(`with ${caveats.peer.length} peer(s)`);
  if (caveats.uses !== undefined) parts.push(`${caveats.uses} use(s)`);
  // Compare against undefined, not truthiness: `expires=0` is a real bound, and
  // treating it as absent would render a lapsed mandate as if it never expired.
  // `not_before` is rendered for the same reason — a mandate that is not valid
  // yet must not read as live.
  if (caveats.not_before !== undefined)
    parts.push(`from ${new Date(caveats.not_before * 1000).toISOString()}`);
  if (caveats.expires !== undefined)
    parts.push(`until ${new Date(caveats.expires * 1000).toISOString()}`);
  if (caveats.depth !== undefined) {
    parts.push(
      caveats.depth === 0
        ? "no sub-delegation"
        : `${caveats.depth} more hop(s)`,
    );
  }

  return parts.length > 0 ? parts.join(" · ") : "unconstrained";
}
