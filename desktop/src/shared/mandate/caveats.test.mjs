import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  authorizes,
  describeCaveats,
  encodeCaveats,
  narrows,
  parseCaveats,
  permits,
} from "./caveats.ts";

// The same file `crates/buzz-mandate/tests/vectors.rs` runs against. If this
// implementation and the Rust one ever disagree, one of the two suites fails
// rather than the disagreement shipping.
const VECTORS = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL(
        "../../../../crates/buzz-mandate/tests/vectors.json",
        import.meta.url,
      ),
    ),
    "utf8",
  ),
);

test("canonical caveat vectors parse and round-trip", () => {
  for (const input of VECTORS.canonical_caveats) {
    const parsed = parseCaveats(input);
    assert.equal(
      encodeCaveats(parsed),
      input,
      `${JSON.stringify(input)} must round-trip`,
    );
  }
});

test("invalid caveat vectors are rejected", () => {
  for (const { input, reason } of VECTORS.invalid_caveats) {
    assert.throws(
      () => parseCaveats(input),
      `${JSON.stringify(input)} must be rejected (${reason})`,
    );
  }
});

test("narrowing vectors agree with the Rust implementation", () => {
  for (const testCase of VECTORS.narrowing) {
    const parent = parseCaveats(testCase.parent);
    const child = parseCaveats(testCase.child);
    assert.equal(
      narrows(child, parent) === null,
      testCase.narrows,
      `${JSON.stringify(testCase.child)} narrows ${JSON.stringify(testCase.parent)}` +
        ` should be ${testCase.narrows}`,
    );
  }
});

test("authorization vectors agree with the Rust implementation", () => {
  for (const testCase of VECTORS.authorization) {
    const caveats = parseCaveats(testCase.caveats);
    const denial = permits(caveats, testCase.request, {
      now: testCase.now,
      usesConsumed: testCase.uses_consumed,
    });

    assert.equal(
      denial === null,
      testCase.allowed,
      `${JSON.stringify(testCase.caveats)} at ${testCase.now}` +
        ` should be allowed=${testCase.allowed}, got ${denial}`,
    );
    if (denial !== null && testCase.reason) {
      assert.equal(
        denial,
        testCase.reason,
        `${JSON.stringify(testCase.caveats)}: deny reason`,
      );
    }
  }
});

test("every signed chain vector's leaf caveats parse and round-trip", () => {
  for (const chain of VECTORS.chains) {
    const leaf = chain.envelope.links[chain.envelope.links.length - 1];
    const parsed = parseCaveats(leaf.caveats);

    assert.equal(
      encodeCaveats(parsed),
      leaf.caveats,
      `${chain.name}: leaf round-trip`,
    );
    // NIP-CM's leaf-completeness guarantee, checked from the client side.
    assert.equal(
      leaf.caveats,
      chain.effective_caveats,
      `${chain.name}: leaf is the whole grant`,
    );
  }
});

test("each link in a chain vector narrows the one before it", () => {
  for (const chain of VECTORS.chains) {
    const links = chain.envelope.links;
    for (let index = 1; index < links.length; index += 1) {
      const parent = parseCaveats(links[index - 1].caveats);
      const child = parseCaveats(links[index].caveats);
      assert.equal(
        narrows(child, parent),
        null,
        `${chain.name}: link ${index} must narrow link ${index - 1}`,
      );
    }
  }
});

test("describeCaveats summarises a grant in one line", () => {
  assert.equal(describeCaveats({}), "unconstrained");
  assert.equal(
    describeCaveats(parseCaveats("channel=engineering&depth=0&kind=9&uses=3")),
    "kinds 9 · in #engineering · 3 use(s) · no sub-delegation",
  );
});

test("actor binding vectors agree with the Rust implementation", () => {
  // The rule NIP-CM calls mandatory: a chain prefix is valid and wider, and
  // only the subject check makes it useless to whoever truncated it.
  for (const testCase of VECTORS.actor_binding) {
    const links = testCase.envelope.links;
    const leaf = links[links.length - 1];
    const mandate = {
      subject: leaf.subject,
      caveats: parseCaveats(leaf.caveats),
    };

    const denial = authorizes(mandate, testCase.actor, testCase.request, {
      now: testCase.now,
    });

    assert.equal(
      denial === null,
      testCase.allowed,
      `${testCase.name}: expected allowed=${testCase.allowed}, got ${denial}`,
    );
    if (denial !== null && testCase.reason) {
      assert.equal(denial, testCase.reason, `${testCase.name}: deny reason`);
    }
  }
});

test("this module does not pretend to verify chains", () => {
  // Chain-level rules — signatures, linkage, attenuation, root trust — live in
  // Rust. Asserting the boundary here keeps a future edit from quietly turning
  // a display helper into something a permission decision leans on.
  // A chain the Rust suite rejects outright is still parseable here, because
  // parsing caveats is all this module claims to do.
  const invalid = VECTORS.invalid_chains.find(
    (c) => c.name === "widened_after_signing",
  );
  assert.ok(invalid, "vector present");
  const leaf = invalid.envelope.links[invalid.envelope.links.length - 1];
  assert.doesNotThrow(() => parseCaveats(leaf.caveats));
});

test("encodeCaveats canonicalises hand-built objects", () => {
  // Nothing in TS signs today, but an encoder that can emit a non-canonical
  // string is a footgun waiting for the day something does.
  assert.equal(
    encodeCaveats({ kind: [40002, 9, 9], channel: ["general", "engineering"] }),
    "channel=engineering,general&kind=9,40002",
  );
});

test("describeCaveats renders both time bounds", () => {
  const described = describeCaveats(
    parseCaveats("expires=2000&kind=9&not_before=1000"),
  );
  assert.match(described, /from 1970-01-01T00:16:40/);
  assert.match(described, /until 1970-01-01T00:33:20/);

  // expires=0 is a real bound, not a missing one.
  assert.match(describeCaveats({ expires: 0 }), /until 1970-01-01T00:00:00/);
});

test("every stated value must be in scope", () => {
  const caveats = parseCaveats("channel=engineering");
  const context = { now: 1000 };

  assert.equal(permits(caveats, { channels: ["engineering"] }, context), null);
  assert.equal(
    permits(caveats, { channels: ["engineering", "secrets"] }, context),
    "out_of_scope",
  );
  assert.equal(
    permits(caveats, { channels: ["secrets", "engineering"] }, context),
    "out_of_scope",
  );
  assert.equal(permits(caveats, {}, context), "unstated_dimension");
});
