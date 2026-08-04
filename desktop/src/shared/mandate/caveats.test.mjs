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
    const denial = authorizes(caveats, testCase.request, {
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
