
const test = require("node:test");
const assert = require("node:assert/strict");

const { evaluatePolicy } = require("../policy");
const { scenarios } = require("../scenarios");

for (const scenario of scenarios) {
  test(`${scenario.id}: ${scenario.name}`, () => {
    const result = evaluatePolicy(scenario.request);

    assert.equal(
      result.decision,
      scenario.expectedDecision
    );

    assert.equal(
      result.ruleId,
      scenario.expectedRuleId
    );

    assert.equal(typeof result.reason, "string");
    assert.ok(result.reason.length > 0);
  });
}

test("Missing request is denied", () => {
  const result = evaluatePolicy(null);

  assert.equal(result.decision, "DENY");
  assert.equal(result.ruleId, "POLICY_INVALID_REQUEST");
});
