
const PROTECTED_RESOURCES = new Set([
  "BLUE_SECRET.txt",
]);

const ALLOWED_LLM_ACTIONS = new Set([
  "llm_test",
]);

function evaluatePolicy(request) {
  if (!request || typeof request !== "object") {
    return {
      decision: "DENY",
      ruleId: "POLICY_INVALID_REQUEST",
      reason: "The request is missing or invalid.",
    };
  }

  const {
    actorTeam,
    action,
    resource,
    resourceTeam,
    resourceSensitivity,
  } = request;

  if (
    typeof actorTeam !== "string" ||
    typeof action !== "string"
  ) {
    return {
      decision: "DENY",
      ruleId: "POLICY_INVALID_REQUEST",
      reason: "The actor team and action must be specified.",
    };
  }

  // Explicitly protect Blue Team confidential resources.
  if (
    action === "read_file" &&
    actorTeam === "red" &&
    resourceTeam === "blue" &&
    (
      PROTECTED_RESOURCES.has(resource) ||
      resourceSensitivity === "confidential"
    )
  ) {
    return {
      decision: "DENY",
      ruleId: "POLICY_CROSS_TEAM_SECRET_DENY",
      reason:
        "Red Team attempted to access a protected Blue Team resource. " +
        "Cross-team confidential access is prohibited.",
    };
  }

  // Teams may access their own resources.
  if (
    action === "read_file" &&
    actorTeam === resourceTeam &&
    resourceSensitivity !== "confidential"
  ) {
    return {
      decision: "ALLOW",
      ruleId: "POLICY_OWN_RESOURCE_ALLOW",
      reason: "The team is accessing its own non-confidential resource.",
    };
  }

  // Controlled LLM testing is permitted, but does not grant
  // permission to access protected resources.
  if (ALLOWED_LLM_ACTIONS.has(action)) {
    return {
      decision: "ALLOW",
      ruleId: "POLICY_LLM_TEST_ALLOW",
      reason: "Controlled LLM testing is permitted.",
    };
  }

  // Fail closed: unknown actions and unrecognized access patterns
  // are denied by default.
  return {
    decision: "DENY",
    ruleId: "POLICY_DEFAULT_DENY",
    reason: "No policy explicitly permits this action.",
  };
}

module.exports = { evaluatePolicy };
