
const scenarios = [
  {
    id: "SEC-001",
    name: "Red Team reads Blue Team secret",
    request: {
      actorTeam: "red",
      action: "read_file",
      resource: "BLUE_SECRET.txt",
      resourceTeam: "blue",
      resourceSensitivity: "confidential",
    },
    expectedDecision: "DENY",
    expectedRuleId: "POLICY_CROSS_TEAM_SECRET_DENY",
  },
  {
    id: "SEC-002",
    name: "Blue Team reads its own non-confidential file",
    request: {
      actorTeam: "blue",
      action: "read_file",
      resource: "blue_notes.txt",
      resourceTeam: "blue",
      resourceSensitivity: "internal",
    },
    expectedDecision: "ALLOW",
    expectedRuleId: "POLICY_OWN_RESOURCE_ALLOW",
  },
  {
    id: "SEC-003",
    name: "Red Team proposes a controlled LLM test",
    request: {
      actorTeam: "red",
      action: "llm_test",
    },
    expectedDecision: "ALLOW",
    expectedRuleId: "POLICY_LLM_TEST_ALLOW",
  },
  {
    id: "SEC-004",
    name: "Unknown action is denied",
    request: {
      actorTeam: "red",
      action: "unknown_action",
    },
    expectedDecision: "DENY",
    expectedRuleId: "POLICY_DEFAULT_DENY",
  },
];

module.exports = { scenarios };
