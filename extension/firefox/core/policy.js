/**
 * Validate the policy projection that the root service sends to adapters.
 * The validator is browser-agnostic, so both adapters reject schema drift.
 */
"use strict";

const POLICY_SCHEMA_VERSION = 4;

/** Return the rule list from one valid policy document. */
function rules_from_policy(value) {
  // Breadcrumb: exact outer fields make incompatible service changes fail
  // closed. Rule fields remain under the existing engine validation contract.
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The service returned an invalid policy document.");
  }
  const fields = Object.keys(value).sort();
  if (fields.join("\u0000") !== "revision\u0000rules\u0000schema_version") {
    throw new Error("The service returned invalid policy fields.");
  }
  if (value.schema_version !== POLICY_SCHEMA_VERSION) {
    throw new Error("The service returned an unsupported policy schema.");
  }
  if (
    !Number.isInteger(value.revision) ||
    value.revision < 0 ||
    !Array.isArray(value.rules)
  ) {
    throw new Error("The service returned invalid policy values.");
  }
  return value.rules;
}
