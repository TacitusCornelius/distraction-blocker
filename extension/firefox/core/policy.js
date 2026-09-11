/**
 * Validate the policy projection that the root service sends to adapters.
 * The validator is browser-agnostic, so both adapters reject schema drift.
 */
"use strict";

const POLICY_SCHEMA_VERSION = 6;

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

/**
 * Expand managed-list references before matcher compilation.
 * The caller supplies the native request function so the complete browser
 * projection is assembled before either adapter changes active enforcement.
 */
async function expand_managed_lists(policy, read_list) {
  if (typeof read_list !== "function") {
    throw new Error("Managed-list loader is unavailable.");
  }
  const list_ids = new Set();
  for (const rule of policy.rules) {
    for (const target of rule.targets ?? []) {
      if (target?.kind === "managed_list") {
        list_ids.add(target.value);
      }
    }
  }
  const domains = new Map();
  for (const list_id of list_ids) {
    const values = [];
    let offset = 0;
    while (true) {
      const response = await read_list(list_id, offset);
      if (!response?.ok || !response.result) {
        throw new Error(
          response?.error?.message ?? "Managed-list contents unavailable.",
        );
      }
      const result = response.result;
      if (
        result.id !== list_id ||
        result.offset !== offset ||
        result.revision !== policy.revision ||
        !Array.isArray(result.domains) ||
        result.domains.length > 200 ||
        result.domains.some((value) => typeof value !== "string")
      ) {
        throw new Error("Managed-list contents changed during policy load.");
      }
      values.push(...result.domains);
      if (result.next_offset === null) {
        break;
      }
      if (
        !Number.isInteger(result.next_offset) ||
        result.next_offset <= offset ||
        result.next_offset !== offset + result.domains.length
      ) {
        throw new Error("Managed-list contents are invalid.");
      }
      offset = result.next_offset;
    }
    domains.set(list_id, values);
  }
  return {
    ...policy,
    rules: policy.rules.map((rule) => {
      const targets = [];
      const seen = new Set();
      for (const target of rule.targets ?? []) {
        const expanded = target?.kind === "managed_list"
          ? (domains.get(target.value) ?? []).map((value) => ({
              kind: "website",
              value,
            }))
          : [target];
        for (const item of expanded) {
          const key = `${item.kind}\u0000${item.value}`;
          if (!seen.has(key)) {
            seen.add(key);
            targets.push(item);
          }
        }
      }
      return { ...rule, targets };
    }),
  };
}
