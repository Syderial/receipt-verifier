export const RECEIPT_ROUTE_KINDS = ["proxy", "hook", "observe_only"];
export const OBSERVE_ONLY_ROUTE_NOTICE = "Observed only. Syderial recorded this after it happened and could not block it. Send the agent's traffic through the Syderial proxy or install the Syderial hooks to enforce policy.";
export const ADVISORY_HOOK_ROUTE_NOTICE = "Advisory hook. Syderial checked this call before it ran but was not allowed to block it.";
export function receiptRoute(kind, options = {}) {
    if (kind === "observe_only")
        return { kind, enforcement: "observed_only", notice: OBSERVE_ONLY_ROUTE_NOTICE };
    if (kind === "hook" && options.advisory === true)
        return { kind, enforcement: "observed_only", notice: ADVISORY_HOOK_ROUTE_NOTICE };
    return { kind, enforcement: "enforced" };
}
const ACTION_AUTHORITY_DECISIONS = ["allow", "deny", "approval_required"];
export function buildUnsignedActionReceipt(input) {
    const issues = validateActionReceiptDraft(input);
    if (issues.length > 0)
        throw new Error(issues[0]);
    return {
        schema_version: "syderial.action-receipt.v1",
        ...(input.claims_mode === undefined ? {} : { claims_mode: input.claims_mode }),
        receipt_id: input.receipt_id,
        action: { name: input.action.name, arguments_hash: input.action.arguments_hash },
        principal: { kind: input.principal.kind, id: input.principal.id },
        boundary_labels: {
            ...input.boundary_labels,
            boundary: [...input.boundary_labels.boundary].sort(),
            compartments: input.boundary_labels.compartments === undefined ? undefined : [...input.boundary_labels.compartments].sort(),
        },
        authority: {
            decision: input.authority.decision,
            policy_ref: input.authority.policy_ref,
            ...(input.authority.policy_version === undefined ? {} : { policy_version: input.authority.policy_version }),
            ...(input.authority.reason_code === undefined ? {} : { reason_code: input.authority.reason_code }),
            ...(input.authority.action_gate === undefined
                ? {}
                : { action_gate: { decision: input.authority.action_gate.decision, ticket_id: input.authority.action_gate.ticket_id } }),
            ...(input.authority.access === undefined ? {} : { access: input.authority.access }),
        },
        ...(input.entailment === undefined ? {} : { entailment: normalizeEntailment(input.entailment) }),
        ...(input.approval === undefined
            ? {}
            : {
                approval: {
                    ticket_id: input.approval.ticket_id,
                    proposal_id: input.approval.proposal_id,
                    approver_role: input.approval.approver_role,
                },
            }),
        ...(input.governance === undefined ? {} : { governance: normalizeGovernance(input.governance) }),
        ...(input.route === undefined ? {} : { route: { kind: input.route.kind, enforcement: input.route.enforcement,
                ...(input.route.notice === undefined ? {} : { notice: input.route.notice }) } }),
        at: input.at,
        source: input.source,
    };
}
function normalizeEntailment(entailment) {
    return {
        entailed: entailment.entailed,
        band: entailment.band,
        score: entailment.score,
        claim_ids: Array.from(new Set(entailment.claim_ids)).sort(),
        scorer_model: entailment.scorer_model,
        hypothesis_hash: entailment.hypothesis_hash,
        premise_hash: entailment.premise_hash,
        ...(entailment.reason === undefined ? {} : { reason: entailment.reason }),
    };
}
function normalizeGovernance(governance) {
    return JSON.parse(JSON.stringify(governance));
}
const MAX_RECEIPT_EVIDENCE_ENTRIES = 64;
function validateGovernance(governance) {
    const issues = [];
    if (governance.session_mode !== "interactive" && governance.session_mode !== "autonomous") {
        issues.push("governance session mode must be interactive or autonomous");
    }
    if (!Number.isInteger(governance.settings_version) || governance.settings_version < 0) {
        issues.push("governance settings version must be a non-negative integer");
    }
    if (!/^[a-f0-9]{64}$/.test(governance.settings_hash))
        issues.push("governance settings hash must be sha256 hex");
    const path = governance.evidence_path;
    if (path.entries.length > MAX_RECEIPT_EVIDENCE_ENTRIES)
        issues.push("evidence path lists at most 64 entries");
    if (path.path_hash !== null && !/^[a-f0-9]{64}$/.test(path.path_hash))
        issues.push("evidence path hash must be sha256 hex");
    if (path.served_count < path.entries.length)
        issues.push("evidence path count must cover its entries");
    if (path.entries.some((entry) => entry.ref.length === 0 || !Number.isInteger(entry.depth) || entry.depth < 0)) {
        issues.push("evidence path entries need a ref and a non-negative depth");
    }
    if (path.relied_on.some((ref) => typeof ref !== "string" || ref.length === 0)) {
        issues.push("evidence path relied_on refs must be non-empty strings");
    }
    const override = governance.override;
    if (override !== undefined) {
        if (override.out_of_envelope !== true)
            issues.push("override receipts must be marked out of envelope");
        if (!(override.min_score >= 0 && override.min_score <= 1))
            issues.push("override minimum score must be within [0, 1]");
        if (override.score !== null && !(override.score >= 0 && override.score <= 1))
            issues.push("override score must be null or within [0, 1]");
        if (override.evidence_hash !== null && !/^[a-f0-9]{64}$/.test(override.evidence_hash)) {
            issues.push("override evidence hash must be sha256 hex");
        }
    }
    return issues;
}
function validateActionReceiptDraft(input) {
    const issues = [];
    if (input.receipt_id.length === 0)
        issues.push("receipt id is required");
    if (input.action.name.length === 0)
        issues.push("action name is required");
    if (!/^[a-f0-9]{64}$/.test(input.action.arguments_hash))
        issues.push("action arguments hash must be sha256 hex");
    if (input.principal.id.length === 0)
        issues.push("principal id is required");
    if (input.boundary_labels.boundary.length === 0)
        issues.push("boundary labels are required");
    if (!ACTION_AUTHORITY_DECISIONS.includes(input.authority.decision)) {
        issues.push("authority decision must be allow, deny or approval_required");
    }
    if (input.authority.decision === "approval_required" && input.approval === undefined) {
        issues.push("approval_required receipts must name the approval ticket");
    }
    if (input.entailment !== undefined)
        issues.push(...validateEntailment(input.entailment));
    if (input.governance !== undefined)
        issues.push(...validateGovernance(input.governance));
    if (input.approval !== undefined) {
        if (input.approval.ticket_id.length === 0)
            issues.push("approval ticket id is required");
        if (input.approval.proposal_id.length === 0)
            issues.push("approval proposal id is required");
        if (input.approval.approver_role.length === 0)
            issues.push("approval approver role is required");
    }
    if (input.at.length === 0)
        issues.push("action timestamp is required");
    if (input.source.length === 0)
        issues.push("action source is required");
    if (input.route !== undefined) {
        if (!RECEIPT_ROUTE_KINDS.includes(input.route.kind))
            issues.push("route must be proxy, hook or observe_only");
        if (input.route.kind === "observe_only" && input.route.enforcement !== "observed_only")
            issues.push("an observe_only route cannot claim enforcement");
        if (input.route.enforcement === "observed_only" && (input.route.notice ?? "").length === 0)
            issues.push("an observed_only route must say so in its notice");
        if (input.route.kind === "observe_only" && input.authority.decision !== "allow")
            issues.push("an observe_only route cannot record a block or a hold");
    }
    return issues;
}
function validateEntailment(entailment) {
    const issues = [];
    if (entailment.band.length === 0)
        issues.push("entailment band is required");
    if (entailment.score !== null && !(Number.isFinite(entailment.score) && entailment.score >= 0 && entailment.score <= 1)) {
        issues.push("entailment score must be null or within [0, 1]");
    }
    if (entailment.claim_ids.some((claimId) => typeof claimId !== "string" || claimId.length === 0)) {
        issues.push("entailment claim ids must be non-empty strings");
    }
    if (entailment.entailed && entailment.claim_ids.length === 0)
        issues.push("an entailed action must cite record claims");
    if (entailment.entailed && entailment.score === null)
        issues.push("an entailed action must carry its entailment score");
    if (!/^[a-f0-9]{64}$/.test(entailment.hypothesis_hash))
        issues.push("entailment hypothesis hash must be sha256 hex");
    if (entailment.premise_hash !== null && !/^[a-f0-9]{64}$/.test(entailment.premise_hash)) {
        issues.push("entailment premise hash must be sha256 hex");
    }
    return issues;
}

const encoder = new TextEncoder();

export function canonicalJson(value) {
  return JSON.stringify(sortCanonical(value));
}

function sortCanonical(value) {
  if (Array.isArray(value)) return value.map(sortCanonical);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)).map(([key, item]) => [key, sortCanonical(item)]));
}

export async function hashCanonical(value) {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(canonicalJson(value))));
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
}

function base64(value) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("Invalid base64");
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

function date(value) {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new Error("Invalid timestamp");
  return Date.parse(value);
}

async function importKey(pem) {
  if (typeof pem !== "string" || !/^-----BEGIN PUBLIC KEY-----\s+[A-Za-z0-9+/=\s]+-----END PUBLIC KEY-----\s*$/.test(pem)) throw new Error("Invalid public key");
  return crypto.subtle.importKey("spki", base64(pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, "")), "Ed25519", true, ["verify"]);
}

export async function signingKeyId(publicKeyPem) {
  const key = await importKey(publicKeyPem);
  return hex(await crypto.subtle.digest("SHA-256", await crypto.subtle.exportKey("raw", key))).slice(0, 16);
}

async function validatedKeys(keySet) {
  if (keySet?.schema_version !== "syderial.signing-keys.v1" || !Array.isArray(keySet.keys) || !keySet.keys.length) throw new Error("Invalid key set");
  const ids = new Set();
  for (const key of keySet.keys) {
    if (key.key_id !== await signingKeyId(key.public_key_pem)) throw new Error("Key fingerprint mismatch");
    const start = date(key.valid_from);
    if (key.valid_until !== null && date(key.valid_until) <= start) throw new Error("Invalid key window");
    if (!Array.isArray(key.aliases ?? [])) throw new Error("Invalid key aliases");
    for (const id of [key.key_id, ...(key.aliases ?? [])]) {
      if (typeof id !== "string" || !id || ids.has(id)) throw new Error("Duplicate or invalid key id");
      ids.add(id);
    }
  }
  const current = keySet.keys.find(key => key.key_id === keySet.current_key_id);
  if (!current || current.valid_until !== null || keySet.keys.some(key => key !== current && key.valid_until === null)
    || !keySet.keys.some(key => key.key_id === keySet.legacy_key_id)) throw new Error("Invalid current or legacy key");
  return keySet.keys;
}

export async function verifyReceipt(receipt, keySet) {
  try {
    const keys = await validatedKeys(keySet);
    let unsigned, digest, signature, keyId, at;
    if (receipt?.schema_version === "syderial.action-receipt.v1") {
      const { signature: signed, receipt_digest, ...body } = receipt;
      if (signed?.algorithm !== "ed25519" || typeof signed.public_key_ref !== "string") throw new Error("Invalid receipt signature");
      unsigned = buildUnsignedActionReceipt(body);
      digest = receipt_digest;
      signature = signed.value;
      keyId = signed.key_id;
      at = body.at;
    } else if (typeof receipt?.event_hash === "string") {
      unsigned = { event_id: receipt.event_id, claim_id: receipt.claim_id, operation: receipt.operation,
        recorded_at: receipt.recorded_at, previous_event_hash: receipt.previous_event_hash ?? null, payload: receipt.payload };
      digest = receipt.event_hash;
      signature = receipt.signature;
      keyId = receipt.signer_key_id;
      at = receipt.recorded_at;
    } else throw new Error("Unsupported receipt format");
    const key = keys.find(key => key.key_id === (keyId === undefined ? keySet.legacy_key_id : keyId)
      || key.aliases?.includes(keyId === undefined ? keySet.legacy_key_id : keyId));
    if (!key || (receipt.schema_version === "syderial.action-receipt.v1" && keyId !== undefined && keyId !== key.key_id)) throw new Error("Unknown signing key");
    const timestamp = date(at);
    if (timestamp < date(key.valid_from) || (key.valid_until !== null && timestamp >= date(key.valid_until))) throw new Error("Signature outside key validity window");
    const calculated = await hashCanonical(unsigned);
    if (digest !== calculated) throw new Error("Canonical hash mismatch");
    const bytes = base64(signature);
    if (bytes.length !== 64 || !await crypto.subtle.verify("Ed25519", await importKey(key.public_key_pem), bytes, encoder.encode(calculated))) throw new Error("Signature verification failed");
    return { verified: true, key_id: key.key_id, issues: [] };
  } catch (error) {
    const allowed = new Set(["Unsupported receipt format", "Invalid receipt signature", "Unknown signing key", "Signature outside key validity window", "Canonical hash mismatch", "Signature verification failed", "Key fingerprint mismatch", "Invalid key window", "Duplicate or invalid key id", "Invalid current or legacy key", "Invalid key aliases", "Invalid key set", "Invalid timestamp", "Receipt must contain JSON values", "Invalid public key", "Invalid base64"]);
    return { verified: false, issues: [allowed.has(error?.message) ? error.message : "Invalid receipt or key set"] };
  }
}

export async function verifyAnswerReceipt(receipt, keySet) {
  if (receipt?.schema_version === 'syderial.runtime.retrieval-receipt.v1') {
    if (!receipt.recall || !Array.isArray(receipt.candidates)) return { verified: false, issues: ['Receipt is missing the canonical retrieval payload'] };
    return { verified: false, issues: ['Retrieval receipt has no signed timestamp for key validity verification'] };
  }
  return verifyReceipt(receipt, keySet);
}
