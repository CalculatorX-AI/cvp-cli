/** Application client for versioned CalculatorX UUCE preflight policies. */

const origin = 'https://www.calculatorx.com';
const capability = 'units.convert';
const calculationVersion = '0.1.1';
const legacyPolicyVersion = '1.0.0';
const expandedPolicyVersion = '1.1.0';
const conversionPath = '/api/v1/units/convert';
const maxResponseBytes = 256 * 1024;
const sha256 = /^[a-f0-9]{64}(?![\s\S])/;
const decimal = /^(?:0|[1-9][0-9]{0,6})(?:\.[0-9]{1,12})?(?![\s\S])/;

export interface UuceInputs {
  value: string;
  from_unit_id: string;
  to_unit_id: string;
  quantity_kind: string;
  role: string;
  snapshot: string;
}

export interface UuceBinding {
  profile: string;
  verification_revision: string;
  cvp_core_sha256: string;
  registry_version: string;
  definition_sha256: string;
  execution_projection_sha256: string;
  integrity_manifest_sha256: string;
  numerical_policy: string;
}

export interface UuceExpandedPolicy {
  format: 'calculatorx-uuce-agent-client-pins-v1';
  capability_id: 'units.convert';
  calculation_version: '0.1.1';
  policy_version: '1.1.0';
  policy_sha256: string;
  binding: UuceBinding;
  groups: Record<string, string[]>;
}

type JsonObject = Record<string, unknown>;
type Decision = 'ALLOW' | 'DENY' | 'NEED_CONTEXT';
export interface UuceResult extends JsonObject {
  exact: { numerator: string; denominator: string; pi_power: 0 };
  decimal: string;
  binary64: number;
  binary64_status: 'finite';
}

export class UuceError extends Error {
  readonly code?: string;
  readonly decision?: Decision;
  readonly status?: number;
  readonly retryAfter?: string;

  constructor(message: string, details: { code?: string; decision?: Decision; status?: number; retryAfter?: string } = {}) {
    super(message);
    this.name = 'UuceError';
    Object.assign(this, details);
  }
}

const record = (value: unknown): value is JsonObject =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function equal(actual: unknown, expected: unknown, depth = 0): boolean {
  if (depth > 32) return false;
  if (actual === expected) return true;
  if (Array.isArray(actual) && Array.isArray(expected)) {
    return actual.length === expected.length && expected.every((value, index) => equal(actual[index], value, depth + 1));
  }
  return record(actual) && record(expected) && Object.keys(actual).length === Object.keys(expected).length &&
    Object.entries(expected).every(([key, value]) => Object.hasOwn(actual, key) && equal(actual[key], value, depth + 1));
}

async function requestJson(path: string, body?: JsonObject): Promise<JsonObject> {
  try {
    const response = await fetch(origin + path, {
      method: body ? 'POST' : 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
      cache: 'no-store',
      body: body ? JSON.stringify(body) : undefined,
    });
    if (response.status !== 200 || !response.body) {
      await response.body?.cancel();
      throw new UuceError(`Unexpected HTTP ${response.status}`, {
        status: response.status,
        code: response.status === 429 ? 'RATE_LIMITED' : undefined,
        retryAfter: response.headers.get('Retry-After') ?? undefined,
      });
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let size = 0;
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxResponseBytes) {
        await reader.cancel();
        throw new UuceError('UUCE response exceeds its size limit');
      }
      text += decoder.decode(value, { stream: true });
    }
    const data: unknown = JSON.parse(text + decoder.decode());
    if (!record(data)) throw new UuceError('Expected a UUCE JSON object');
    return data;
  } catch (error) {
    if (error instanceof UuceError) throw error;
    throw new UuceError('Could not read the CalculatorX response');
  }
}

function timestamp(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString() === value ? ms : NaN;
}

function verifyReceipt(receipt: JsonObject, binding: UuceBinding) {
  const checked = timestamp(receipt.checked_at);
  const expires = timestamp(receipt.expires_at);
  const now = Date.now();
  if (receipt.contract !== 'calculatorx-cvp-production-receipt-v1' || receipt.issuer !== origin ||
      receipt.capability_id !== capability || receipt.calculation_version !== calculationVersion ||
      receipt.production_freshness !== 'CURRENT' || !equal(receipt.binding, binding) ||
      typeof receipt.attestation_id !== 'string' || !sha256.test(receipt.attestation_id) ||
      !(checked <= now && now < expires) || expires - checked !== 7 * 24 * 60 * 60 * 1000) {
    throw new UuceError('Production receipt is expired, unavailable or differs from the trusted pins');
  }
}

async function checkPolicy(policy: UuceExpandedPolicy | undefined, binding: UuceBinding) {
  if (policy === undefined) {
    return { pins: { policy_version: legacyPolicyVersion }, groups: new Map([['length', ['cx:m', 'cx:ft_i']]]) };
  }
  if (!record(policy) || policy.format !== 'calculatorx-uuce-agent-client-pins-v1' ||
      policy.capability_id !== capability || policy.calculation_version !== calculationVersion ||
      policy.policy_version !== expandedPolicyVersion || !equal(policy.binding, binding) ||
      typeof policy.policy_sha256 !== 'string' || !sha256.test(policy.policy_sha256) || !record(policy.groups)) {
    throw new UuceError('The trusted policy record differs from the calculation or receipt pins');
  }
  const digest = policy.policy_sha256;
  const entries: [string, string[]][] = [];
  for (const [kind, units] of Object.entries(policy.groups)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,127}(?![\s\S])/.test(kind) || !Array.isArray(units) || units.length < 2 ||
        ![...units].every(id => typeof id === 'string' && /^cx:[A-Za-z0-9_.-]{1,124}(?![\s\S])/.test(id)) ||
        new Set(units).size !== units.length) {
      throw new UuceError('Invalid trusted policy unit group');
    }
    entries.push([kind, [...units]]);
  }
  entries.sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  const bytes = new TextEncoder().encode(JSON.stringify(entries));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const hex = Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('');
  if (!entries.length || hex !== digest) throw new UuceError('Trusted policy scope does not match its digest');
  return { pins: { policy_version: expandedPolicyVersion, policy_sha256: digest }, groups: new Map(entries) };
}

function inPolicy(inputs: UuceInputs, binding: UuceBinding, groups: Map<string, string[]>) {
  const { from_unit_id: from, to_unit_id: to, quantity_kind: kind } = inputs;
  const units = groups.get(kind);
  const [whole, fraction = ''] = inputs.value.split('.');
  return from !== to && units?.includes(from) && units.includes(to) && inputs.role === 'scalar' &&
    inputs.snapshot === binding.registry_version && decimal.test(inputs.value) &&
    Number(whole) <= 1000000 && (whole !== '1000000' || !/[1-9]/.test(fraction));
}

function resultFor(response: JsonObject, binding: UuceBinding, inputs: UuceInputs) {
  const { verification, result } = response;
  if (response.status !== 'success' || response.capability_id !== capability ||
      response.calculation_version !== calculationVersion || !record(verification) ||
      verification.cvp !== 'verified' || verification.calculation_version !== calculationVersion ||
      verification.verification_revision !== binding.verification_revision ||
      verification.evidence_digest !== binding.cvp_core_sha256 ||
      verification.execution_projection_sha256 !== binding.execution_projection_sha256 ||
      !record(result) || !equal(result.snapshot, {
        version: binding.registry_version, content_digest: binding.definition_sha256,
        execution_projection_sha256: binding.execution_projection_sha256,
        integrity_manifest_sha256: binding.integrity_manifest_sha256,
      }) || result.numerical_policy !== binding.numerical_policy ||
      !equal(result.input, { value: inputs.value, quantity_kind: inputs.quantity_kind, role: inputs.role }) ||
      !record(result.from) || result.from.unit_id !== inputs.from_unit_id ||
      !record(result.to) || result.to.unit_id !== inputs.to_unit_id) {
    throw new UuceError('Conversion response differs from the approved version, binding or inputs', { decision: 'ALLOW' });
  }
  const exact = result.exact;
  if (!record(exact) || exact.pi_power !== 0 ||
      typeof exact.numerator !== 'string' || !/^[0-9]+(?![\s\S])/.test(exact.numerator) ||
      typeof exact.denominator !== 'string' || !/^[1-9][0-9]*(?![\s\S])/.test(exact.denominator) ||
      typeof result.decimal !== 'string' || typeof result.binary64 !== 'number' ||
      !Number.isFinite(result.binary64) || result.binary64_status !== 'finite') {
    throw new UuceError('Invalid UUCE result for the approved scalar conversion', { decision: 'ALLOW' });
  }
  return result as UuceResult;
}

export async function convertUnits(source: UuceInputs, options: {
  binding: UuceBinding; useCase: 'standalone_low_risk'; policy?: UuceExpandedPolicy;
}) {
  const useCase = options?.useCase;
  if (useCase !== 'standalone_low_risk') {
    throw new UuceError('Confirm standalone_low_risk before requesting a conversion', {
      code: 'CONTEXT_REQUIRED', decision: 'NEED_CONTEXT',
    });
  }
  const inputs = { ...source };
  const binding = { ...options.binding };
  const bindingFields = ['profile', 'verification_revision', 'cvp_core_sha256', 'registry_version',
    'definition_sha256', 'execution_projection_sha256', 'integrity_manifest_sha256', 'numerical_policy'];
  const pins: JsonObject = { ...binding };
  if (Object.keys(binding).length !== bindingFields.length || !bindingFields.every(key =>
    typeof pins[key] === 'string' && pins[key] && (!key.endsWith('_sha256') || sha256.test(pins[key] as string)))) {
    throw new UuceError('Supply a complete, independently trusted UUCE binding', { code: 'INVALID_TRUST_PIN' });
  }
  const inputFields: (keyof UuceInputs)[] = ['value', 'from_unit_id', 'to_unit_id', 'quantity_kind', 'role', 'snapshot'];
  if (Object.keys(inputs).length !== inputFields.length ||
      !inputFields.every(key => typeof inputs[key] === 'string' && inputs[key])) {
    throw new UuceError('Supply explicit unit IDs, decimal text, quantity kind, role and snapshot', { code: 'INVALID_INPUT' });
  }
  const { pins: policyPins, groups } = await checkPolicy(options.policy, binding);
  const query = new URLSearchParams({ capability_id: capability, calculation_version: calculationVersion });
  const receipt = await requestJson('/api/v1/cvp/receipt?' + query);
  verifyReceipt(receipt, binding);
  const envelope = { calculation_version: calculationVersion, inputs };
  const approval = await requestJson('/api/v1/units/preflight', {
    ...envelope, ...policyPins, trust: binding, context: { use_case: useCase },
  });
  if (approval.contract !== 'calculatorx-uuce-agent-preflight-v1' ||
      Object.entries(policyPins).some(([key, pin]) => approval[key] !== pin)) {
    throw new UuceError('Production preflight contract or policy pins differ');
  }
  if (approval.decision === 'DENY' || approval.decision === 'NEED_CONTEXT') {
    throw new UuceError(`Production preflight returned ${approval.decision}`, {
      decision: approval.decision, code: typeof approval.code === 'string' ? approval.code : undefined,
    });
  }
  if (approval.decision !== 'ALLOW' || approval.code !== 'IN_POLICY' || !inPolicy(inputs, binding, groups) ||
      !equal(approval.receipt, receipt) ||
      !equal(approval.execute, { method: 'POST', path: conversionPath, body: envelope })) {
    throw new UuceError('Production approval differs from the pinned policy, receipt or request');
  }
  verifyReceipt(receipt, binding);
  const result = resultFor(await requestJson(conversionPath, envelope), binding, inputs);
  return {
    result,
    production_preflight: {
      decision: 'ALLOW' as const, code: 'IN_POLICY', ...policyPins,
      attestation_id: receipt.attestation_id as string, expires_at: receipt.expires_at as string,
    },
  };
}
