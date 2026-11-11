import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { convertUnits, UuceError, type UuceExpandedPolicy } from './uuce.ts';

const { binding } = JSON.parse(readFileSync(new URL('../../releases/uuce-agent-policy-1.0.0.json', import.meta.url), 'utf8'));
const inputs = {
  value: '2', from_unit_id: 'cx:ft_i', to_unit_id: 'cx:m', quantity_kind: 'length',
  role: 'scalar', snapshot: binding.registry_version,
};
const options = { binding, useCase: 'standalone_low_risk' as const };
const checked = Date.now() - 3600000;
const receipt = {
  contract: 'calculatorx-cvp-production-receipt-v1', issuer: 'https://www.calculatorx.com',
  capability_id: 'units.convert', calculation_version: '0.1.1', production_freshness: 'CURRENT',
  attestation_id: '1'.repeat(64), binding,
  checked_at: new Date(checked).toISOString(),
  expires_at: new Date(checked + 7 * 86400000).toISOString(),
};
const approval = {
  contract: 'calculatorx-uuce-agent-preflight-v1', policy_version: '1.0.0', decision: 'ALLOW', code: 'IN_POLICY',
  receipt, execute: { method: 'POST', path: '/api/v1/units/convert', body: { calculation_version: '0.1.1', inputs } },
};
const output = {
  status: 'success', capability_id: 'units.convert', calculation_version: '0.1.1',
  verification: {
    cvp: 'verified', calculation_version: '0.1.1', verification_revision: binding.verification_revision,
    evidence_digest: binding.cvp_core_sha256, execution_projection_sha256: binding.execution_projection_sha256,
  },
  result: {
    exact: { numerator: '381', denominator: '625', pi_power: 0 },
    decimal: '6.096e-1', binary64: 0.6096, binary64_status: 'finite',
    snapshot: { version: binding.registry_version, content_digest: binding.definition_sha256,
      execution_projection_sha256: binding.execution_projection_sha256, integrity_manifest_sha256: binding.integrity_manifest_sha256 },
    numerical_policy: binding.numerical_policy, input: { value: '2', quantity_kind: 'length', role: 'scalar' },
    from: { unit_id: 'cx:ft_i' }, to: { unit_id: 'cx:m' },
  },
};

test('executes the original request after verifying approval and returns the bound result', async t => {
  const replies = [receipt, approval, output];
  const fetch = t.mock.method(globalThis, 'fetch', async (url, request) => {
    assert.equal(new URL(url).origin, receipt.issuer);
    assert.equal(request.redirect, 'error');
    if (replies.length === 1) assert.deepEqual(JSON.parse(request.body), approval.execute.body);
    return Response.json(replies.shift());
  });
  const converted = await convertUnits(inputs, options);
  assert.equal(fetch.mock.callCount(), 3);
  assert.deepEqual(converted.result.exact, output.result.exact);
  assert.equal(converted.production_preflight.decision, 'ALLOW');
});

test('rejects a denial, changed approval, expired receipt and limits before conversion', async t => {
  const cases = [
    { replies: [receipt, { ...approval, decision: 'DENY', code: 'CONVERSION_OUTSIDE_POLICY' }], code: 'CONVERSION_OUTSIDE_POLICY' },
    { replies: [receipt, { ...approval, execute: { ...approval.execute, path: '/different' } }] },
    { replies: [{ ...receipt, expires_at: new Date(checked).toISOString() }] },
    { replies: [new Response(null, { status: 429, headers: { 'Retry-After': '7' } })], code: 'RATE_LIMITED', retryAfter: '7' },
  ];
  for (const { replies, code, retryAfter } of cases) {
    const pending = [...replies];
    const fetch = t.mock.method(globalThis, 'fetch', async url => {
      assert.notEqual(new URL(url).pathname, '/api/v1/units/convert');
      const reply = pending.shift();
      return reply instanceof Response ? reply : Response.json(reply);
    });
    try {
      await assert.rejects(convertUnits(inputs, options),
        error => error instanceof UuceError && error.code === code && error.retryAfter === retryAfter);
      assert.equal(fetch.mock.callCount(), replies.length);
    } finally {
      fetch.mock.restore();
    }
  }
});

test('requires explicit context and checks the returned binding', async t => {
  const replies = [receipt, approval, { ...output, verification: { ...output.verification, evidence_digest: '0'.repeat(64) } }];
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json(replies.shift()));
  await assert.rejects(convertUnits(inputs, { binding } as typeof options), { decision: 'NEED_CONTEXT' });
  assert.equal(fetch.mock.callCount(), 0);
  await assert.rejects(convertUnits(inputs, options), /differs from the approved version/);
  assert.equal(fetch.mock.callCount(), 3);
});

test('opts into a pinned expanded policy for mass and rejects a changed digest', async t => {
  const policy: UuceExpandedPolicy = JSON.parse(readFileSync(new URL('../../releases/uuce-agent-policy-1.1.0.json', import.meta.url), 'utf8'));
  const mass = { ...inputs, quantity_kind: 'mass', from_unit_id: 'cx:kg', to_unit_id: 'cx:g' };
  const body = { calculation_version: '0.1.1', inputs: mass };
  const expanded = { ...approval, policy_version: '1.1.0', policy_sha256: policy.policy_sha256,
    execute: { ...approval.execute, body } };
  const massOutput = { ...output, result: { ...output.result, exact: { numerator: '2000', denominator: '1', pi_power: 0 },
    decimal: '2e3', binary64: 2000, input: { ...output.result.input, quantity_kind: 'mass' },
    from: { unit_id: 'cx:kg' }, to: { unit_id: 'cx:g' } } };
  const replies = [receipt, expanded, massOutput, receipt, { ...expanded, policy_sha256: '0'.repeat(64) }];
  const fetch = t.mock.method(globalThis, 'fetch', async (url, request) => {
    if (new URL(url).pathname.endsWith('/preflight')) assert.equal(JSON.parse(request.body).policy_sha256, policy.policy_sha256);
    return Response.json(replies.shift());
  });
  const result = await convertUnits(mass, { ...options, policy });
  assert.equal(result.result.decimal, '2e3');
  assert.equal(result.production_preflight.policy_version, '1.1.0');
  await assert.rejects(convertUnits(mass, { ...options, policy }), /policy pins differ/);
  await assert.rejects(convertUnits(mass, { ...options, policy: { ...policy, groups: { mass: ['cx:kg', 'cx:g'] } } }), /scope does not match/);
  assert.equal(fetch.mock.callCount(), 5);
});
