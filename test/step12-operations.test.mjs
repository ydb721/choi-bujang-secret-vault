import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { RULE_IDS } from '../src/decider.mjs';
import { DETECTION_CONTRACT } from '../src/detect.mjs';
import {
  STATUS,
  operationFailure,
  protectedReadObservation,
  UNDEFINED_VERIFICATION_STEPS,
  VERIFICATION_CASES,
  summarizeDevices,
  validateManifest,
} from '../public/operations.mjs';

const publicFile = path => new URL('../public/' + path.replace(/^\//u, ''), import.meta.url);

test('operations manifest describes implementation only and never invents 41 attack executions', async () => {
  const manifest = validateManifest(JSON.parse(await readFile(publicFile('/operations-manifest.json'), 'utf8')));
  assert.deepEqual(manifest.implementation.decider.ruleIds, [...RULE_IDS]);
  assert.deepEqual(manifest.implementation.decider.outcomes, ['allow', 'deny', 'step_up']);
  assert.deepEqual(manifest.implementation.detection.windowSeconds, DETECTION_CONTRACT.windowSeconds);
  assert.deepEqual(manifest.implementation.detection.readLimit, DETECTION_CONTRACT.readLimit);
  assert.equal(manifest.implementation.detection.action, 'propose_revocation');
  assert.equal(manifest.attackCatalog.expectedCount, 41);
  assert.equal(manifest.attackCatalog.officialIdentifiersAvailable, false);
  assert.deepEqual(manifest.attackCatalog.executions, []);
  assert.equal(manifest.judgeRecord.status, 'user_reported');
});

test('every stage 1-11 is represented without fabricating unavailable HTTP definitions', () => {
  assert.deepEqual(UNDEFINED_VERIFICATION_STEPS, [1, 2, 5, 6, 7, 8, 9]);
  assert.equal(VERIFICATION_CASES.length, 10);
  assert.deepEqual(
    [...new Set([...VERIFICATION_CASES.map(record => record.step), ...UNDEFINED_VERIFICATION_STEPS])].sort((a, b) => a - b),
    Array.from({ length: 11 }, (_, i) => i + 1),
  );
});

test('device observations contain state counts only, not protected device identifiers', () => {
  const summary = summarizeDevices({ devices: [
    { id: 'private-device-row', credentialId: 'private-credential', fingerprint: 'private-fingerprint', state: 'approved' },
    { id: 'another-device-row', state: 'pending' },
  ] });
  assert.deepEqual(summary, {
    total: 2,
    states: { pending: 1, approved: 1, rejected: 0, revoked: 0 },
  });
  assert.doesNotMatch(JSON.stringify(summary), /private|credential|fingerprint|\bid\b/iu);
  assert.throws(() => summarizeDevices({ devices: [{ state: 'unknown' }] }), /INVALID_DEVICE_SUMMARY/u);
});

test('operational, deployment, and failure observations remain distinct', () => {
  const production = 'https://choi-bujang-secret-vault-pink.vercel.app';
  const signed = protectedReadObservation({
    httpStatus: 200, checkedAt: '2026-10-18T00:00:00.000Z', origin: production, configuredOrigin: production,
    serverRequestId: 'trace-signed-200',
  });
  assert.equal(signed.status, STATUS.operationalObserved);
  assert.equal(signed.requestId, 'trace-signed-200');
  assert.equal(protectedReadObservation({
    httpStatus: 200, origin: production, configuredOrigin: production,
    serverRequestId: 'contains spaces and private data',
  }).requestId, null);
  assert.equal(protectedReadObservation({
    httpStatus: 200, checkedAt: '2026-10-18T00:00:00.000Z', origin: 'https://preview.example.test', configuredOrigin: production,
  }).status, STATUS.deploymentObserved);
  assert.deepEqual(operationFailure(503), {
    status: STATUS.verificationFailed, httpStatus: 503, requestId: null,
  });
});

test('operations source and UI retain approval gate and avoid protected-content storage', async () => {
  const [ui, source] = await Promise.all([
    readFile(publicFile('/index.html'), 'utf8'),
    readFile(publicFile('/operations.mjs'), 'utf8'),
  ]);
  assert.match(ui, /id="operations-room"[^>]*hidden/u);
  assert.match(ui, /byteback:operations-access/u);
  assert.match(ui, /byteback:operations-hidden/u);
  assert.match(ui, /src="\/operations\.mjs"/u);
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/u);
  assert.match(source, /fetch\('\/api\/memos', \{\s*method: 'GET', credentials: 'omit'/u,
    'the only operations memo request is the user-clicked cookie-free GET check');
  assert.doesNotMatch(source, /fetch\('\/api\/memos', \{\s*method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/u);
  assert.match(source, /\/api\/devices/u);
  assert.match(source, /requestId: null/u);
});
