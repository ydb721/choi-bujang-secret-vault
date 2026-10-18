import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import {
  UNDEFINED_VERIFICATION_STEPS,
  VERIFICATION_CASES,
  compareVerification,
  recordVerification,
} from '../public/operations.mjs';

const approvedRead = VERIFICATION_CASES.find(value => value.testId === 'approved_signed_memo_list');
const unsigned = VERIFICATION_CASES.find(value => value.testId === 'unsigned_protected_request');
const unauthenticated = VERIFICATION_CASES.find(value => value.testId === 'unauthenticated_memo_list');

test('a verification record requires an actual HTTP response and keeps client and server IDs distinct', () => {
  assert.throws(() => recordVerification(approvedRead, {}, { clientCaseId: 'case-1' }), /HTTP_RESPONSE_REQUIRED/u);
  const record = recordVerification(approvedRead, {
    httpStatus: 200, errorCode: 'UNTRUSTED_SERVER_TEXT', serverRequestId: 'server-request-7',
    serverObservedAt: '2026-10-18T01:02:03.000Z', environment: 'operational', source: 'approved_signed_fetch',
  }, {
    clientCaseId: 'case-1', executedAt: '2026-10-18T01:02:02.000Z', confirmedAt: '2026-10-18T01:02:04.000Z',
  });
  assert.equal(record.passed, true);
  assert.equal(record.serverRequestId, 'server-request-7');
  assert.equal(record.clientCaseId, 'case-1');
  assert.equal(record.actualErrorCode, null, 'unknown response text is never retained as an error code');
  assert.equal(record.serverObservedAt, '2026-10-18T01:02:03.000Z');
  assert.equal(recordVerification(approvedRead, {
    httpStatus: 200, serverRequestId: 'not a safe request id', errorCode: null,
  }, { clientCaseId: 'case-2' }).serverRequestId, null);
  assert.equal(recordVerification(approvedRead, {
    httpStatus: 200, errorCode: null,
  }, { clientCaseId: 'case-3' }).serverRequestId, null);
});

test('normal success and documented prohibited-request rejection have separate pass rules', () => {
  assert.deepEqual(compareVerification(approvedRead, { httpStatus: 200, errorCode: null }), { state: 'passed', passed: true });
  assert.deepEqual(compareVerification(unsigned, { httpStatus: 403, errorCode: 'DEVICE_SIGNATURE_REQUIRED' }), { state: 'passed', passed: true });
  assert.deepEqual(compareVerification(unsigned, { httpStatus: 403, errorCode: null }), { state: 'failed', passed: false });
  assert.deepEqual(compareVerification(unsigned, { httpStatus: 503, errorCode: 'DEVICE_SIGNATURE_REQUIRED' }), { state: 'verification_failed', passed: false });
  assert.deepEqual(compareVerification(unauthenticated, { httpStatus: 401, errorCode: 'AUTH_REQUIRED' }), { state: 'passed', passed: true });
  assert.deepEqual(compareVerification(unauthenticated, { httpStatus: 401, errorCode: null }), { state: 'failed', passed: false });
});

test('unexecuted and undefined candidates cannot contribute to a pass count', () => {
  const definedButUnexecuted = VERIFICATION_CASES.find(value => value.testId === 'foreign_memo_scope');
  assert.deepEqual(compareVerification(definedButUnexecuted, null), { state: 'not_run', passed: false });
  assert.equal(VERIFICATION_CASES.some(value => value.testId === 'allowed_route_scope'), false);
  assert.equal(UNDEFINED_VERIFICATION_STEPS.includes(5), true);
});

test('verification UI uses generalized paths and clears protected records with the operations room', async () => {
  const [source, html, procedure] = await Promise.all([
    readFile(new URL('../public/operations.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../public/index.html', import.meta.url), 'utf8'),
    readFile(new URL('../docs/OPERATIONS_VERIFICATION.md', import.meta.url), 'utf8'),
  ]);
  assert.match(html, /id="verification-table-body"/u);
  assert.match(source, /verificationRecords = \[\]/u);
  assert.match(source, /serverRequestId: safeRequestId/u);
  assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/u);
  assert.match(html, /id="operations-unauthenticated-check"/u);
  assert.match(source, /fetch\('\/api\/memos', \{\s*method: 'GET', credentials: 'omit'/u);
  assert.match(source, /response\.headers\.get\('x-byteback-trace'\)/u);
  assert.doesNotMatch(source, /response\.headers\.get\('x-request-id'\)/u);
  assert.match(html, /serverRequestId:\s*response\.headers\.get\('x-byteback-trace'\)/u);
  assert.match(source, /통과로 기록하지 않았습니다/u);
  assert.match(procedure, /공식 41종 공격/u);
  assert.match(procedure, /운영에서는 승인 기기의 기존 읽기 전용 자료 조회만/u);
});
