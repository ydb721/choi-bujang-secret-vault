import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = Object.freeze({
  step: 12,
  publicAppUrl: 'https://student-defense.vercel.app',
  originalApiUrl: 'https://fixture.supabase.co/rest/v1/memos',
});

const urls = Object.freeze([
  'https://student-defense.vercel.app/api/memos',
  'https://student-defense.vercel.app/api/memos/11111111-1111-4111-8111-111111111111',
  'https://student-defense.vercel.app/data.json',
  'https://student-defense.vercel.app/aleph.json',
  'https://fixture.supabase.co/rest/v1/memos',
]);

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json' },
  });
}

function byId(results) {
  return new Map(results.map(result => [result.attackId, result.observed]));
}

test('A: fetch sees five URL strings and five explicit GET calls', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (input, init) => {
      calls.push({ type: input?.constructor?.name, url: String(input), method: init?.method });
      return jsonResponse(401, { error: 'AUTH_REQUIRED' });
    };
    const observed = byId(await runAttackChecks(config));
    assert.deepEqual(calls, urls.map(url => ({ type: 'String', url, method: 'GET' })));
    assert.equal(observed.get('unauthenticated_memo_list'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(observed.get('foreign_memo_scope'), 'not_run');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('B: a string-only tracer records all requests while fetch receives the same responses', async () => {
  const originalFetch = globalThis.fetch;
  let actualCalls = 0;
  const traced = [];
  try {
    globalThis.fetch = async (input, init) => {
      ++actualCalls;
      if (typeof input === 'string') traced.push({ url: input, method: init?.method });
      return jsonResponse(401, { error: 'AUTH_REQUIRED' });
    };
    const observed = byId(await runAttackChecks(config));
    assert.equal(actualCalls, 5);
    assert.deepEqual(traced, urls.map(url => ({ url, method: 'GET' })));
    assert.equal(observed.get('unauthenticated_memo_list'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(observed.get('unauthenticated_memo_item'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(observed.get('direct_no_key_probe'), 'HTTP 401; error=AUTH_REQUIRED');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('C: connection failures call fetch five times and leave all executed checks not_run', async () => {
  const originalFetch = globalThis.fetch;
  let actualCalls = 0;
  try {
    globalThis.fetch = async () => {
      ++actualCalls;
      throw new TypeError('network unavailable');
    };
    const results = await runAttackChecks(config);
    assert.equal(actualCalls, 5);
    assert.ok(results.every(result => result.observed === 'not_run'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('D: requests that start but reject before an HTTP response remain not_run', async () => {
  const originalFetch = globalThis.fetch;
  let started = 0;
  let responses = 0;
  try {
    globalThis.fetch = async () => {
      ++started;
      await Promise.resolve();
      throw new TypeError('connection closed before headers');
    };
    const results = await runAttackChecks(config);
    assert.equal(started, 5);
    assert.equal(responses, 0);
    assert.ok(results.every(result => result.observed === 'not_run'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('E: each HTTP response keeps its own status and actual JSON error only', async () => {
  const originalFetch = globalThis.fetch;
  const fixtures = new Map([
    [urls[0], jsonResponse(200, [])],
    [urls[1], jsonResponse(401, { error: 'AUTH_REQUIRED' })],
    [urls[2], jsonResponse(403, { error: 'FORBIDDEN' })],
    [urls[3], jsonResponse(404, { error: 'NOT_FOUND' })],
    [urls[4], jsonResponse(401, { message: 'No API key found' })],
  ]);
  try {
    globalThis.fetch = async input => fixtures.get(String(input));
    const observed = byId(await runAttackChecks(config));
    assert.equal(observed.get('unauthenticated_memo_list'), 'HTTP 200');
    assert.equal(observed.get('unauthenticated_memo_item'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(observed.get('static_memo_empty'),
      'HTTP 403; error=FORBIDDEN; static_memo_empty=false');
    assert.equal(observed.get('deployment_identity'),
      'HTTP 404; error=NOT_FOUND; deployment_identity_available=false');
    assert.equal(observed.get('direct_no_key_probe'), 'HTTP 401');
    assert.equal(observed.get('foreign_memo_scope'), 'not_run');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('one failed request does not erase the other four received responses', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async input => {
      const url = String(input);
      if (url === urls[2]) throw new TypeError('single request failed');
      return jsonResponse(401, { error: 'AUTH_REQUIRED' });
    };
    const observed = byId(await runAttackChecks(config));
    assert.equal(observed.get('static_memo_empty'), 'not_run');
    assert.equal(observed.get('unauthenticated_memo_list'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(observed.get('unauthenticated_memo_item'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(observed.get('deployment_identity'),
      'HTTP 401; error=AUTH_REQUIRED; deployment_identity_available=false');
    assert.equal(observed.get('direct_no_key_probe'), 'HTTP 401; error=AUTH_REQUIRED');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('redirect metadata and final response URL are not included in observed', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async input => ({
      status: 200,
      ok: true,
      redirected: true,
      url: String(input).replace('student-defense.vercel.app', 'redirected.example'),
      async json() { return {}; },
    });
    const observed = byId(await runAttackChecks(config));
    assert.equal(observed.get('deployment_identity'),
      'HTTP 200; deployment_identity_available=true');
    assert.ok(!observed.get('deployment_identity').includes('redirected.example'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
