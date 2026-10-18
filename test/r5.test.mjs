import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.deepEqual(options, { method: 'GET' });
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('isolated bundle checks use only GET and mark failed network requests as not_run', async () => {
  const originalFetch = globalThis.fetch;
  const originalTimeout = AbortSignal.timeout;
  const runtimeConfig = { ...config, step: 12,
    originalApiUrl: 'https://fixture.supabase.co/rest/v1/memos' };
  try {
    AbortSignal.timeout = undefined;
    globalThis.fetch = async (_url, init) => {
      assert.deepEqual(init, { method: 'GET' });
      throw new TypeError('isolated network unavailable');
    };
    const results = await runAttackChecks(runtimeConfig);
    assert.equal(results.length, 6);
    assert.ok(results.every(result => result.observed === 'not_run'));
  } finally {
    globalThis.fetch = originalFetch;
    AbortSignal.timeout = originalTimeout;
  }
});

test('stage 12 attack records preserve exact HTTP status and actual safe error codes', async () => {
  const originalFetch = globalThis.fetch;
  const runtimeConfig = { ...config, step: 12,
    originalApiUrl: 'https://fixture.supabase.co/rest/v1/memos' };
  const scenarios = [
    { status: 401, body: { error: 'AUTH_REQUIRED' }, expected: 'HTTP 401; error=AUTH_REQUIRED' },
    { status: 401, body: { error: 'OTHER_ERROR' }, expected: 'HTTP 401; error=OTHER_ERROR' },
    { status: 403, body: { error: 'FORBIDDEN' }, expected: 'HTTP 403; error=FORBIDDEN' },
    { status: 404, body: { error: 'NOT_FOUND' }, expected: 'HTTP 404; error=NOT_FOUND' },
    { status: 500, body: { error: 'SERVER_ERROR' }, expected: 'HTTP 500; error=SERVER_ERROR' },
    { status: 200, body: [], expected: 'HTTP 200' },
  ];
  try {
    for (const scenario of scenarios) {
      globalThis.fetch = async url => {
        const target = String(url);
        if (target.endsWith('/api/memos')) {
          return new Response(JSON.stringify(scenario.body), { status: scenario.status,
            headers: { 'content-type': 'application/json' } });
        }
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      };
      const results = await runAttackChecks(runtimeConfig);
      assert.equal(results.find(item => item.attackId === 'unauthenticated_memo_list').observed,
        scenario.expected);
      assert.equal(results.find(item => item.attackId === 'foreign_memo_scope').observed, 'not_run');
    }

    globalThis.fetch = async url => String(url).endsWith('/api/memos')
      ? new Response('<html>not json</html>', { status: 401, headers: { 'content-type': 'text/html' } })
      : new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    const nonJson = await runAttackChecks(runtimeConfig);
    assert.equal(nonJson.find(item => item.attackId === 'unauthenticated_memo_list').observed,
      'HTTP 401');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('each executed stage 12 public check records its own response without reusing another result', async () => {
  const originalFetch = globalThis.fetch;
  const runtimeConfig = { ...config, step: 12,
    originalApiUrl: 'https://fixture.supabase.co/rest/v1/memos' };
  try {
    globalThis.fetch = async url => {
      const target = String(url);
      if (target === 'https://student-defense.vercel.app/api/memos') {
        return new Response(JSON.stringify({ error: 'AUTH_REQUIRED' }), { status: 401 });
      }
      if (target.includes('/api/memos/')) {
        return new Response(JSON.stringify({ error: 'DEVICE_SIGNATURE_REQUIRED' }), { status: 403 });
      }
      if (target.endsWith('/data.json')) return new Response('not json', { status: 404 });
      if (target.endsWith('/aleph.json')) {
        return new Response(JSON.stringify({ error: 'SERVER_ERROR' }), { status: 500 });
      }
      return new Response('{}', { status: 200 });
    };
    const byId = new Map((await runAttackChecks(runtimeConfig))
      .map(result => [result.attackId, result.observed]));
    assert.equal(byId.get('unauthenticated_memo_list'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(byId.get('unauthenticated_memo_item'),
      'HTTP 403; error=DEVICE_SIGNATURE_REQUIRED');
    assert.equal(byId.get('foreign_memo_scope'), 'not_run');
    assert.equal(byId.get('static_memo_empty'), 'HTTP 404; static_memo_empty=true');
    assert.equal(byId.get('deployment_identity'),
      'HTTP 500; error=SERVER_ERROR; deployment_identity_available=false');
    assert.equal(byId.get('direct_no_key_probe'), 'HTTP 200');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 12 sends five distinct GET requests and records only received responses', async () => {
  const originalFetch = globalThis.fetch;
  const runtimeConfig = { ...config, step: 12,
    originalApiUrl: 'https://fixture.supabase.co/rest/v1/memos' };
  const calls = [];
  const responses = new Map([
    ['https://student-defense.vercel.app/api/memos', [401, 'AUTH_REQUIRED']],
    ['https://student-defense.vercel.app/api/memos/11111111-1111-4111-8111-111111111111',
      [401, 'AUTH_REQUIRED']],
    ['https://student-defense.vercel.app/data.json', [404, 'NOT_FOUND']],
    ['https://student-defense.vercel.app/aleph.json', [200, null]],
    ['https://fixture.supabase.co/rest/v1/memos', [403, 'FORBIDDEN']],
  ]);
  try {
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      calls.push({ url: href, method: init?.method });
      const [status, error] = responses.get(href);
      return new Response(JSON.stringify(error ? { error } : {}), { status,
        headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks(runtimeConfig);
    assert.deepEqual(calls, [...responses.keys()].map(url => ({ url, method: 'GET' })));
    const byId = new Map(results.map(result => [result.attackId, result.observed]));
    assert.equal(byId.get('unauthenticated_memo_list'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(byId.get('unauthenticated_memo_item'), 'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(byId.get('static_memo_empty'),
      'HTTP 404; error=NOT_FOUND; static_memo_empty=true');
    assert.equal(byId.get('deployment_identity'),
      'HTTP 200; deployment_identity_available=true');
    assert.equal(byId.get('direct_no_key_probe'), 'HTTP 403; error=FORBIDDEN');
    assert.equal(byId.get('foreign_memo_scope'), 'not_run');

    let callIndex = 0;
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      const index = callIndex++;
      assert.equal(init?.method, 'GET');
      if (index === 2) throw new TypeError('simulated send failure');
      const [status, error] = responses.get(href);
      return new Response(JSON.stringify(error ? { error } : {}), { status,
        headers: { 'content-type': 'application/json' } });
    };
    const withFailure = new Map((await runAttackChecks(runtimeConfig))
      .map(result => [result.attackId, result.observed]));
    assert.equal(withFailure.get('static_memo_empty'), 'not_run');
    assert.equal(withFailure.get('unauthenticated_memo_list'),
      'HTTP 401; error=AUTH_REQUIRED');
    assert.equal(withFailure.get('deployment_identity'),
      'HTTP 200; deployment_identity_available=true');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 10 deployment advertises its separate recovery route while preserving allowed routes', () => {
  const recoveryConfig = { ...config, step: 10,
    allowedRoutes: ['GET /api/memos'],
    originalApiUrl: 'https://fixture.supabase.co/rest/v1/memos',
    restoreRoute: '/api/restore/:id' };
  assert.equal(deploymentIdentity(env, recoveryConfig).restoreRoute, recoveryConfig.restoreRoute);
  assert.equal(deploymentIdentity(env, recoveryConfig).publicAppUrl, config.publicAppUrl);
  assert.deepEqual(deploymentIdentity(env, recoveryConfig).allowedRoutes, ['GET /api/memos']);
  assert.throws(() => deploymentIdentity(env, { ...recoveryConfig,
    restoreRoute: '/outside/restore/:id' }));
  assert.throws(() => deploymentIdentity(env, { ...recoveryConfig,
    restoreRoute: null }));
});

test('stage 10 public origin cannot contain credentials, another protocol or a path', () => {
  const recoveryConfig = { ...config, step: 10,
    allowedRoutes: ['GET /api/memos'],
    originalApiUrl: 'https://fixture.supabase.co/rest/v1/memos', restoreRoute: '/api/restore/:id' };
  for (const publicAppUrl of ['http://student-defense.vercel.app',
    'https://name:password@student-defense.vercel.app', 'https://student-defense.vercel.app/path',
    'https://student-defense.vercel.app/?query=1', 'https://student-defense.vercel.app/#fragment',
    'https://other.example.com']) {
    assert.throws(() => deploymentIdentity(env, { ...recoveryConfig, publicAppUrl }));
  }
});
