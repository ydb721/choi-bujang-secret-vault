import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createOperationsRoom } from '../public/operations.mjs';

class Node {
  constructor() {
    this.children = [];
    this.disabled = false;
    this.hidden = false;
    this.textContent = '';
    this.listeners = new Map();
  }

  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  click() { this.listeners.get('click')?.(); }
}

const deferred = () => {
  let resolve;
  const promise = new Promise(value => { resolve = value; });
  return { promise, resolve };
};

const response = (status, body, traceId = null) => ({
  status, ok: status >= 200 && status < 300,
  headers: { get: name => name.toLowerCase() === 'x-byteback-trace' ? traceId : null },
  json: async () => body,
});
const settle = async () => { await Promise.resolve(); await Promise.resolve(); };
const text = node => node.textContent + node.children.map(text).join('');

function roomFixture() {
  const nodes = new Map([
    ['#operations-refresh', new Node()],
    ['#operations-unauthenticated-check', new Node()],
    ['#operations-feedback', new Node()],
    ['#operations-list', new Node()],
    ['#verification-summary', new Node()],
    ['#verification-table-body', new Node()],
  ]);
  const root = new Node();
  root.querySelector = selector => nodes.get(selector) ?? null;
  return { root, nodes };
}

test('a cleared or replaced operations session ignores delayed manifest, verification, and refresh responses', async () => {
  const manifest = JSON.parse(await readFile(new URL('../public/operations-manifest.json', import.meta.url), 'utf8'));
  const previous = { document: globalThis.document, window: globalThis.window, fetch: globalThis.fetch };
  const delayedManifest = deferred();
  const delayedMemo = deferred();
  const delayedAleph = deferred();
  const delayedDevices = deferred();
  let manifestCalls = 0;
  globalThis.document = { createElement: () => new Node() };
  globalThis.window = { location: { origin: manifest.deployment.publicOrigin } };
  globalThis.fetch = path => {
    if (path === '/operations-manifest.json') {
      ++manifestCalls;
      return manifestCalls === 1 ? delayedManifest.promise : Promise.resolve(response(200, manifest));
    }
    if (path === '/api/memos') return delayedMemo.promise;
    if (path === '/aleph.json') return delayedAleph.promise;
    if (path === '/api/devices') return delayedDevices.promise;
    throw new Error('UNEXPECTED_FETCH_' + path);
  };

  try {
    const { root, nodes } = roomFixture();
    const room = createOperationsRoom(root);
    const first = { httpStatus: 200, checkedAt: '2026-10-18T00:00:00.000Z' };

    room.allow(first);
    room.clear();
    delayedManifest.resolve(response(200, manifest));
    await settle();
    assert.equal(root.hidden, true);
    assert.equal(nodes.get('#operations-feedback').textContent, '');
    assert.equal(nodes.get('#verification-table-body').children.length, 0);

    room.allow(first);
    await settle();
    nodes.get('#operations-unauthenticated-check').click();
    room.clear();
    room.allow({ httpStatus: 200, checkedAt: '2026-10-18T00:01:00.000Z' });
    delayedMemo.resolve(response(401, { error: 'AUTH_REQUIRED' }));
    await settle();
    assert.match(text(nodes.get('#verification-table-body')), /approved_signed_memo_list/u);
    assert.match(nodes.get('#verification-summary').textContent, /실제 HTTP 응답 기록 1건/u);
    assert.doesNotMatch(text(nodes.get('#verification-table-body')), /user_requested_credentials_omit_get/u,
      'a prior session cannot restore its delayed 401 verification record');

    nodes.get('#operations-refresh').click();
    room.clear();
    room.allow({ httpStatus: 200, checkedAt: '2026-10-18T00:02:00.000Z' });
    delayedAleph.resolve(response(200, { step: 12, commit: 'a'.repeat(40) }));
    delayedDevices.resolve(response(200, { devices: [{ state: 'approved' }] }));
    await settle();
    assert.doesNotMatch(text(nodes.get('#operations-list')), /aaaaaaaaaaaa/u,
      'a prior session cannot restore delayed deployment or device state');
  } finally {
    globalThis.document = previous.document;
    globalThis.window = previous.window;
    globalThis.fetch = previous.fetch;
  }
});

test('operations records the real trace header for signed 200 and unauthenticated 401 observations', async () => {
  const manifest = JSON.parse(await readFile(new URL('../public/operations-manifest.json', import.meta.url), 'utf8'));
  const previous = { document: globalThis.document, window: globalThis.window, fetch: globalThis.fetch };
  globalThis.document = { createElement: () => new Node() };
  globalThis.window = { location: { origin: manifest.deployment.publicOrigin } };
  globalThis.fetch = path => {
    if (path === '/operations-manifest.json') return Promise.resolve(response(200, manifest));
    if (path === '/api/memos') {
      return Promise.resolve(response(401, { error: 'AUTH_REQUIRED' }, 'trace-unauthenticated-401'));
    }
    throw new Error('UNEXPECTED_FETCH_' + path);
  };

  try {
    const { root, nodes } = roomFixture();
    const room = createOperationsRoom(root);
    room.allow({ httpStatus: 200, checkedAt: '2026-10-18T00:00:00.000Z',
      serverRequestId: 'trace-signed-200' });
    await settle();
    await settle();
    assert.match(text(nodes.get('#verification-table-body')), /trace-signed-200/u);
    assert.match(text(nodes.get('#operations-list')), /서버 제공 요청 ID trace-signed-200/u);
    assert.match(text(nodes.get('#verification-table-body')), /1 · 시험 정의 미확인/u);
    assert.match(nodes.get('#verification-summary').textContent, /시험 정의 미확인 7개 단계/u);

    nodes.get('#operations-unauthenticated-check').click();
    await settle();
    await settle();
    const table = text(nodes.get('#verification-table-body'));
    assert.match(table, /HTTP 401 · AUTH_REQUIRED/u);
    assert.match(table, /trace-unauthenticated-401/u);
    assert.match(nodes.get('#verification-summary').textContent, /실제 HTTP 응답 기록 2건 · 통과 2건/u);

    room.clear();
    assert.equal(nodes.get('#verification-table-body').children.length, 0);
  } finally {
    globalThis.document = previous.document;
    globalThis.window = previous.window;
    globalThis.fetch = previous.fetch;
  }
});
