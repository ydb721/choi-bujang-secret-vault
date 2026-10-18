import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const ORIGIN = 'https://pwa.example.test';
const CACHE = 'byteback-public-v4';
const PUBLIC_PATHS = [
  '/offline.html',
  '/manifest.webmanifest',
  '/pwa.mjs',
  '/device.mjs',
  '/operations.mjs',
  '/operations-manifest.json',
  '/vendor/simplewebauthn-browser.js',
  '/vendor/simplewebauthn-browser.umd.js',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/apple-touch-icon.png',
];
const publicFile = path => new URL('../public/' + path.replace(/^\//u, ''), import.meta.url);
const swSource = await readFile(publicFile('/sw.js'), 'utf8');
const pwaSource = await readFile(publicFile('/pwa.mjs'), 'utf8');

function requestUrl(request) {
  return new URL(typeof request === 'string' ? request : request.url, ORIGIN).href;
}

function serviceWorker() {
  const listeners = new Map();
  const stores = new Map();
  const operations = [];
  const requests = [];
  let network = async request => {
    const response = new Response('network:' + requestUrl(request), {
      headers: { 'Content-Type': 'text/plain' },
    });
    Object.defineProperty(response, 'type', { value: 'basic' });
    return response;
  };
  const fetch = async (request, options = {}) => {
    requests.push({
      url: requestUrl(request), method: options.method ?? request.method ?? 'GET',
      credentials: options.credentials ?? request.credentials,
      cache: options.cache ?? request.cache, redirect: options.redirect ?? request.redirect,
    });
    return network(request, options);
  };
  const open = async name => {
    if (!stores.has(name)) stores.set(name, new Map());
    const entries = stores.get(name);
    return {
      async match(request) {
        const url = requestUrl(request);
        operations.push({ kind: 'match', name, url });
        return entries.get(url)?.clone();
      },
      async put(request, response) {
        const url = requestUrl(request);
        operations.push({ kind: 'put', name, url });
        entries.set(url, response.clone());
      },
      async addAll(paths) {
        const responses = await Promise.all(paths.map(path => fetch(path)));
        for (let index = 0; index < paths.length; index++) {
          assert.equal(responses[index].ok, true);
          await this.put(paths[index], responses[index]);
        }
      },
      async keys() { return [...entries.keys()].map(url => new Request(url)); },
    };
  };
  const caches = {
    open,
    async keys() { return [...stores.keys()]; },
    async delete(name) { return stores.delete(name); },
    async match(request) {
      for (const name of stores.keys()) {
        const result = await (await open(name)).match(request);
        if (result) return result;
      }
      return undefined;
    },
  };
  const self = {
    location: new URL('/sw.js', ORIGIN),
    clients: { async claim() {} },
    async skipWaiting() {},
    addEventListener(type, callback) { listeners.set(type, callback); },
  };
  vm.runInNewContext(swSource, {
    self, caches, fetch, URL, Request, Response, Headers, console,
  }, { filename: 'public/sw.js', timeout: 1000 });

  async function dispatch(type, fields = {}) {
    const pending = [];
    let response;
    listeners.get(type)?.({
      ...fields,
      waitUntil(value) { pending.push(Promise.resolve(value)); },
      respondWith(value) {
        assert.equal(response, undefined, 'respondWith must be called once');
        response = Promise.resolve(value);
      },
    });
    const result = type === 'fetch'
      ? await (response ?? fetch(fields.request)) : undefined;
    await Promise.all(pending);
    return result;
  }
  return {
    stores, operations, requests,
    setNetwork(callback) { network = callback; },
    dispatch,
    async seed(name, path, body = 'seeded-cache') {
      await (await open(name)).put(path, new Response(body));
    },
    async fetch(path, { method = 'GET', mode = 'cors', headers = {}, cache = 'default' } = {}) {
      return dispatch('fetch', { request: {
        url: new URL(path, ORIGIN).href, method, mode,
        headers: new Headers(headers), cache, destination: mode === 'navigate' ? 'document' : '',
      } });
    },
    resetLog() { operations.length = 0; requests.length = 0; },
  };
}

test('PWA manifest and real PNG files provide install metadata', async () => {
  const manifest = JSON.parse(await readFile(publicFile('/manifest.webmanifest'), 'utf8'));
  assert.match(manifest.name, /BYTE\s*BACK/iu);
  assert.ok(manifest.short_name?.length);
  assert.equal(manifest.display, 'standalone');
  assert.equal(manifest.start_url, '/');
  assert.equal(manifest.scope, '/');
  for (const size of [192, 512]) {
    const entry = manifest.icons.find(icon => icon.sizes === `${size}x${size}` && icon.type === 'image/png');
    assert.ok(entry, `${size}px PNG icon must be declared`);
    const bytes = await readFile(publicFile(entry.src));
    assert.deepEqual(bytes.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    assert.equal(bytes.toString('ascii', 12, 16), 'IHDR');
    assert.equal(bytes.readUInt32BE(16), size);
    assert.equal(bytes.readUInt32BE(20), size);
  }
  const appleIcon = await readFile(publicFile('/icons/apple-touch-icon.png'));
  assert.equal(appleIcon.toString('ascii', 12, 16), 'IHDR');
  assert.ok(appleIcon.readUInt32BE(16) >= 180);
  assert.equal(appleIcon.readUInt32BE(16), appleIcon.readUInt32BE(20));
  const index = await readFile(publicFile('/index.html'), 'utf8');
  const tags = index.match(/<(?:link|script)\b[^>]*>/giu) ?? [];
  assert.ok(tags.some(tag => /rel=["']manifest["']/iu.test(tag)
    && /href=["']\/manifest\.webmanifest["']/u.test(tag)));
  assert.ok(tags.some(tag => /type=["']module["']/iu.test(tag)
    && /src=["']\/pwa\.mjs["']/u.test(tag)));
  assert.ok(tags.some(tag => /type=["']module["']/iu.test(tag)
    && /src=["']\/operations\.mjs["']/u.test(tag)));
  assert.match(index, /기기 승인 미확인/u);
});

test('pinned WebAuthn vendor bytes and license match and the real ESM wrapper exports browser functions', async () => {
  const [projectText, packageText, installedBundle, deployedBundle, installedLicense, deployedLicense, wrapperSource] = await Promise.all([
    readFile(new URL('../package.json', import.meta.url), 'utf8'),
    readFile(new URL('../node_modules/@simplewebauthn/browser/package.json', import.meta.url), 'utf8'),
    readFile(new URL('../node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js', import.meta.url)),
    readFile(publicFile('/vendor/simplewebauthn-browser.umd.js')),
    readFile(new URL('../node_modules/@simplewebauthn/browser/LICENSE.md', import.meta.url)),
    readFile(publicFile('/vendor/simplewebauthn-LICENSE.md')),
    readFile(publicFile('/vendor/simplewebauthn-browser.js'), 'utf8'),
  ]);
  assert.equal(JSON.parse(projectText).dependencies['@simplewebauthn/browser'], '14.0.0');
  const installed = JSON.parse(packageText);
  assert.equal(installed.version, '14.0.0');
  assert.equal(installed.license, 'MIT');
  assert.deepEqual(deployedBundle, installedBundle, 'the vendored UMD must be an unchanged package copy');
  assert.deepEqual(deployedLicense, installedLicense, 'the complete upstream license must be preserved');
  assert.match(deployedBundle.toString('utf8'), /^\/\* \[@simplewebauthn\/browser@14\.0\.0\] \*\//u);

  // Browser window and globalThis refer to the same global object. Evaluate the
  // actual files as ESM, without replacing the UMD with a test module double.
  let ceremonies = 0;
  const context = vm.createContext({
    AbortController,
    navigator: { credentials: {
      create() { ++ceremonies; throw new Error('loading modules must not start a registration'); },
      get() { ++ceremonies; throw new Error('loading modules must not start an authentication'); },
    } },
  });
  vm.runInContext('globalThis.window = globalThis; globalThis.self = globalThis;', context);
  const umd = new vm.SourceTextModule(deployedBundle.toString('utf8'), {
    context, identifier: ORIGIN + '/vendor/simplewebauthn-browser.umd.js',
  });
  const wrapper = new vm.SourceTextModule(wrapperSource, {
    context, identifier: ORIGIN + '/vendor/simplewebauthn-browser.js',
  });
  await wrapper.link(specifier => {
    assert.equal(specifier, './simplewebauthn-browser.umd.js');
    return umd;
  });
  await wrapper.evaluate({ timeout: 1000 });
  for (const name of ['startRegistration', 'startAuthentication']) {
    assert.equal(typeof wrapper.namespace[name], 'function', name + ' must be a real exported function');
    assert.equal(wrapper.namespace[name], context.SimpleWebAuthnBrowser[name]);
  }
  assert.equal(ceremonies, 0, 'module loading does not authenticate or imply device approval');
});

test('install precaches only the explicit public files and activation preserves unrelated caches', async () => {
  const worker = serviceWorker();
  await worker.dispatch('install');
  assert.deepEqual(worker.requests.map(request => new URL(request.url).pathname).sort(), [...PUBLIC_PATHS].sort());
  assert.ok(worker.requests.every(request => request.credentials === 'omit'
    && request.cache === 'reload' && request.redirect === 'error'));
  assert.deepEqual([...worker.stores.keys()], [CACHE]);
  assert.deepEqual([...worker.stores.get(CACHE).keys()].map(url => new URL(url).pathname).sort(), [...PUBLIC_PATHS].sort());
  await worker.seed('byteback-public-v0', '/offline.html');
  await worker.seed('unrelated-app-cache', '/unrelated');
  await worker.seed('byteback-private-data', '/unrelated');
  await worker.dispatch('activate');
  assert.deepEqual([...worker.stores.keys()].sort(), [CACHE, 'unrelated-app-cache', 'byteback-private-data'].sort());
});

test('same-origin public assets can be read from cache without contacting the network', async () => {
  const worker = serviceWorker();
  await worker.dispatch('install');
  worker.setNetwork(async () => { throw new TypeError('simulated offline'); });
  worker.resetLog();
  for (const path of PUBLIC_PATHS) {
    const response = await worker.fetch(path);
    assert.equal(response.ok, true, path);
  }
  assert.equal(worker.requests.length, 0);
  assert.ok(worker.operations.every(operation => PUBLIC_PATHS.includes(new URL(operation.url).pathname)));
});

test('a public cache miss uses a fixed URL and omits request credentials', async () => {
  const worker = serviceWorker();
  const response = await worker.fetch('/offline.html');
  assert.equal(response.ok, true);
  assert.equal(worker.requests.length, 1);
  assert.equal(worker.requests[0].url, ORIGIN + '/offline.html');
  assert.equal(worker.requests[0].credentials, 'omit');
  assert.equal(worker.requests[0].cache, 'reload');
  assert.equal(worker.requests[0].redirect, 'error');
  assert.deepEqual([...worker.stores.get(CACHE).keys()], [ORIGIN + '/offline.html']);
});

test('failed, redirected and private public responses are never persisted', async () => {
  for (const properties of [
    { status: 401 }, { status: 403 }, { redirected: true }, { type: 'opaque' },
    { headers: { 'Cache-Control': 'no-store' } }, { headers: { 'Cache-Control': 'private' } },
    { headers: { 'Set-Cookie': 'fixture=example; Secure' } },
  ]) {
    const worker = serviceWorker();
    worker.setNetwork(async () => {
      const response = new Response('fixture response', {
        status: properties.status ?? 200, headers: properties.headers,
      });
      Object.defineProperty(response, 'type', { value: properties.type ?? 'basic' });
      if (properties.redirected) Object.defineProperty(response, 'redirected', { value: true });
      return response;
    });
    await worker.fetch('/offline.html').catch(error => {
      assert.ok(error instanceof Error || typeof error?.message === 'string');
    });
    assert.equal(worker.operations.filter(operation => operation.kind === 'put').length, 0);
  }
});

test('API methods, auth paths, external URLs, query strings and online documents are network-only', async () => {
  const worker = serviceWorker();
  await worker.dispatch('install');
  const cases = [
    ...['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].map(method => ['/api/memos', { method }]),
    ['/api', {}], ['/api/auth', {}], ['/api/backup', {}], ['/api/restore/fixture', {}],
    ['/api/devices', {}], ['/api/devices', { method: 'POST' }],
    ['/auth/callback', {}], ['/login', {}], ['/logout', {}],
    ['https://external.example.test/offline.html', {}],
    ['/offline.html?access_token=fixture.jwt.value', {}],
    ['/manifest.webmanifest?jwt=fixture.jwt.value', {}],
    ['/icons/icon-192.png?v=1', {}],
    ['/pwa.mjs', { method: 'POST' }],
    ['/pwa.mjs', { headers: { Authorization: 'Bearer fixture.jwt.value' } }],
    ['/pwa.mjs', { headers: { Cookie: 'fixture=example' } }],
    ['/device.mjs', { headers: { 'X-Byteback-Proof': 'synthetic-public-proof' } }],
    ['/offline.html', { cache: 'no-store' }],
    ['/offline.html', { headers: { 'Cache-Control': 'no-store' } }],
    ['/', { mode: 'navigate' }], ['/index.html', { mode: 'navigate' }],
  ];
  // Poisoned entries model an old cache. They must never satisfy protected requests.
  for (const [path] of cases) await worker.seed(CACHE, path, 'must-not-be-served');
  worker.resetLog();
  for (const [path, options] of cases) {
    const response = await worker.fetch(path, options);
    assert.equal(await response.text(), 'network:' + new URL(path, ORIGIN).href, path);
  }
  assert.equal(worker.requests.length, cases.length);
  assert.deepEqual(worker.operations, [], 'network-only requests must not read or write Cache Storage');
});

test('offline fallback is limited to root and index document navigations', async () => {
  const worker = serviceWorker();
  await worker.dispatch('install');
  await worker.seed(CACHE, '/offline.html', 'public offline 안내');
  worker.setNetwork(async () => { throw new TypeError('simulated offline'); });
  worker.resetLog();
  for (const path of ['/', '/index.html']) {
    assert.equal(await (await worker.fetch(path, { mode: 'navigate' })).text(), 'public offline 안내');
  }
  for (const options of [
    { headers: { Cookie: 'fixture=example' } },
    { headers: { Authorization: 'Bearer fixture.jwt.value' } },
    { cache: 'no-store' },
  ]) {
    worker.resetLog();
    const response = await worker.fetch('/', { mode: 'navigate', ...options });
    assert.equal(await response.text(), 'public offline 안내');
    assert.ok(worker.operations.every(operation => operation.kind === 'match'
      && new URL(operation.url).pathname === '/offline.html'));
  }
  for (const [path, options] of [
    ['/api/memos', {}], ['/api/auth', {}], ['/api/restore/fixture', { method: 'POST' }],
    ['/auth/callback', { mode: 'navigate' }], ['/other-page', { mode: 'navigate' }],
    ['/', {}], ['/index.html', {}],
    ['https://external.example.test/', { mode: 'navigate' }],
  ]) {
    worker.resetLog();
    await assert.rejects(worker.fetch(path, options), /simulated offline/u, path);
    assert.deepEqual(worker.operations, [], path + ' must not receive offline HTML');
  }
});

test('HTTP denials are preserved rather than replaced by the offline page', async () => {
  const worker = serviceWorker();
  await worker.dispatch('install');
  for (const status of [401, 403, 500]) {
    worker.setNetwork(async () => new Response('fixture denial', { status }));
    for (const path of ['/', '/index.html', '/api/memos']) {
      const response = await worker.fetch(path, { mode: 'navigate' });
      assert.equal(response.status, status);
      assert.equal(await response.text(), 'fixture denial');
    }
  }
});

function eventTarget(initial = {}) {
  const listeners = new Map();
  return {
    ...initial,
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(callback);
    },
    removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
    dispatchEvent(event) {
      for (const callback of listeners.get(event.type) ?? []) callback(event);
      return true;
    },
    async emit(type, fields = {}) {
      const event = { type, preventDefault() { this.defaultPrevented = true; }, ...fields };
      await Promise.all([...(listeners.get(type) ?? [])].map(callback => callback(event)));
      return event;
    },
  };
}

async function pwaPage({ standalone = false, swSupported = true } = {}) {
  const nodes = new Map([
    ['#pwa-install', eventTarget({ hidden: true, disabled: false, textContent: '' })],
    ['#pwa-install-status', eventTarget({ textContent: '' })],
    ['#device-approval-status', eventTarget({ textContent: '기기 승인 미확인' })],
    ['#network-status', eventTarget({ textContent: '' })],
    ['#connection-retry', eventTarget({ hidden: true, disabled: false, textContent: '' })],
  ]);
  const document = eventTarget({
    readyState: 'complete',
    querySelector(selector) { return nodes.get(selector) ?? null; },
    getElementById(id) { return nodes.get('#' + id) ?? null; },
  });
  const media = eventTarget({ matches: standalone });
  const registrations = [];
  const registration = { installing: null, waiting: null, active: {}, async update() {} };
  const navigator = {
    onLine: true,
    standalone: false,
    ...(swSupported ? { serviceWorker: eventTarget({
      async register(...args) { registrations.push(args); return registration; },
    }) } : {}),
  };
  let storageAccesses = 0;
  const forbiddenStorage = new Proxy({}, {
    get() { storageAccesses++; throw new Error('installation must not access identity storage'); },
    set() { storageAccesses++; throw new Error('installation must not write identity storage'); },
  });
  let reloads = 0;
  const location = { protocol: 'https:', hostname: 'pwa.example.test', reload() { reloads++; } };
  const window = eventTarget({
    navigator, document, location, isSecureContext: true,
    matchMedia() { return media; },
    localStorage: forbiddenStorage, sessionStorage: forbiddenStorage, indexedDB: forbiddenStorage,
  });
  vm.runInNewContext(pwaSource, {
    window, document, navigator, location, isSecureContext: true,
    matchMedia: window.matchMedia,
    localStorage: forbiddenStorage, sessionStorage: forbiddenStorage, indexedDB: forbiddenStorage,
    URL, console, setTimeout, clearTimeout,
  }, { filename: 'public/pwa.mjs', timeout: 1000 });
  await window.emit('load');
  await Promise.resolve();
  return { window, nodes, navigator, media, registrations,
    storageAccesses: () => storageAccesses, reloads: () => reloads };
}

test('install prompt and appinstalled never grant device approval or write browser identity storage', async () => {
  const page = await pwaPage();
  assert.equal(page.registrations.length, 1);
  assert.equal(page.registrations[0][0], '/sw.js');
  assert.equal(page.registrations[0][1]?.scope, '/');
  assert.equal(page.registrations[0][1]?.updateViaCache, 'none');
  const install = page.nodes.get('#pwa-install');
  assert.equal(install.hidden, true);
  let prompts = 0;
  const event = await page.window.emit('beforeinstallprompt', {
    async prompt() { prompts++; },
    userChoice: Promise.resolve({ outcome: 'accepted' }),
  });
  assert.equal(event.defaultPrevented, true);
  assert.equal(install.hidden, false);
  await install.emit('click');
  assert.equal(prompts, 1);
  assert.match(page.nodes.get('#pwa-install-status').textContent, /설치.*(?:요청|보냈|진행)/u);
  const requestedStatus = page.nodes.get('#pwa-install-status').textContent;
  assert.equal(page.nodes.get('#device-approval-status').textContent, '기기 승인 미확인');
  await page.window.emit('appinstalled');
  assert.equal(install.hidden, true);
  assert.notEqual(page.nodes.get('#pwa-install-status').textContent, requestedStatus);
  assert.equal(page.nodes.get('#device-approval-status').textContent, '기기 승인 미확인');
  assert.equal(page.storageAccesses(), 0);
});

test('standalone, unsupported browsers and offline status retain an unverified device state', async () => {
  for (const options of [{ standalone: true }, { swSupported: false }]) {
    const page = await pwaPage(options);
    assert.equal(page.nodes.get('#pwa-install').hidden, true);
    assert.equal(page.nodes.get('#device-approval-status').textContent, '기기 승인 미확인');
    page.navigator.onLine = false;
    await page.window.emit('offline');
    assert.match(page.nodes.get('#network-status').textContent, /오프라인|연결.*(?:없|끊)/u);
    assert.equal(page.nodes.get('#connection-retry').hidden, false);
    assert.equal(page.nodes.get('#connection-retry').disabled, true);
    page.navigator.onLine = true;
    await page.window.emit('online');
    assert.equal(page.nodes.get('#connection-retry').hidden, false);
    assert.equal(page.nodes.get('#connection-retry').disabled, false);
    await page.nodes.get('#connection-retry').emit('click');
    assert.equal(page.reloads(), 1);
    assert.equal(page.storageAccesses(), 0);
  }
});

// The real inline ESM is linked to an explicit device-module test double.
// The separate device UI suite executes the real device.mjs with virtual WebAuthn.
// Neither suite exercises browser rendering, real credentials or a judge.
async function inlinePage({ authenticated = false, approved = true } = {}) {
  const html = await readFile(publicFile('/index.html'), 'utf8');
  const source = html.match(/<script\s+type="module">([\s\S]*?)<\/script>/u)?.[1];
  assert.ok(source, 'the existing inline application module must exist');
  function element() {
    const node = eventTarget({ value: '', hidden: false, disabled: false, children: [] });
    let text = '';
    Object.defineProperty(node, 'textContent', {
      get() { return text + node.children.map(child => child.textContent).join(''); },
      set(value) { text = String(value); node.children = []; },
    });
    node.append = (...children) => node.children.push(...children);
    node.replaceChildren = (...children) => { text = ''; node.children = children; };
    node.scrollIntoView = () => {};
    node.requestSubmit = () => node.emit('submit');
    node.reset = () => {};
    node.setAttribute = () => {};
    return node;
  }
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/gu)].map(([, id]) => ['#' + id, element()]));
  const get = id => nodes.get('#' + id);
  get('memo-editor').reset = () => { get('memo-title').value = ''; get('memo-body').value = ''; };
  const navigator = { onLine: true };
  const window = eventTarget({ prompt() { return null; }, confirm() { return false; } });
  const id = '11111111-1111-4111-8111-111111111111';
  const version = 'a'.repeat(64);
  const stateVersion = 'b'.repeat(64);
  const notes = [{ id, title: 'fixture original', body: '' }];
  const requests = [];
  const signedRequests = [];
  let deviceActive = false;
  let deferList = false;
  let releaseList;
  const fetch = async (path, options = {}) => {
    const method = options.method ?? 'GET';
    const body = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ path, method, body, options });
    if (path === '/api/auth') {
      if (method === 'POST') authenticated = body.action === 'login';
      return Response.json({ authenticated, email: 'fixture@example.test' });
    }
    if (path === '/api/memos' && method === 'GET') {
      if (deferList) {
        deferList = false;
        return new Promise(resolve => { releaseList = rows => resolve(Response.json(rows)); });
      }
      return Response.json(notes);
    }
    if (path === '/api/memos' && method === 'POST') {
      notes.push({ id, title: body.title, body: body.body });
      return Response.json({ id }, { status: 201 });
    }
    if (path === '/api/restore/item?id=' + id && method === 'POST') {
      return Response.json(body.preview ? {
        id, verified: true, version, stateVersion, changedFields: ['title'],
        capturedAt: '2026-10-01T00:00:00.000Z',
      } : { id, restored: true, verified: true });
    }
    throw new Error('Unexpected synthetic request: ' + method + ' ' + path);
  };
  const flush = () => new Promise(resolve => setImmediate(resolve));
  const context = vm.createContext({
    document: { querySelector: selector => nodes.get(selector), createElement: element },
    navigator, window, fetch, console,
  });
  const deviceDouble = new vm.SyntheticModule(
    ['signedFetch', 'refreshDevices', 'clearDeviceState', 'hasApprovedDevice'], function () {
      this.setExport('signedFetch', async (path, options) => {
        assert.equal(deviceActive && approved, true, 'protected requests require the approved device double');
        signedRequests.push({ path, options });
        return fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store' });
      });
      this.setExport('refreshDevices', async () => { deviceActive = true; return approved; });
      this.setExport('clearDeviceState', () => {
        deviceActive = false;
        window.dispatchEvent({ type: 'byteback:device-invalidated', detail: { message: '기기로 다시 연결하세요.' } });
      });
      this.setExport('hasApprovedDevice', () => deviceActive && approved);
    }, { context });
  const application = new vm.SourceTextModule(source, { context, identifier: 'public/index.html inline module' });
  await application.link(specifier => {
    assert.equal(specifier, '/device.mjs');
    return deviceDouble;
  });
  await application.evaluate({ timeout: 1000 });
  await flush();
  return { get, navigator, window, requests, signedRequests, id, version, stateVersion, flush,
    deferNextList() { deferList = true; },
    releaseList(rows) { assert.ok(releaseList, 'a list request must be pending'); releaseList(rows); },
  };
}

test('inline UI preserves synthetic login, memo creation, restore and logout request contracts', async () => {
  const page = await inlinePage();
  assert.equal(page.get('login-form').hidden, false);
  assert.equal(page.get('memo-editor').hidden, true);
  page.get('email-input').value = ' fixture@example.test ';
  // Empty synthetic input verifies request shape without putting a password in a fixture.
  await page.get('login-form').emit('submit');
  await page.flush();
  assert.equal(page.get('logged-in-view').hidden, false);
  assert.equal(page.get('memo-editor').hidden, true);
  assert.equal(page.requests.some(request => request.path === '/api/memos'), false,
    'login and approved server status alone never load protected data');
  await page.get('device-connect').emit('click');
  assert.equal(page.get('memo-editor').hidden, false);
  assert.equal(page.get('user-email-display').textContent, 'fixture@example.test');
  assert.match(page.get('notes').textContent, /fixture original/u);
  assert.deepEqual(page.requests.find(request => request.path === '/api/auth' && request.method === 'POST').body,
    { action: 'login', email: 'fixture@example.test', password: '' });
  page.get('memo-title').value = 'fixture added';
  await page.get('memo-editor').emit('submit');
  await page.flush();
  assert.deepEqual(page.requests.find(request => request.path === '/api/memos' && request.method === 'POST').body,
    { title: 'fixture added', body: '' });
  assert.equal(page.get('memo-editor').hidden, true);
  assert.doesNotMatch(page.get('notes').textContent, /fixture original/u);
  await page.get('device-connect').emit('click');
  assert.match(page.get('notes').textContent, /fixture added/u);
  page.get('recovery-id').value = page.id;
  await page.get('recovery-preview-form').emit('submit');
  assert.equal(page.get('recovery-confirmation').hidden, false);
  await page.get('recovery-apply').emit('click');
  await page.flush();
  const restores = page.requests.filter(request => request.path === '/api/restore/item?id=' + page.id);
  assert.deepEqual(restores.map(request => request.method), ['POST', 'POST']);
  assert.deepEqual(restores.map(request => request.body), [
    { preview: true }, { expectedVersion: page.version, expectedState: page.stateVersion },
  ]);
  assert.equal(page.get('recovery-confirmation').hidden, true);
  assert.match(page.get('notes').textContent, /복원했습니다/u);
  assert.equal(page.get('memo-editor').hidden, true);
  await page.get('logout-btn').emit('click');
  assert.deepEqual(page.requests.at(-1).body, { action: 'logout' });
  assert.equal(page.get('login-form').hidden, false);
  assert.equal(page.get('memo-editor').hidden, true);
  assert.equal(page.get('user-email-display').textContent, '');
  assert.doesNotMatch(page.get('notes').textContent, /fixture/u);
  assert.ok(page.requests.every(request => request.options.cache === 'no-store'));
  assert.ok(page.requests.every(request => !new Headers(request.options.headers).has('authorization')));
  assert.equal(page.signedRequests.length,
    page.requests.filter(request => request.path !== '/api/auth').length,
    'every memo and restore request passes through the linked signing module');
});

test('inline offline handler clears protected DOM and restore plan, then ignores an in-flight list response', async () => {
  const page = await inlinePage({ authenticated: true });
  await page.get('device-connect').emit('click');
  assert.match(page.get('notes').textContent, /fixture original/u);
  page.get('recovery-id').value = page.id;
  await page.get('recovery-preview-form').emit('submit');
  assert.equal(page.get('recovery-confirmation').hidden, false);
  assert.match(page.get('recovery-details').textContent, new RegExp(page.id, 'u'));
  page.get('memo-title').value = 'fixture unsaved input';
  page.navigator.onLine = false;
  await page.window.emit('offline');
  assert.equal(page.get('memo-editor').hidden, true);
  assert.equal(page.get('recovery-panel').hidden, true);
  assert.equal(page.get('recovery-confirmation').hidden, true);
  assert.equal(page.get('recovery-details').textContent, '');
  assert.equal(page.get('recovery-id').value, '');
  assert.equal(page.get('memo-title').value, '');
  assert.equal(page.get('password-input').value, '');
  assert.equal(page.get('user-email-display').textContent, '');
  assert.match(page.get('auth-error').textContent, /오프라인/u);
  const count = page.requests.length;
  await page.get('recovery-apply').emit('click');
  assert.equal(page.requests.length, count, 'the cleared restore plan cannot issue a request');
  assert.doesNotMatch(page.get('notes').textContent, /fixture/u);
  assert.equal(page.get('memo-editor').hidden, true);

  const race = await inlinePage({ authenticated: true });
  race.deferNextList();
  const loading = race.get('device-connect').emit('click');
  await race.flush();
  race.navigator.onLine = false;
  await race.window.emit('offline');
  race.releaseList([{ id: race.id, title: 'fixture late protected row', body: '' }]);
  await loading;
  await race.flush();
  assert.doesNotMatch(race.get('notes').textContent, /fixture/u);
  assert.equal(race.get('memo-editor').hidden, true);
  assert.equal(race.get('recovery-panel').hidden, true);
});
