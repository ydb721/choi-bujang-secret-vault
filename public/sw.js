const CACHE_PREFIX = 'byteback-public-';
const CACHE_NAME = CACHE_PREFIX + 'v4';
const OFFLINE_PATH = '/offline.html';
const PUBLIC_FILES = Object.freeze([
  OFFLINE_PATH,
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
]);
const PUBLIC_PATHS = new Set(PUBLIC_FILES);

async function fetchPublic(path) {
  // Use fixed public paths and omit credentials; never cache the incoming request.
  const response = await fetch(path, { credentials: 'omit', cache: 'reload', redirect: 'error' });
  if (!response.ok || response.type === 'opaque' || response.redirected
      || response.headers.has('set-cookie')
      || /\b(private|no-store)\b/iu.test(response.headers.get('cache-control') || '')) {
    throw new Error('PUBLIC_RESOURCE_UNAVAILABLE');
  }
  return response;
}

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const files = await Promise.all(PUBLIC_FILES.map(async path => [path, await fetchPublic(path)]));
    const cache = await caches.open(CACHE_NAME);
    await Promise.all(files.map(([path, response]) => cache.put(path, response)));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter(name => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
      .map(name => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  // API, unknown paths and query strings never use the offline document or cache.
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.search
      || url.pathname === '/api' || url.pathname.startsWith('/api/')) return;

  if (request.mode === 'navigate' && ['/', '/index.html'].includes(url.pathname)) {
    event.respondWith((async () => {
      try { return await fetch(request, { cache: 'no-store' }); }
      catch {
        const cache = await caches.open(CACHE_NAME);
        return await cache.match(OFFLINE_PATH)
          || new Response('오프라인에서는 보호 자료를 읽을 수 없습니다. 연결 후 다시 확인하세요.', {
            status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
          });
      }
    })());
    return;
  }

  // Even a credential-bearing navigation may receive the public offline notice,
  // but its request/response is never persisted. Static cache keys omit credentials.
  if (request.headers.has('authorization') || request.headers.has('cookie')
      || request.headers.has('x-byteback-proof')
      || /\bno-store\b/iu.test(request.headers.get('cache-control') || '')
      || request.cache === 'no-store') return;

  if (PUBLIC_PATHS.has(url.pathname)) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(url.pathname);
      if (cached) return cached;
      const response = await fetchPublic(url.pathname);
      await cache.put(url.pathname, response.clone());
      return response;
    })());
  }
});
