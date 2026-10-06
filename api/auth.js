import { createClient } from '@supabase/supabase-js';

// The publishable key is intentionally server-only in stage 5.
// An optional Vercel environment variable can replace this public training key.
const authKey = process.env.SUPABASE_PUBLISHABLE_KEY
  || 'sb_publishable_E4o3qIRW_1RucMUHkOur2Q_gBN5SRqB';

const accessName = '__Host-byteback-access';
const refreshName = '__Host-byteback-refresh';
const cookieFlags = 'Path=/; HttpOnly; Secure; SameSite=Strict';
const noCache = 'no-store';

function authClient() {
  if (!process.env.SUPABASE_URL) throw new Error('MISSING_SUPABASE_URL');
  return createClient(process.env.SUPABASE_URL, authKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
}

function readCookies(req) {
  const entries = String(req.headers.cookie || '').split(';').map(s => s.trim());
  const cookies = {};
  for (const entry of entries) {
    const split = entry.indexOf('=');
    if (split < 1) continue;
    try { cookies[entry.slice(0, split)] = decodeURIComponent(entry.slice(split + 1)); }
    catch { /* Ignore malformed cookies */ }
  }
  return cookies;
}

function clearSession(res) {
  res.setHeader('Set-Cookie', [
    accessName + '=; ' + cookieFlags + '; Max-Age=0',
    refreshName + '=; ' + cookieFlags + '; Max-Age=0',
  ]);
}

function saveSession(res, session) {
  const expiry = Math.max(1, Math.min(Number(session.expires_in) || 3600, 3600));
  res.setHeader('Set-Cookie', [
    accessName + '=' + encodeURIComponent(session.access_token)
      + '; ' + cookieFlags + '; Max-Age=' + expiry,
    refreshName + '=' + encodeURIComponent(session.refresh_token)
      + '; ' + cookieFlags + '; Max-Age=1209600',
  ]);
}

function parseBody(req) {
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return null; }
  }
  return req.body && typeof req.body === 'object' ? req.body : null;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', noCache);
  res.setHeader('Vary', 'Cookie');

  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const origin = req.headers.origin;
  if (req.method === 'POST' && origin && origin !== 'https://' + req.headers.host) {
    return res.status(403).json({ error: 'ORIGIN_REJECTED' });
  }

  let client;
  try { client = authClient(); }
  catch { return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' }); }

  if (req.method === 'POST') {
    const input = parseBody(req);
    if (input?.action === 'logout') {
      const stored = readCookies(req);
      if (stored[accessName] && stored[refreshName]) {
        try {
          const { error } = await client.auth.setSession({
            access_token: stored[accessName], refresh_token: stored[refreshName],
          });
          if (!error) await client.auth.signOut();
        } catch { /* Clear the browser session even if revocation fails */ }
      }
      clearSession(res);
      return res.status(200).json({ authenticated: false });
    }

    if (input?.action !== 'login'
        || typeof input.email !== 'string' || input.email.length > 254
        || typeof input.password !== 'string' || input.password.length > 1024) {
      return res.status(400).json({ error: 'INVALID_LOGIN_REQUEST' });
    }

    try {
      const { data, error } = await client.auth.signInWithPassword({
        email: input.email.trim(), password: input.password,
      });
      if (error || !data?.session || !data.user) {
        return res.status(401).json({ error: error?.message || 'INVALID_LOGIN' });
      }
      saveSession(res, data.session);
      return res.status(200).json({ authenticated: true, email: data.user.email ?? '' });
    } catch {
      return res.status(502).json({ error: 'AUTH_PROVIDER_UNAVAILABLE' });
    }
  }

  const cookies = readCookies(req);
  const access = cookies[accessName];
  const refresh = cookies[refreshName];
  if (!refresh) {
    clearSession(res);
    return res.status(200).json({ authenticated: false });
  }

  try {
    if (access) {
      const { data, error } = await client.auth.getUser(access);
      if (!error && data?.user) {
        return res.status(200).json({ authenticated: true, email: data.user.email ?? '' });
      }
    }
    const { data, error } = await client.auth.refreshSession({ refresh_token: refresh });
    if (!error && data?.session && data?.user) {
      saveSession(res, data.session);
      return res.status(200).json({ authenticated: true, email: data.user.email ?? '' });
    }
  } catch { /* An invalid or expired session becomes logged out */ }

  clearSession(res);
  return res.status(200).json({ authenticated: false });
}
