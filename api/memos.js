import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { createLoginVerifier } from '../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let verifier;
function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return verifier;
}

function readBody(req) {
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return null; }
  }
  return req.body ?? null;
}

function memoFields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.title !== 'string' || typeof value.body !== 'string') return null;
  const title = value.title.trim();
  const body = value.body;
  if (!title || title.length > 120 || body.length > 4000) return null;
  return { title, content: body };
}

function resultMemo(note) {
  return { id: note.public_id, title: note.title, body: note.content ?? '' };
}

async function dbRequest(method, params, payload) {
  const url = new URL('/rest/v1/memos', process.env.SUPABASE_URL);
  Object.entries(params).forEach(([name, value]) => url.searchParams.set(name, value));
  const key = process.env.SUPABASE_SECRET_KEY;
  const headers = {
    apikey: key,
    Authorization: 'Bearer ' + key,
    'Content-Type': 'application/json',
  };
  if (method !== 'GET') headers.Prefer = 'return=representation';

  const response = await fetch(url, {
    method,
    headers,
    ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
  });
  let data;
  try { data = await response.json(); } catch { data = null; }

  if (!response.ok) {
    if (method === 'POST' && response.status === 409) {
      return { error: 'MEMO_ID_ALREADY_EXISTS', status: 409 };
    }
    return { error: 'DATA_REQUEST_FAILED', status: 502 };
  }
  if (!Array.isArray(data)) return { error: 'INVALID_DATA_FORMAT', status: 502 };
  return { data };
}

export async function handleMemos(req, res, noteId = null) {
  res.setHeader('Cache-Control', 'no-store');

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  let verifyLogin;
  try {
    verifyLogin = getVerifier();
  } catch {
    return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  // Only the token-verified identity determines ownership on every operation.
  const identity = await verifyLogin(req.headers.authorization);
  if (!identity) {
    return res.status(401).json({ error: 'AUTH_REQUIRED' });
  }

  const isSingle = noteId !== null;
  const allowed = isSingle ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
  if (!allowed.includes(req.method)) {
    res.setHeader('Allow', allowed.join(', '));
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  if (isSingle && (typeof noteId !== 'string' || !uuidPattern.test(noteId))) {
    return res.status(400).json({ error: 'INVALID_MEMO_ID' });
  }

  try {
    if (req.method === 'GET' && !isSingle) {
      const result = await dbRequest('GET', {
        select: 'public_id,title,content',
        owner_id: 'eq.' + identity.userId,
        order: 'created_at.asc',
      });
      if (result.error) return res.status(result.status).json({ error: result.error });
      return res.status(200).json(result.data.map(resultMemo));
    }

    if (req.method === 'POST') {
      const incoming = readBody(req);
      const fields = memoFields(incoming);
      if (!fields || (incoming.id !== undefined
          && (typeof incoming.id !== 'string' || !uuidPattern.test(incoming.id)))) {
        return res.status(400).json({ error: 'INVALID_MEMO' });
      }
      const publicId = incoming.id ?? randomUUID();
      const result = await dbRequest('POST', {
        select: 'public_id',
      }, {
        public_id: publicId,
        owner_id: identity.userId,
        ...fields,
      });
      if (result.error) return res.status(result.status).json({ error: result.error });
      if (result.data.length !== 1) return res.status(502).json({ error: 'CREATE_FAILED' });
      return res.status(201).json({ id: result.data[0].public_id });
    }

    const byId = { public_id: 'eq.' + noteId, owner_id: 'eq.' + identity.userId };
    // Every per-ID operation is atomically restricted to the token-verified owner.
    if (req.method === 'GET') {
      const result = await dbRequest('GET', {
        ...byId,
        select: 'public_id,title,content',
        limit: '1',
      });
      if (result.error) return res.status(result.status).json({ error: result.error });
      if (!result.data.length) return res.status(404).json({ error: 'MEMO_NOT_FOUND' });
      return res.status(200).json(resultMemo(result.data[0]));
    }

    if (req.method === 'PUT') {
      const incoming = readBody(req);
      // Never accept an owner change or an identity supplied in the request body.
      if (incoming && typeof incoming === 'object'
          && (Object.hasOwn(incoming, 'owner_id') || Object.hasOwn(incoming, 'ownerId'))) {
        return res.status(403).json({ error: 'OWNER_CHANGE_FORBIDDEN' });
      }
      const fields = memoFields(incoming);
      if (!fields) return res.status(400).json({ error: 'INVALID_MEMO' });
      const result = await dbRequest('PATCH', {
        ...byId,
        select: 'public_id,title,content,owner_id',
      }, fields);
      if (result.error) return res.status(result.status).json({ error: result.error });
      if (!result.data.length) return res.status(404).json({ error: 'MEMO_NOT_FOUND' });
      if (result.data[0].owner_id !== identity.userId) {
        return res.status(403).json({ error: 'OWNER_MISMATCH' });
      }
      return res.status(200).json(resultMemo(result.data[0]));
    }

    if (req.method === 'DELETE') {
      const result = await dbRequest('DELETE', {
        ...byId,
        select: 'public_id',
      });
      if (result.error) return res.status(result.status).json({ error: result.error });
      if (!result.data.length) return res.status(404).json({ error: 'MEMO_NOT_FOUND' });
      return res.status(204).end();
    }
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}

export default async function handler(req, res) {
  return handleMemos(req, res);
}
