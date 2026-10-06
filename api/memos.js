import { createRequire } from 'node:module';
import { createLoginVerifier } from '../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');

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

export default async function handler(req, res) {
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

  // The verifier validates the token and derives the user ID server-side.
  // Browser-provided userId and role are never trusted.
  const identity = await verifyLogin(req.headers.authorization);
  if (!identity) {
    return res.status(401).json({ error: 'AUTH_REQUIRED' });
  }

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  try {
    const response = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/memos?select=id,title,content&order=title.asc`,
      {
        headers: {
          apikey: process.env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SECRET_KEY}`,
        },
      },
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(502).json({ error: 'UPSTREAM_DATA_ERROR' });
    }
    if (!Array.isArray(data)) {
      return res.status(502).json({ error: 'INVALID_DATA_FORMAT' });
    }

    // Owner checks and CRUD are deliberately reserved for stage 3 task 3/4.
    return res.status(200).json(data);
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}
