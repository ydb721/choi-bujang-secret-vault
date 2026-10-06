export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  try {
    const response = await fetch(
      `${url}/rest/v1/memos?select=id,title,content&order=title.asc`,
      {
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
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

    return res.status(200).json(data);
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}
