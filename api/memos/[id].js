import { handleMemos } from '../memos.js';

export default async function handler(req, res) {
  const pathId = new URL(req.url, 'https://example.invalid').pathname
    .match(/^\/api\/memos\/([^/]+)\/?$/)?.[1];
  const noteId = req.query?.id ?? pathId ?? '';
  return handleMemos(req, res, noteId);
}
