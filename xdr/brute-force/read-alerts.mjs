// XDR bonus / brute-force: read-only Wazuh fixture inspector.
// This module does not participate in access decisions.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const FIXTURE_URL = new URL('../fixtures/brute-force.json', import.meta.url);

// Only sanitized, explicitly permitted fields are ever included in output.
function safeText(value) {
  if (typeof value !== 'string' || value.length === 0) return '확인 불가';

  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/giu, '[비밀값 가림]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{12,}\b/gu, '[비밀값 가림]')
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{12,}\b/gu, '[비밀값 가림]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/gu, '[비밀값 가림]')
    .replace(/\bsk-[A-Za-z0-9_-]{12,}\b/gu, '[비밀값 가림]')
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]{8,}={0,2}/giu, '[비밀값 가림]')
    .replace(/\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|client[_-]?secret)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu, '[비밀값 가림]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b/gu, '[비밀값 가림]');
}

export function extractAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'brute-force'
    || !Array.isArray(fixture.alerts)) {
    throw new Error('올바른 brute-force 경보 묶음이 아닙니다.');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: Number.isInteger(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(FIXTURE_URL, 'utf8'));
  return extractAlerts(fixture);
}

// One JSON line per source alert, with no header/footer or raw alert output.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    for (const row of await readAlerts()) {
      process.stdout.write(`${JSON.stringify(row)}\n`);
    }
  } catch {
    process.stderr.write('경보 파일을 읽지 못했습니다.\n');
    process.exitCode = 1;
  }
}
