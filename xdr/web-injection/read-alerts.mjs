import { readFile } from 'node:fs/promises';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);

function safeText(value) {
  if (typeof value !== 'string') return '';
  // The reader never emits values that look like secret-bearing fields.
  return /(?:password|token|api[_-]?key|secret|authorization)\s*[:=]/iu.test(value)
    ? '[민감정보 마스킹]'
    : value;
}

const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
const alerts = Array.isArray(fixture?.alerts) ? fixture.alerts : [];

for (const alert of alerts) {
  const row = {
    timestamp: safeText(alert?.timestamp),
    'data.srcip': safeText(alert?.data?.srcip),
    'data.srcuser': typeof alert?.data?.srcuser === 'string' && alert.data.srcuser.trim()
      ? safeText(alert.data.srcuser)
      : '미확인',
    'rule.level': typeof alert?.rule?.level === 'number' ? alert.rule.level : null,
    'rule.description': safeText(alert?.rule?.description),
  };
  console.log(JSON.stringify(row));
}
