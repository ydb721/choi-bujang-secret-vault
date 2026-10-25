import { readFile } from 'node:fs/promises';

const fixtureUrl = new URL('../fixtures/persistence.json', import.meta.url);

function safeText(value) {
  if (typeof value !== 'string') return '';

  return value
    .replace(/(?:password|token|api[_-]?key|secret|authorization)\s*[:=]\s*[^\s,;]+/giu, '[민감정보 마스킹]')
    .replace(/(?:[a-z]:\\[^\s"'`]+|\/(?:[\w.-]+\/)+[\w.-]+)/giu, '[실행 경로 마스킹]')
    .replace(/(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|sh)\s+(?:-\w+\s+)?[^\r\n]+/giu, '[명령어 마스킹]');
}

const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));

if (fixture?.schema !== 'aleph.xdr.fixture.v1') {
  throw new Error('Unsupported fixture schema');
}

if (fixture?.moduleKey !== 'persistence') {
  throw new Error('Unexpected fixture moduleKey');
}

if (!Array.isArray(fixture.alerts)) {
  throw new Error('Fixture alerts must be an array');
}

for (const alert of fixture.alerts) {
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
