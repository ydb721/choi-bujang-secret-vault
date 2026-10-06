// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('2단계 공격 점검 설정을 확인해 주세요.');

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const staticResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let staticEmpty = false;
  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      staticEmpty = !Object.prototype.hasOwnProperty.call(data ?? {}, 'sampleMarker')
        && ((Array.isArray(data) && data.length === 0)
          || (Array.isArray(data?.notes) && data.notes.length === 0));
    } catch {
      staticEmpty = false;
    }
  }

  const apiResponse = await fetch(new URL('/api/memos', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let apiArray = false;
  if (apiResponse.ok) {
    try {
      apiArray = Array.isArray(await apiResponse.json());
    } catch {
      apiArray = false;
    }
  }

  return [
    {
      attackId: 'anonymous_static_note_read',
      expected: '정적 data.json에서 가상 메모 0건이며 1단계 확인 표시가 없음',
      observed: staticEmpty
        ? '비로그인 정적 요청에서 메모 0건 및 1단계 확인 표시 제거 확인'
        : `정적 자료 또는 1단계 확인 표시가 남아 있거나 읽을 수 없음 (HTTP ${staticResponse.status})`,
    },
    {
      attackId: 'anonymous_api_read',
      expected: '2단계에서는 공개 API 약점이 남아 있음을 기록',
      observed: apiArray
        ? '비로그인 API 요청이 JSON 배열을 반환함'
        : `공개 API 응답을 확인하지 못함 (HTTP ${apiResponse.status})`,
    },
  ];
}
