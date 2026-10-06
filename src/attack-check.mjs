// Stage 3 attack checks: only public test responses, never credentials or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 3) throw new Error('3단계 공격 점검 설정을 확인해 주세요.');

  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || !app.hostname.endsWith('.vercel.app')) {
    throw new Error('올바른 Vercel 배포 주소를 확인해 주세요.');
  }

  const anon = await fetch(new URL('/api/memos', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  let anonJsonError = false;
  try {
    const data = await anon.json();
    anonJsonError = typeof data?.error === 'string';
  } catch { /* Not valid JSON */ }

  const invalid = await fetch(new URL('/api/memos', app), {
    headers: { Authorization: 'Bearer invalid.invalid.invalid' },
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  const staticResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  let staticEmpty = staticResponse.status === 404;
  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      staticEmpty = Array.isArray(data?.notes) && data.notes.length === 0
        && !Object.prototype.hasOwnProperty.call(data, 'sampleMarker');
    } catch { staticEmpty = false; }
  }

  return [
    {
      attackId: 'anonymous_api_blocked',
      expected: '비로그인 요청은 401/403 + JSON 오류',
      observed: (anon.status === 401 || anon.status === 403) && anonJsonError
        ? '비로그인 요청이 JSON 오류와 함께 거부됨'
        : '비로그인 요청 상태 ' + anon.status + ', JSON 오류 ' + anonJsonError,
    },
    {
      attackId: 'invalid_token_rejected',
      expected: '잘못된 토큰 요청 거부',
      observed: (invalid.status === 401 || invalid.status === 403)
        ? '잘못된 토큰 요청 거부됨'
        : '잘못된 토큰 요청 상태 ' + invalid.status,
    },
    {
      attackId: 'static_notes_removed',
      expected: '정적 data.json 메모 0건, 1단계 표식 제거',
      observed: staticEmpty ? '정적 메모와 표식 없음' : '정적 확인 실패: HTTP ' + staticResponse.status,
    },
  ];
}
