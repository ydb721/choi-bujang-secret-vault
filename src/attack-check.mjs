// 4단계 자기 점검: 비밀값, 로그인 토큰, 가상 메모 본문은 수집하지 않음.
// A/B 타인 메모 검사와 RLS 적용 확인은 사용자가 직접 진행하여야 함.
export async function runAttackChecks(config) {
  if (config.step !== 4) throw new Error('4단계 설정을 확인해 주세요.');
  const base = new URL(config.publicAppUrl);
  if (base.protocol !== 'https:' || !base.hostname.endsWith('.vercel.app')
      || base.pathname !== '/') {
    throw new Error('실제 HTTPS Vercel 주소를 확인해 주세요.');
  }

  const request = (path, headers) => fetch(new URL(path, base), {
    redirect: 'error',
    headers,
    signal: AbortSignal.timeout(10000),
  });
  const list = await request('/api/memos');
  let jsonError = false;
  try {
    const body = await list.json();
    jsonError = Boolean(body && typeof body.error === 'string');
  } catch { jsonError = false; }

  const fakeId = '11111111-1111-4111-8111-111111111111';
  const single = await request('/api/memos/' + fakeId);
  const staticFile = await request('/data.json');
  const aleph = await request('/aleph.json');
  let staticEmpty = staticFile.status === 404;
  if (staticFile.ok) {
    try {
      const obj = await staticFile.json();
      staticEmpty = Array.isArray(obj?.notes) && obj.notes.length === 0
        && !Object.prototype.hasOwnProperty.call(obj, 'sampleMarker');
    } catch { staticEmpty = false; }
  }

  return [
    { attackId: 'anonymous_list_block',
      expected: '비로그인 목록 401/403 및 JSON 오류',
      observed: [401,403].includes(list.status) && jsonError
        ? '인증 없는 목록 요청 거부 및 JSON 오류 확인'
        : '목록 요청 ' + list.status + ', JSON 오류 ' + jsonError },
    { attackId: 'anonymous_item_block',
      expected: '비로그인 단건 401/403',
      observed: [401,403].includes(single.status)
        ? '인증 없는 단건 요청 거부'
        : '단건 요청 HTTP ' + single.status },
    { attackId: 'static_file_check',
      expected: '공개 정적 메모 0건',
      observed: staticEmpty ? '정적 메모 0건' : '정적 확인 실패 (HTTP ' + staticFile.status + ')' },
    { attackId: 'deployment_identity',
      expected: '/aleph.json 정상 응답',
      observed: aleph.ok ? '/aleph.json 열림' : '/aleph.json HTTP ' + aleph.status },
  ];
}
