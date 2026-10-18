// Public self-checks; preserve the original stage-1 exposure regression and stage-5+ checks.
export async function runAttackChecks(config) {
  const base = new URL(config.publicAppUrl);
  // The judge's isolated runner supports public GET/HEAD only and may not
  // implement timeout helpers or nonessential fetch options.
  const publicGet = async (url) => {
    try { return await fetch(String(url), { method: 'GET' }); }
    catch { return null; }
  };
  const inspectResponse = async (response) => {
    if (!response) return null;
    let body = null;
    try { body = await response.json(); } catch { /* non-json */ }
    const errorCode = typeof body?.error === 'string'
      && /^[A-Z][A-Z0-9_]{0,79}$/u.test(body.error) ? body.error : null;
    return { status: response.status, ok: response.ok, body, errorCode };
  };
  const httpObservation = (result, detail = '') => result
    ? `HTTP ${result.status}${result.errorCode ? `; error=${result.errorCode}` : ''}${detail}`
    : 'not_run';

  if (config.step === 1) {
    const response = await publicGet(new URL('/data.json', base));
    if (!response) return [{
      attackId: 'public_data_json',
      expected: '공개 data.json에서 가상 자료 확인',
      observed: 'not_run',
    }];
    let exposed = false;
    try {
      const body = await response.json();
      exposed = response.ok
        && body?.sampleMarker === config.sampleMarker
        && Array.isArray(body?.notes)
        && body.notes.length > 0;
    } catch { exposed = false; }

    return [{
      attackId: 'public_data_json',
      expected: '공개 data.json에서 가상 자료 확인',
      observed: exposed ? '확인 표시가 보임' : '확인 표시가 보이지 않음',
    }];
  }

  if (config.step < 5) throw new Error('5단계 이상 설정이 필요합니다.');
  const direct = new URL(config.originalApiUrl);
  if (base.protocol !== 'https:' || !base.hostname.endsWith('.vercel.app')
      || direct.protocol !== 'https:') throw new Error('HTTPS 주소를 확인해 주세요.');

  const list = await inspectResponse(await publicGet(new URL('/api/memos',base)));
  const single = await inspectResponse(await publicGet(
    new URL('/api/memos/11111111-1111-4111-8111-111111111111',base)));
  const staticRes = await inspectResponse(await publicGet(new URL('/data.json',base)));
  const deployed = await inspectResponse(await publicGet(new URL('/aleph.json',base)));
  const noStatic = staticRes?.status === 404 || staticRes?.ok
    && Array.isArray(staticRes.body?.notes) && !staticRes.body.notes.length
    && !('sampleMarker' in staticRes.body);

  // Direct access using an anon/publishable key is checked by the judge, not by this script.
  const directRes = await inspectResponse(await publicGet(direct));

  return [
    {attackId:'unauthenticated_memo_list',expected:'HTTP 401; error=AUTH_REQUIRED',
      observed:httpObservation(list)},
    {attackId:'unauthenticated_memo_item',expected:'HTTP 401; error=AUTH_REQUIRED',
      observed:httpObservation(single)},
    {attackId:'foreign_memo_scope',expected:'인증된 다른 소유자 메모 조회 거부',
      observed:'not_run'},
    {attackId:'static_memo_empty',expected:'정적 자료 0건',
      observed:httpObservation(staticRes, noStatic ? '; static_memo_empty=true' : '; static_memo_empty=false')},
    {attackId:'deployment_identity',expected:'/aleph.json 열림',
      observed:httpObservation(deployed, deployed?.ok ? '; deployment_identity_available=true'
        : '; deployment_identity_available=false')},
    {attackId:'direct_no_key_probe',expected:'키 없이 직접 자료 API 요청 거부',
      observed:httpObservation(directRes)},
  ];
}
