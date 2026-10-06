// Stage 5 public self-checks; no private keys, credentials, or record bodies.
export async function runAttackChecks(config) {
  if (config.step !== 5) throw new Error('5단계 설정이 아닙니다.');
  const base = new URL(config.publicAppUrl);
  const direct = new URL(config.originalApiUrl);
  if (base.protocol !== 'https:' || !base.hostname.endsWith('.vercel.app')
      || direct.protocol !== 'https:') throw new Error('HTTPS 주소를 확인해 주세요.');

  const options = () => ({redirect: 'error', signal: AbortSignal.timeout(10000)});
  const list = await fetch(new URL('/api/memos',base),options());
  let jsonError = false;
  try { jsonError = typeof (await list.json())?.error === 'string'; } catch { /* non-json */ }

  const single = await fetch(new URL('/api/memos/11111111-1111-4111-8111-111111111111',base),options());
  const staticRes = await fetch(new URL('/data.json',base),options());
  const deployed = await fetch(new URL('/aleph.json',base),options());
  let noStatic = staticRes.status === 404;
  if(staticRes.ok) {
    try {
      const obj = await staticRes.json();
      noStatic = Array.isArray(obj?.notes) && !obj.notes.length && !('sampleMarker' in obj);
    } catch { noStatic = false; }
  }

  // Direct access using an anon/publishable key is checked by the judge, not by this script.
  const directRes = await fetch(direct,options());
  return [
    {attackId:'unauthenticated_memo_list',expected:'401/403 JSON 오류',
      observed:[401,403].includes(list.status)&&jsonError?'비로그인 목록 거부, JSON 오류':'HTTP '+list.status+', JSON='+jsonError},
    {attackId:'unauthenticated_memo_item',expected:'401/403',
      observed:[401,403].includes(single.status)?'비로그인 단건 거부':'HTTP '+single.status},
    {attackId:'static_memo_empty',expected:'정적 자료 0건',
      observed:noStatic?'정적 자료 0건':'확인 필요 HTTP '+staticRes.status},
    {attackId:'deployment_identity',expected:'/aleph.json 열림',
      observed:deployed.ok?'/aleph.json 열림':'HTTP '+deployed.status},
    {attackId:'direct_no_key_probe',expected:'키 없이 직접 자료 API 요청 거부',
      observed:'키 없는 요청 HTTP '+directRes.status+'; anon 키 요청은 심판에서 확인'},
  ];
}
