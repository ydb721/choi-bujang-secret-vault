-- BYTE BACK 4단계 제작 1: 학습용 A/B 소유자 배정
-- 먼저 Supabase Authentication > Users에서 B 계정(test-b@example.com)을 생성한다.
-- 현재 실제 사용 중인 A 계정: test-a@example.com
-- 기존 네 메모는 삭제하지 않음. 세 건은 A, '훈련 행정 자료' 한 건은 B로 배정.

do $$
declare
  a_user uuid;
  b_user uuid;
begin
  select id into a_user from auth.users where email = 'test-a@example.com';
  select id into b_user from auth.users where email = 'test-b@example.com';

  if a_user is null or b_user is null then
    raise exception 'A 또는 B 테스트 계정이 없음: Authentication > Users에서 먼저 생성';
  end if;

  update public.memos
  set owner_id = a_user
  where title in ('과제', '포트폴리오', '아침 리추얼')
    and (owner_id = a_user or owner_id is null);

  update public.memos
  set owner_id = b_user
  where title = '훈련 행정 자료'
    and (owner_id = a_user or owner_id = b_user or owner_id is null);
end $$;

select
  count(*) filter (where owner_id = (select id from auth.users where email='test-a@example.com')) as a_notes,
  count(*) filter (where owner_id = (select id from auth.users where email='test-b@example.com')) as b_notes,
  count(*) as total_notes
from public.memos;
