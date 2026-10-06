-- BYTE BACK 5단계: 학습용 public.memos 원본 자료 API 직접 권한 회수
-- 서버 전용 SUPABASE_SECRET_KEY는 Vercel 비밀 환경변수로 유지합니다.
-- 다른 테이블 또는 로그인(auth.users) 권한은 변경하지 않습니다.

-- 적용 전: 역할별 테이블 권한
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'memos'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

select role_name, privilege,
       has_table_privilege(role_name, 'public.memos', privilege) as has_privilege
from (values ('anon'),('authenticated')) roles(role_name)
cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),
                   ('TRUNCATE'),('REFERENCES'),('TRIGGER')) perms(privilege)
order by role_name, privilege;

-- 실제 권한 회수: public.memos 한 테이블만
begin;
revoke all on table public.memos from PUBLIC, anon, authenticated;
commit;

-- 적용 후: 위 두 역할은 모든 권한 false여야 함
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'memos'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

select role_name, privilege,
       has_table_privilege(role_name, 'public.memos', privilege) as has_privilege
from (values ('anon'),('authenticated')) roles(role_name)
cross join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),
                   ('TRUNCATE'),('REFERENCES'),('TRIGGER')) perms(privilege)
order by role_name, privilege;

-- 기존 RLS는 그대로 유지합니다. Vercel 서버 함수의 소유자 검사도 유지합니다.
