-- BYTE BACK 4단계 제작 3: public.memos 테이블에만 최소 권한 + 소유자 정책 적용
-- 학습용 자료 전용이며, 실행 전 SQL을 직접 검토할 것.
-- 기존 Supabase Auth 사용자 A/B와 소유자 배정 SQL 확인 후 실행할 것.

-- 권한 변경 전: 테이블 권한 목록 및 실제 권한
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'memos'
  and grantee in ('anon', 'authenticated', 'PUBLIC')
order by grantee, privilege_type;

select role_name, privilege,
       has_table_privilege(role_name, 'public.memos', privilege) as has_privilege
from (values ('anon'), ('authenticated')) as r(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as p(privilege)
order by role_name, privilege;

begin;

revoke all on table public.memos from PUBLIC, anon, authenticated;
grant select, insert, update, delete on table public.memos to authenticated;
alter table public.memos enable row level security;

drop policy if exists memos_4_select on public.memos;
drop policy if exists memos_4_insert on public.memos;
drop policy if exists memos_4_update on public.memos;
drop policy if exists memos_4_delete on public.memos;

create policy memos_4_select on public.memos
for select to authenticated
using (auth.uid() = owner_id);

create policy memos_4_insert on public.memos
for insert to authenticated
with check (auth.uid() = owner_id);

create policy memos_4_update on public.memos
for update to authenticated
using (auth.uid() = owner_id)
with check (auth.uid() = owner_id);

create policy memos_4_delete on public.memos
for delete to authenticated
using (auth.uid() = owner_id);

commit;

-- 권한 변경 후: authenticated에는 SELECT/INSERT/UPDATE/DELETE만 허용, anon은 없음
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'memos'
  and grantee in ('anon', 'authenticated', 'PUBLIC')
order by grantee, privilege_type;

select role_name, privilege,
       has_table_privilege(role_name, 'public.memos', privilege) as has_privilege
from (values ('anon'), ('authenticated')) as r(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
                   ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as p(privilege)
order by role_name, privilege;
