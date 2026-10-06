# BYTE BACK 방어전 R5

이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 5단계 — 자료 요청을 서버 한곳으로 모읍니다

현재 기능 (5줄):
1. 로그인·로그아웃은 Vercel `/api/auth`에서 공식 Supabase Auth SDK 사용
2. 브라우저는 `/api/memos` 서버 함수로만 메모 조회·추가·수정·삭제
3. JWT는 HttpOnly Secure SameSite=Strict 쿠키, 서버는 원본 `src/verify-login.mjs`로 검증
4. 모든 메모 요청은 서버에서 검증한 사용자 ID와 소유자를 비교
5. 비로그인 시 JSON 401, `/data.json` 메모 0건, `/aleph.json` 및 nosniff 유지

### 5단계 제작 1 결과

`public/index.html`에 Supabase 메모 Data API 직접 호출은 **없음**. `/rest/v1/memos`는 기존부터 `api/memos.js` 서버 함수 내부에서만 사용했음.
3단계까지 브라우저가 호출하던 Supabase Auth SDK는 5단계 공개 키 가점 조건을 위해 `api/auth.js`로 이동함. A/B 이메일·비밀번호 로그인·로그아웃 동작은 유지.

### 5단계 제작 2: 직접 DB 권한 회수

검토 후 [supabase/step5-revoke-direct.sql](supabase/step5-revoke-direct.sql)을 **Supabase SQL Editor에서 직접 실행**할 것.
`public.memos`에서 `PUBLIC`, `anon`, `authenticated` 테이블 권한만 REVOKE ALL; `service_role` 역할은 변경하지 않음.
원본 직접 자료 API (쿼리 없는 HTTPS 주소): `https://pizhdpzwtognhuklasrt.supabase.co/rest/v1/memos`.
브라우저는 `api/auth.js` 서버를 통해 Supabase Auth SDK를 사용하고, Supabase 공개 키는 `public/index.html`에 포함하지 않음.
인증 서버에서는 공개용 `SUPABASE_PUBLISHABLE_KEY` (선택 환경변수 또는 공개 학습용 서버 상수)를 사용.
메모 서버 `api/memos.js`는 비공개 `SUPABASE_SECRET_KEY`를 환경변수에서만 읽으며 검증·소유자 검사 유지.

### 5단계 재현 확인

1. 배포에서 A 로그인 후 **A 메모 3건**과 자신의 추가·수정·삭제를 확인
2. B 로그인 후 **B 메모 1건**과 자신의 추가·수정·삭제를 확인
3. B가 A 메모 UUID를 사용한 GET·PUT·DELETE 요청 → 403 또는 404, A 메모 유지
4. 로그아웃 후 /api/memos 직접 요청 → 401 JSON 오류
5. 원본 Data API `https://pizhdpzwtognhuklasrt.supabase.co/rest/v1/memos`에 anon 키만 담아 GET/POST → 자료 접근 거부 (심판이 검사)
6. `/aleph.json`의 step=5, allowedRoutes 확인; 첫 화면 nosniff 헤더 및 공개 HTML에 `sb_publishable_` 없는지 확인

### 5단계 저장점 및 제출 묶음

```powershell
git status
git pull
npm.cmd run bundle
```

로컬 `bundle-notes.json`의 explanation을 5단계로 바꿔 저장. `artifacts/submission.json` 및 `bundle-notes.json`은 커밋하지 않음.
SQL 권한 회수와 A/B 로그인·CRUD 검증은 실제 실행 전 통과했다고 기록하지 않음.

## 4단계 저장점 — 로그인해도 내 자료만

현재 기능 (5줄):
1. Supabase Auth 로그인·로그아웃 및 유효한 토큰 검증
2. 로그인한 사용자의 메모 목록 조회
3. 가상 메모 추가·조회·수정·삭제 (UUID)
4. 서버에서 모든 단건 CRUD를 `owner_id = 검증된 userId`로 제한
5. 비로그인 요청은 JSON 401로 거부하며 정적 `/data.json`은 비어 있음

### 4단계 작업 순서

- [supabase/step4-owner-fixtures.sql](supabase/step4-owner-fixtures.sql): 먼저 Supabase Auth에 B 계정 `test-b@example.com`을 만들고 실행. 기존 4건 중 세 건은 A, '훈련 행정 자료' 한 건은 B로 배정. 입력한 이메일과 테스트 계정을 실행 전 점검
- [supabase/step4-rls.sql](supabase/step4-rls.sql): **학생 검토 후 직접 실행할 SQL**. `public.memos`만 권한 재정의 및 SELECT/INSERT/UPDATE/DELETE 정책 적용
- 서버 API: `GET /api/memos`, `POST /api/memos`, `GET /api/memos/:id`, `PUT /api/memos/:id`, `DELETE /api/memos/:id`는 인증 필수
- 단건 조회·수정·삭제는 `public_id`와 `owner_id`를 함께 필터. 수정 요청의 `owner_id` 변경은 403. 추가 시 owner_id는 서버가 검증한 사용자 ID로만 설정
- RLS 실행 후 `role_table_grants`, `has_table_privilege`으로 anon 및 authenticated 테이블 권한을 재확인해야 함
- Supabase 서버 전용 키를 사용하는 서버 호출은 RLS를 우회할 수 있으므로 API에서의 소유자 검사를 별도로 유지
- 3단계 기존 메모 본문·로그인 SDK·화면 구성은 보존

### 4단계 직접 검증

1. A 로그인 → 세 건 목록. 자신이 만든 임시 메모는 추가·수정·삭제 가능
2. B 로그인 → '훈련 행정 자료' 한 건 목록. 자신의 임시 메모도 CRUD 가능
3. B가 A의 메모 UUID로 GET·PUT·DELETE 요청 → 404 또는 403, A의 메모 그대로 유지
4. A가 B 메모 UUID로 요청 → 404 또는 403. 요청에 owner_id를 넣어도 소유권 변경 불가
5. 비로그인 API 목록 → 401과 JSON 오류, `/aleph.json` 열림, nosniff 보안 헤더 확인
6. 5단계 완료 후에도 A/B 각각 로그인하여 화면 검증 반복

### 재실행과 제출 묶음

Vercel 자동 배포 후 로컬 VSCode의 저장소 폴더에서:

```powershell
git pull
npm.cmd run bundle
```

`bundle-notes.json`의 explanation은 4단계 변경 내용으로 수정해 두되 Git에 올리지 않음. 출력 `artifacts/submission.json`도 Git 커밋 대상이 아님.
SQL 두 파일은 실행용 계획이며 DB에 직접 적용하지 않은 상태에서는 RLS 및 B 계정 검증이 완료되었다고 기록하지 않음.

## 3단계 저장점 — 로그인 및 가상 메모 CRUD

- Supabase Auth 로그인/로그아웃과 서버 토큰 검증 적용
- GET /api/memos: 서버가 확인한 사용자 ID(owner_id)의 메모 목록
- POST /api/memos: {id?, title, body}로 추가 (id 생략 시 서버가 UUID 생성), 응답 {id}
- GET /api/memos/:id: {id, title, body} 반환
- PUT /api/memos/:id: {title, body} 수정
- DELETE /api/memos/:id: 삭제, 삭제 후 GET은 404
- api/memos.js 및 api/memos/[id].js에서 JWT를 원본 src/verify-login.mjs로 검증
- public_id UUID를 외부 메모 ID로 사용하고 DB 내부 bigint ID는 노출하지 않음
- aleph.config.json에 identityProvider 및 allowedRoutes 지정
- 비로그인/유효하지 않은 JWT 요청은 메모 없이 JSON 401 응답
- 이 단계에는 의도적으로 단건 요청의 소유자 확인이 없음. ID를 안다면 다른 로그인 계정의 메모도 변경할 수 있으며, **4단계에서 방어할 과제**임

### 3단계 저장점 — 검증과 재실행

1. A 계정 로그인 → 기존 가상 메모 네 건 확인
2. 기존 네 건은 그대로 두고, **새 테스트 메모 1건**을 추가
3. 새 메모를 수정하고 삭제. 삭제된 메모 ID에 대한 직접 GET 요청은 404인지 별도로 점검
4. 로그아웃 후 메모 화면이 사라지는지 확인
5. 비로그인 상태에서 /api/memos 직접 호출 시 JSON 오류 및 401/403 확인
6. 브라우저 코드와 응답에 SUPABASE_SECRET_KEY가 없는지 확인
7. 배포 /aleph.json 및 nosniff 헤더 확인

로컬에서 최신 제출 묶음을 만들 때:

```powershell
git pull
npm.cmd run bundle
```

출력 파일은 `artifacts/submission.json`이며 `.gitignore`에 포함되어 GitHub에 커밋하지 않음. `bundle-notes.json`의 explanation은 3단계 작업을 설명하도록 로컬에서 갱신할 것.

단건 메모를 검사할 때는 테스트용 메모 UUID를 사용함. 실제 비밀번호·토큰·서버 전용 키는 Git이나 제출 기록에 남기지 않음.

## 2단계 저장점

정적 파일에 있던 가상 메모를 학습용 Supabase로 옮기고, 화면은 Vercel 서버 함수 `/api/memos`를 통해 읽도록 변경했습니다.

- `supabase/step2-memos.sql`: `owner_id uuid`, RLS 활성화, `anon`·`authenticated` 직접 권한 제거, `auth.users` 외래키 없음
- `data.json`, `public/data.json`: 메모 0건 유지
- `scripts/build-public.mjs`: 2단계 이후 빌드에서 공개 메모를 다시 복사하지 않음
- `api/memos.js`: 서버에서 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수를 읽어 학습용 메모 조회
- `public/index.html`: 브라우저는 서버 API만 호출해 카드 표시
- `aleph.config.json`: 2단계와 실제 GitHub/Vercel 주소 반영
- `vercel.json`: 첫 화면을 포함한 응답에 `X-Content-Type-Options: nosniff` 헤더 적용

## Vercel 환경변수

Vercel 프로젝트 설정의 비밀 입력란에 아래 이름을 사용합니다. 값 자체는 GitHub, 브라우저 파일, 응답, 로그에 넣지 않습니다.

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY`

## 앞 단계 약점의 보완

2단계 공개 API는 3단계에 인증을 적용했고, 3단계 단건 IDOR는 4단계에 서버 측 owner_id 필터를 추가함. 데이터베이스 최소 권한/RLS 적용 여부는 SQL을 실행한 뒤 별도로 확인해야 함.

## 최신 파일 확인 결과

GitHub 기본 브랜치에서 아래 1단계 가상 메모 본문 문장을 각각 검색했습니다.

- `실습용 가상 과제 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 포트폴리오 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 리추얼 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 행정 기록`: 최신 파일 검색 결과 없음

배포 주소의 `/data.json`도 `notes: []` 상태인지 직접 확인합니다. 첫 화면은 정적 파일이 아니라 `/api/memos`를 통해 Supabase의 가상 메모를 읽습니다.

## 과거 공개 이력의 한계

최신 GitHub 파일과 현재 정적 배포에서 메모 문장을 제거했더라도, 이미 만들어진 과거 공개 커밋이나 옛 Vercel 배포가 남아 있는 동안 과거 노출 자체가 해소됐다고 표현하지 않습니다. 2단계에서 확인한 것은 최신 파일과 현재 배포의 정적 노출 경로를 제거한 상태입니다.

## 2단계 당시 직접 확인 절차

1. 배포 주소의 `/`에서 Supabase의 가상 메모 네 건이 표시되는지 확인합니다.
2. `/data.json`을 직접 열어 `notes`가 0건인지 확인합니다.
3. `/aleph.json`을 열어 저장소·커밋·배포 정보가 현재 배포와 맞는지 확인합니다.
4. GitHub 최신 파일에서 위 네 가상 메모 본문 문장을 각각 검색해 결과가 없는지 확인합니다.
5. 2단계 당시 `/api/memos` 비로그인 접근 가능 약점을 기록. 3단계 이후에는 401 JSON 오류로 거부함.
6. 첫 화면 응답 헤더에 `X-Content-Type-Options: nosniff`가 있는지 확인합니다.

## 빌드

Vercel은 `vercel.json`의 `npm run build`를 실행하고 `public`을 배포합니다. 빌드 과정에서 `public/aleph.json`을 자동 생성합니다.
