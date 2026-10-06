# BYTE BACK 방어전 R5

이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 3단계 — 로그인 및 가상 메모 CRUD

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

### 3단계 실습 확인

1. A 계정 로그인 → 기존 가상 메모 네 건 확인
2. 기존 네 건은 그대로 두고, **새 테스트 메모 1건**을 추가
3. 새 메모를 수정하고, 같은 메모를 삭제한 뒤 다시 GET 요청 시 404 확인
4. 로그아웃 후 메모 화면이 사라지는지 확인
5. 비로그인 상태에서 /api/memos 직접 호출 시 JSON 오류 및 401/403 확인
6. 브라우저 코드와 응답에 SUPABASE_SECRET_KEY가 없는지 확인
7. 배포 /aleph.json 및 nosniff 헤더 확인

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

## 현재 남은 약점

2단계 당시 `/api/memos`는 공개 주소였으나, 3단계에서 토큰 검사를 적용함. 아직 **단건 조회·수정·삭제에 소유자 확인이 빠져 있는 상태**이며 4단계에서 막을 예정임.

## 최신 파일 확인 결과

GitHub 기본 브랜치에서 아래 1단계 가상 메모 본문 문장을 각각 검색했습니다.

- `실습용 가상 과제 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 포트폴리오 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 리추얼 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 행정 기록`: 최신 파일 검색 결과 없음

배포 주소의 `/data.json`도 `notes: []` 상태인지 직접 확인합니다. 첫 화면은 정적 파일이 아니라 `/api/memos`를 통해 Supabase의 가상 메모를 읽습니다.

## 과거 공개 이력의 한계

최신 GitHub 파일과 현재 정적 배포에서 메모 문장을 제거했더라도, 이미 만들어진 과거 공개 커밋이나 옛 Vercel 배포가 남아 있는 동안 과거 노출 자체가 해소됐다고 표현하지 않습니다. 2단계에서 확인한 것은 최신 파일과 현재 배포의 정적 노출 경로를 제거한 상태입니다.

## 직접 확인 절차

1. 배포 주소의 `/`에서 Supabase의 가상 메모 네 건이 표시되는지 확인합니다.
2. `/data.json`을 직접 열어 `notes`가 0건인지 확인합니다.
3. `/aleph.json`을 열어 저장소·커밋·배포 정보가 현재 배포와 맞는지 확인합니다.
4. GitHub 최신 파일에서 위 네 가상 메모 본문 문장을 각각 검색해 결과가 없는지 확인합니다.
5. `/api/memos`를 비로그인 상태에서 호출할 수 있는 현재 단계의 약점을 별도로 기록합니다.
6. 첫 화면 응답 헤더에 `X-Content-Type-Options: nosniff`가 있는지 확인합니다.

## 빌드

Vercel은 `vercel.json`의 `npm run build`를 실행하고 `public`을 배포합니다. 빌드 과정에서 `public/aleph.json`을 자동 생성합니다.
