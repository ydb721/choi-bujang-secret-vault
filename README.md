# BYTE BACK 방어전 R5

이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 2단계

정적 파일에 있던 가상 메모를 학습용 Supabase로 옮기고, 화면은 Vercel 서버 함수 `/api/memos`를 통해 읽도록 변경했습니다.

- `data.json`, `public/data.json`: 메모 0건 유지
- `scripts/build-public.mjs`: 2단계 이후 빌드에서 공개 메모를 다시 복사하지 않음
- `api/memos.js`: 서버에서 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수를 읽어 학습용 메모 조회
- `public/index.html`: 브라우저는 서버 API만 호출해 카드 표시
- `aleph.config.json`: 2단계와 실제 GitHub/Vercel 주소 반영

## Vercel 환경변수

Vercel 프로젝트 설정의 비밀 입력란에 아래 이름을 사용합니다. 값 자체는 GitHub, 브라우저 파일, 응답, 로그에 넣지 않습니다.

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY`

## 현재 남은 약점

2단계의 `/api/memos`는 공개 주소입니다. 서버 전용 키는 브라우저에 노출하지 않지만 로그인하지 않은 사용자도 API를 호출할 수 있습니다. 이 인증 문제는 3단계에서 해결합니다.

## 확인

- 첫 화면에서 Supabase의 가상 메모 카드가 보이는지 확인
- `/data.json`을 직접 열었을 때 메모가 0건인지 확인
- `/aleph.json`이 열리고 저장소·커밋·배포 주소가 현재 배포와 맞는지 확인

## 빌드

Vercel은 `vercel.json`의 `npm run build`를 실행하고 `public`을 배포합니다. 빌드 과정에서 `public/aleph.json`을 자동 생성합니다.
