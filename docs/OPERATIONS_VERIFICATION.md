# 1~11단계 통합 검증표 절차

이 문서는 탈환 작전실의 통합 검증표가 무엇을 기록하는지 설명한다. 표는 브라우저 메모리에만 존재하며 정적 JSON, localStorage, sessionStorage, IndexedDB 또는 서버에 시험 결과를 저장하지 않는다.

## 기록 원칙

- 실제 HTTP 응답이 없는 후보는 `미실행`이며 통과 수에 포함하지 않는다.
- `clientCaseId`는 브라우저가 표 행을 구분하는 비밀값 없는 순번이다. 서버 request ID가 아니다.
- 서버가 request ID나 서버 시각을 주지 않으면 각각 `null`과 `없음`으로 남긴다.
- HTTP 500 이상, 응답 형식 오류, 네트워크 오류는 보안 차단 통과가 아니라 `검증 실패` 또는 미실행으로 취급한다.
- 경로는 `/api/memos/:id`처럼 일반화한다. 실제 UUID, query 값, 요청 본문, assertion, nonce, challenge, 쿠키, 토큰은 기록하지 않는다.
- 오류 코드는 이미 구현·문서화된 허용 목록만 기록한다. 그 밖의 응답 문자열은 버린다.

각 실제 기록은 단계, 시험 식별자·목적, 정상/금지 구분, 환경, HTTP method, 일반화 경로, 기대 상태·오류 코드, 실제 HTTP 상태·오류 코드, 서버 request ID, 서버 시각, clientCaseId, 클라이언트 실행·확인 시각, 실행 출처, 실행 상태, 비교 결과, 근거와 한계를 분리한다.

## 현재 연결된 실제 관찰

승인 기기로 연결한 뒤 기존 UI의 서명된 `GET /api/memos`가 HTTP 200과 배열 응답을 모두 확인하면, 작전실은 해당 관찰 한 건을 `approved_signed_memo_list`로 기록한다. 이 동작은 새 요청을 만들지 않고 기존 자료실 조회 결과만 요약한다.

승인된 작전실 화면에서 사용자가 **비로그인 조회 차단 확인**을 직접 누르면 `credentials: 'omit'`인 읽기 전용 `GET /api/memos`를 한 번 보낸다. Authorization 헤더와 요청 본문은 없으며 상태 변경 요청은 하지 않는다. 실제 응답이 정확히 HTTP 401 및 `AUTH_REQUIRED`일 때만 `unauthenticated_memo_list`의 금지 요청 거부로 기록한다. 네트워크 오류, 다른 상태, 다른 오류 코드는 통과가 아니다. 이 기록은 브라우저 메모리에만 있으며 로그아웃·기기 연결 해제 시 지워진다.

`/aleph.json` 및 `/api/devices`의 수동 확인은 작전실의 배포·기기 상태 카드에만 사용한다. 이 응답들은 메모 보호 요청 또는 1~11단계 시험 실행으로 기록하지 않는다.

## 후보와 출처

| 단계 | 후보 | 종류 | 출처 | 기본 상태 |
| --- | --- | --- | --- | --- |
| 3 | unauthenticated_memo_list | 금지 | `api/memos.js` 인증 게이트 · 사용자 요청 cookie-free GET | 미실행 |
| 4 | foreign_memo_scope | 금지 | `api/memos.js` 소유자 필터 | 미실행 |
| 10 | verified_restore_preview | 정상 | `api/restore/[id].js` | 미실행 |
| 10 | restore_owner_or_backup_rejection | 금지 | `api/restore/[id].js` | 미실행 |
| 11 | approved_signed_memo_list | 정상 | 기존 `signedFetch` 흐름 | 실제 응답이 있을 때만 기록 |
| 11 | unapproved_device_rejected | 금지 | `src/device-auth.mjs` | 미실행 |
| 11 | unsigned_protected_request | 금지 | `docs/DEVICE_REQUEST.md` | 미실행 |
| 11 | bound_path_or_query_rejected | 금지 | `docs/DEVICE_REQUEST.md` | 미실행 |
| 11 | bound_body_rejected | 금지 | `docs/DEVICE_REQUEST.md` | 미실행 |
| 11 | nonce_reuse_rejected | 금지 | `docs/DEVICE_REQUEST.md` | 미실행 |

공식 41종 공격의 식별자와 개별 실행 수단은 아직 제공되지 않았으므로 이 표나 작전실은 이를 공식 실행 결과로 만들지 않는다.

1·2·5·6·7·8·9단계는 현재 작업본에서 재현 가능한 HTTP 시험 정의와 안전한 실행 수단을 함께 확인하지 못했다. 통합 검증표에는 각 단계를 **시험 정의 미확인 · 미실행** 행으로 표시한다. 이 행에는 가상 요청·예상 HTTP 상태·통과 기록을 만들지 않으며, 공식 41종 검사에 포함하거나 실제 실행 건수로 계산하지 않는다.

## 운영·격리 실행 경계

운영에서는 승인 기기의 기존 읽기 전용 자료 조회만 화면에서 관찰한다. 소유자 교차 접근, 서명 누락·변조, nonce 재사용, 복원, 수정·삭제, 기기 상태 변경은 운영에서 실행하지 않는다.

그 항목은 별도 승인된 격리 환경에서만, 매번 새로운 WebAuthn assertion을 사용해 실행한다. 결과를 표에 연결하는 후속 기능이 생기더라도 HTTP 상태·허용 오류 코드·서버 제공 request ID/시각만 전달해야 한다. 성공·거부 뒤에는 새로운 서명 GET으로 데이터 변경이 없음을 별도로 확인한다.
