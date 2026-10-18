# BYTE BACK 보호 자료실

## 현재 확정 상태 (2026-10-18)

- 운영 저장소: https://github.com/ydb721/choi-bujang-secret-vault / 운영 배포: https://choi-bujang-secret-vault-pink.vercel.app
- 10단계 100/100 및 11단계 100/100은 사용자가 제공한 심판 결과 스크린샷으로 확인한 기록입니다. 11단계 최종 검증 커밋은 `e2b71097b641bccb8430c898cf65d416b569bd41`입니다.
- Release A/B 운영 배포 완료와 Vercel Serverless Function 12개는 사용자 제공 운영 기록입니다.
- 이 작업본은 `aleph.config.json` step 12의 제작 1·2·3 통합 **저장점**입니다. 12단계 작전실의 운영 배포 완료는 사용자 제공 기록으로 확인했습니다.
- 12단계 초기 공식 심판에서는 `S12_BUNDLE_UNSUPPORTED`로 0/100점이 반복되었습니다. 격리 실행에서 지원되지 않은 Git 하위 명령과 `node:fs`의 `statSync`, `URL.searchParams.set()` 사용을 순서대로 제거한 이력은 보존합니다.
- 이전 공식 최고 기록은 **45/100점**, 당시 실패 코드는 `S12_SCREEN_MISMATCH`였습니다. 이 결과 뒤 제출 자기점검의 `attackAttempts`가 실제 HTTP 상태·오류 코드·`not_run`을 보존하도록 1차 수정했고, 작전실이 서버의 `X-Byteback-Trace` 요청 ID를 연결하도록 2차 수정했습니다.
- 2026-10-18 확인된 `main`과 Vercel Production의 배포 커밋은 `a36a8ecba2a938019c2a650d087e424f16433448`로 일치합니다. 이전 `feature/step12-attack-records`의 요청 ID·자기점검 보완은 이 커밋에 포함되어 운영 반영된 상태입니다.
- 이후 공식 심판은 `runner_task_environment:bundle:run_bundle_capability_unsupported:network_address_scope` / `UNV_RUN_ENVIRONMENT`를 반환했습니다. 심판 격리 환경에서 실행을 완료하지 못해 공식 최고점 45/100이 유지되었으며, 이 결과는 12단계 공격 방어의 통과 또는 실패 증거가 아닙니다.
- 공식 41종 총공세 전체 통과, 12단계 100/100점 또는 실제 SDP 엔진 연동 성공을 주장하지 않습니다.
- 현재 배포의 실제 커밋은 `/aleph.json`의 `commit` 필드와 GitHub 커밋을 대조하여 별도로 확인합니다.

## 12단계 제작 3 — 재현·운영 경계 안내

이 절은 11단계 심판 기록 커밋 `e2b71097b641bccb8430c898cf65d416b569bd41`와 12단계 운영 기준 커밋 `a36a8ecba2a938019c2a650d087e424f16433448`를 구분한다. 제출 자기점검 및 서버 요청 ID 보완은 운영 기준 커밋에 반영되었다. 공식 12단계 최고점은 45/100이며, 최근 심판은 `UNV_RUN_ENVIRONMENT`로 실행 검증에 실패했다. 공식 41종 총공세 전체 결과는 확인되지 않았다. 아래 오래된 단계별 기록은 당시의 실험·배포 이력이다.

### 시스템 구성과 제공 엔진 경계

| 구성요소 | 구현·책임 | 확인 상태 |
| --- | --- | --- |
| ALEPH SDP 엔진(제공) | `aleph.decision.v1` 판정 요청 계약을 검증·전달하고 학생 판정 결과를 소비하는 제공 측 엔진이다. | 실제 운영 엔진의 연결·전달·회수 집행은 이 저장소에서 실측하지 못했다. |
| 학생 판정기 | `src/decider.mjs`의 `decide(request)`가 계약상 입력만 사용해 `allow`·`deny`·`step_up`을 돌려준다. 규칙은 `device_registered`, `step_up_required`, `resource_scope`다. | `npm run decider:test`는 가상 요청 연습이며 실제 엔진 판정이 아니다. |
| 학생 탐지 규칙 | `src/detect.mjs`가 `docs/DETECT_EVENTS.md`의 가상 사건을 읽어 관찰 또는 `propose_revocation`을 반환한다. 10분 내 동일 주체 GET가 120건을 **초과**하면 `burst_read` 회수 제안을 만든다. | 제안은 실제 회수 API 실행이 아니며 운영 엔진 사건 연동도 미검증이다. |
| 접속 앱·자료실 | PWA manifest·서비스 워커, Supabase 로그인, 기기 등록/승인, WebAuthn 요청 서명, 메모·공지 소유권 검사, 검증된 복원, 탈환 작전실을 제공한다. | 보호 API·DB가 필요한 흐름은 올바른 서버 환경과 승인 기기가 있어야 한다. |

`docs/DECIDER_REQUEST.md`는 18개 요청 필드와 `schema`, `requestId`, `decision`, `reasonCode`, `ruleIds`의 5개 응답 필드를 정의한다. 브라우저가 보낸 역할·기기·신원 추정값을 학생 판정기에 새 계약 필드로 만들지 않는다. `docs/DETECT_EVENTS.md`의 사건도 가상 입력 형식이며 실제 접속 로그가 아니다.

제작 1에서 `src/detect.mjs`에 추가한 `DETECTION_CONTRACT` export는 기존의 10분·120건 초과·`propose_revocation`·`burst_read` 상수를 공개 작전실 요약에 재사용할 뿐이다. 탐지 알고리즘, 반환 모양, 회수 제안 계약은 기준 커밋과 달라지지 않았다.

### 깨끗한 설치와 로컬 검증

필수 환경은 Node.js 22 이상과 Git이다. 비밀값은 저장소나 명령줄에 넣지 않는다.

```powershell
git clone https://github.com/ydb721/choi-bujang-secret-vault.git
Set-Location choi-bujang-secret-vault
npm.cmd install
npm.cmd run operations:test
npm.cmd run verification:test
npm.cmd run device:test
npm.cmd run pwa:test
npm.cmd run recovery:test
npm.cmd run policy:test
npm.cmd run decider:test
npm.cmd run detect:test
npm.cmd run build -- --local
```

- `operations:test`·`verification:test`은 12단계 로컬 UI/기록 분리 시험이다.
- `decider:test`와 `detect:test`는 각각 가상 판정 요청·가상 탐지 사건 연습이다.
- `build -- --local`은 정적 공개 자료를 만들며 배포 식별 환경변수를 요구하지 않는다. 일반 `npm run build`는 Vercel이 주입하는 배포 메타데이터가 있어야 한다.
- 정적 PWA 확인은 `node scripts/serve-pwa.mjs` 뒤 `http://127.0.0.1:4173/`을 연다. 이 서버는 `/api/*`를 503으로 거부하며 운영 API, 로그인, DB, 기기 승인을 제공하지 않는다. 종료는 그 터미널에서 `Ctrl+C`다.
- 로컬 자동 시험은 완료되면 자체 종료한다. 이는 운영 서비스를 중지하는 작업이 아니다.

서버 인증·자료실 API·WebAuthn 흐름에는 배포 환경의 `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`가 필요하다. `ALEPH_RESOURCE_BINDINGS`는 판정기 자원 바인딩을 제공하는 선택 환경변수다. 배포 빌드는 Vercel의 `VERCEL_GIT_PROVIDER`, `VERCEL_GIT_REPO_OWNER`, `VERCEL_GIT_REPO_SLUG`, `VERCEL_GIT_COMMIT_SHA`, `VERCEL_URL`을 사용한다. 이름과 용도만 문서화하며 값은 출력·커밋·업로드하지 않는다.

### 실행 기록의 신뢰도와 통합 검증표

탈환 작전실은 다음 상태를 섞지 않는다: 운영 API 실측, 사용자 제공 실제 심판 판정 기록, 로컬 테스트, 가상 입력 연습, 미실행, 미연동, 검증 실패. 11단계 100/100은 사용자 제공 심판 결과 스크린샷으로 확인한 사실이지만 12단계 공식 41종 공격의 실행·통과 증거가 아니다.

`docs/OPERATIONS_VERIFICATION.md`는 1~11단계 통합 표의 필드와 후보를 설명한다. 표는 실제 HTTP 응답이 있을 때만 메모리에 기록하며 서버 request ID가 없으면 `null`로 남긴다. clientCaseId는 서버 ID가 아니고, 경로는 일반화하며 메모 본문·토큰·쿠키·assertion·nonce·challenge·UUID를 저장하지 않는다. 공식 41종의 식별자와 실행 기록은 확보되지 않았으므로 임의로 41/41 성공으로 표시하지 않는다.

### 중지·복구·롤백 절차

1. 먼저 `git status`와 `git diff`로 현재 작업과 되돌릴 파일을 확인한다. 정상 커밋은 `git show e2b71097b641bccb8430c898cf65d416b569bd41 --stat`으로 확인한다.
2. 특정 파일만 기준 커밋으로 되돌릴 때는 다른 미커밋 변경을 먼저 검토·보존한 뒤 `git restore --source=e2b71097b641bccb8430c898cf65d416b569bd41 -- 경로/파일`을 사용한다. `git reset --hard`는 사용하지 않는다.
3. 코드 배포 롤백은 Vercel 대시보드에서 확인한 이전 정상 배포를 선택·승격하는 운영 절차다. `/aleph.json`의 commit과 대상 GitHub 커밋이 일치하는지 확인한 뒤에만 완료로 기록한다. 이는 DB 복구와 별개다.
4. 운영 DB는 Supabase Free 자동 백업에 의존하지 않는다. 승인된 운영 절차로 만든 수동 `pg_dump` 백업은 저장소 밖에 보관한다. DB 복구는 별도 승인·보존 정책·서비스 중단 범위를 검토한 뒤 수행하며, 이 문서는 실제 DB 복원 시험 성공을 주장하지 않는다.
5. 메모 복원은 먼저 검증된 사본의 소유자·해시·버전을 서버에서 검증하고 읽기 전용 미리보기를 확인한 뒤에만 실행한다. 실행 후에는 별도의 정상 조회로 결과를 확인한다. 실행하지 않았다면 미실행으로 남긴다.
6. 정책 복원은 기본적으로 `npm.cmd run policy:restore`로 미리보기만 한다. 변경 범위와 계획 확인값을 검토하지 않은 `--apply` 실행은 하지 않는다. 실제 적용·롤백 결과는 별도 기록이 필요하다.

운영 배포 상태는 Vercel 대시보드 또는 공개 `/aleph.json`에서 읽기 전용으로 확인한다. 로컬 정적 서버의 `Ctrl+C`는 운영 Vercel 서비스를 중지하지 않는다.

## 과거 11단계 제작·검증 이력 (2026-10-15 당시 기록)

- 현재 운영 버전은 [운영 `/aleph.json`](https://choi-bujang-secret-vault-pink.vercel.app/aleph.json)의 **`commit` 필드**로 확인한다. README에는 현재 버전의 SHA를 고정하지 않으며, 아래 고정 SHA는 당시 검증·제출·배포 이력을 식별한다.
- 이전 검증·심판 제출 기준 커밋: `6bfddf6844c872492f34acde09c38c3779453f5d` (`6bfddf6`). 현재 운영 버전을 뜻하지 않는다.
- 저장소: https://github.com/ydb721/choi-bujang-secret-vault
- 운영 배포: https://choi-bujang-secret-vault-pink.vercel.app
- **10단계 100/100점**은 사용자가 확인한 심판 결과다(기준 커밋 `9928c4813bf430435755371850cbf17d7011d0d5`). 이번 작업에서 판정 카드나 심판 증거를 새로 검증한 것은 아니다. **11단계 목표는 100/100점**이며 아직 판정받지 않았다.
- 사용자 전달 과거 심판 응답: `6bfddf6`로 **2회 제출**, 두 번 모두 **`UNV_AMBIGUOUS`**. 세 가지 공격 시나리오 모두 판정 불가로 전달되었다.
- 이는 당시 실패 판정이 아니라 심판의 판정 불가 응답이었다. 개별 오류의 직접 원인은 규명하지 않았으며, 이후 사용자가 확인한 10단계 100점 결과와 구분한다.
- 심판 기록 카드에서 확인한 코드는 `UNV_AMBIGUOUS`이며 실제 호출 URL·메서드·HTTP 상태·응답 내용은 확보하지 못했다.
- UUID 소유권 비교 수정·회귀 시험 6개·검증 증거 정리는 GitHub에 커밋됐고 운영 배포 반영도 확인했다. 아래 격리 시험은 운영 서버의 실제 복원 시험과 별개다. 11단계 제작 1·2의 PWA·기기 서명 변경은 로컬 구현이며 미커밋·미배포·미제출 상태다.

브라우저에서 위 `/aleph.json` 링크를 열거나 PowerShell에서 `(Invoke-RestMethod -Uri 'https://choi-bujang-secret-vault-pink.vercel.app/aleph.json').commit`을 실행한다. 정상 응답은 GitHub에서 확인한 배포 대상 커밋과 일치해야 하며, 불일치하면 배포 반영 완료로 기록하지 않는다.

## 11단계 제작 1 — PWA와 기기 상태 안내 (이전 로컬 검증 이력)

- manifest·192/512px 아이콘·설치 안내·서비스워커·오프라인 화면을 추가했다. 설치 이벤트를 지원할 때만 설치 버튼을 표시한다. 앱 설치는 서버 기기 승인을 의미하지 않는다.
- 제작 1 당시에는 서버 승인 API가 없어 **기기 승인 미확인**으로 표시했다. 아래 제작 2에서 실제 서버 상태와 요청 서명을 연결했다. 운영 적용은 별도 승인 전이며 `config.step`은 10으로 유지한다.
- 제작 1의 서비스워커는 고정된 공개 파일 6개만 자격 증명 없이 캐시한다. `/api/`, 인증·메모·공지·복원 응답과 온라인 문서는 캐시하지 않는다. 오프라인 문서 이동에는 보호 내용이 없는 안내만 제공하고, 열려 있던 화면도 오프라인 전환 시 메모와 복원 계획을 비운다.
- 제작 1의 캐시 이름은 `byteback-public-v1`이었다. 현재 후보는 제작 2 공개 모듈을 포함하는 `byteback-public-v2`(9개 파일)이며 공개 자산 변경 시 버전을 올린다. 새 워커는 자기 접두사의 구버전 캐시만 제거한다. 토큰·개인키·가짜 승인 상태를 브라우저 저장소에 기록하지 않는다.
- 로컬 확인: VS Code **터미널 → 새 터미널**에서 `node scripts/serve-pwa.mjs`를 실행하고 `http://127.0.0.1:4173/`을 연다. 이 도구는 정적 PWA 전용이며 로그인·메모·복원 API는 503으로 거부하고 운영 서버에 연결하지 않는다.
- 브라우저 **개발자 도구 → Application**에서 manifest·아이콘·서비스워커와 공개 캐시만 있는지 확인한다. 네트워크를 Offline으로 바꾸고 일반 새로고침하면 오프라인 안내가 표시되어야 한다. `/api/` 요청이 캐시나 오프라인 HTML로 성공해서는 안 된다. 설치 자체로 기기 승인이 바뀌어서는 안 된다. 정적 확인 서버에는 승인 API가 없으므로 실제 승인·서명은 확인할 수 없다.
- 자동 브라우저 도구는 환경 오류로 실행되지 않아 실제 설치·standalone 실행·실제 브라우저 오프라인 전환은 **미검증**이다. Node VM의 이벤트·캐시·화면 모의 시험은 브라우저 실측 및 운영 로그인·DB 시험과 구분한다.
- 제작 1 당시 실행 결과: Node 시험 **70개 통과 / 실패 0개**(신규 PWA 12개·기존 메모/복원 40개·기타 회귀 18개), 판정기 가상 4사례·탐지 가상 6사례 통과. 정적 localhost HTTP 요청 17건, 로컬 빌드 `npm.cmd run build -- --local`, `git diff --check`도 통과했다. 과거 시작 틀 검사 실패와 커밋을 만드는 제출 묶음 시험은 이번에 재실행하거나 변경하지 않았다.

## 11단계 제작 2 — 서버 기기 승인과 요청 서명 (운영 미적용)

- WebAuthn 라이브러리로 공개키 등록과 사용자 확인을 검증하고 등록 직후에는 **승인 대기**로 저장한다. 최초 기기도 자동 승인하지 않는다. 첫 승인은 신뢰 가능한 운영자가 본인 확인과 공개키 전체 지문 대조 후 비공개 DB 함수로 수행해야 한다. 이후에는 승인된 본인 기기의 서명으로 다른 기기를 승인·거부·회수할 수 있다.
- 메모·공지·복원 API는 기존 JWT·소유권·백업 검사에 추가로 승인 기기 증명을 요구한다. 증명은 사용자·세션·실제 메서드·경로·쿼리·원시 본문 SHA-256·일회 nonce 및 90초 만료에 연결된다. 서버가 서명 검증 후 실제 요청을 다시 비교하며 DB 잠금 안에서 승인·nonce·카운터를 원자적으로 검사한다.
- UI는 서버 상태를 표시하고 **승인 기기로 연결**에서 서명한 조회가 성공해야 메모를 표시한다. 각 작업에는 새 인증장치 확인이 필요하며 쓰기 후에는 **메모 새로 읽기**를 누른다. 회수 감지·인증/기기 거부·로그아웃·오프라인에서 자료를 숨긴다. 토큰·개인키·승인 플래그·서명 응답을 브라우저 저장소나 서비스워커에 저장하지 않는다.
- 신규 SQL은 별도 기기 등록부·challenge·추가 전용 감사 표와 서비스 전용 RPC만 준비한다. 운영 DB에는 적용하지 않았다. API 함수는 9개에서 **10개**가 되며 기존 12개 제한 안이다. 기존 10단계 SQL·복원 경로·로그인 발급자·허용 경로·판정기 18개 입력/5개 출력·규칙은 유지한다.
- 이 후보의 보호 API는 서명을 즉시 강제하며 우회 옵션이 없다. **초기 승인과 전환 계획 없이 배포하면 자료실이 잠기므로 배포하지 않는다.** 실제 운영 적용·단계 11 전환은 별도 승인 대상이다.
- 구현 계약·실패 상태와 한계는 [기기 요청 계약](docs/DEVICE_REQUEST.md), 운영자 신원 확인·첫 승인·전환 순서는 [운영 적용 준비](docs/DEVICE_ROLLOUT.md)를 따른다. 제공된 공식 자료에는 HTTP 기기 서명 형식이 없어 실제 심판·반 엔진과의 호환성은 미확인이다.
- WebAuthn은 승인 키의 서명을 검증하지만 PWA 설치 사실이나 인증장치의 하드웨어 비추출성까지 증명하지 않는다. 동기화/백업 credential은 거부한다. 실제 브라우저·인증장치 및 Vercel 원시 본문 전달은 배포 전 추가 확인이 필요하다. 회수는 새 요청을 차단하며 이미 승인 검사 후 실행 중인 업무 트랜잭션을 취소하지는 않는다.
- 로컬 검증: `npm.cmd run device:test`, `npm.cmd run pwa:test`, `npm.cmd run recovery`, `npm.cmd run policy`, `npm.cmd run decider`, `npm.cmd run detect`, `npm.cmd run build -- --local`. 정상 승인·서명 요청은 기존 권한 범위에서 성공하고 서명 없음·경로/본문 변조·미승인·만료·재사용은 보호 자료를 노출하거나 업무 데이터를 변경하지 않아야 한다. 가상 시험은 실제 심판 통과 증거가 아니다.

### 제작 2 검증 기록 (2026-10-15, 로컬·격리 DB)

| 검사 | 실제 결과와 범위 |
|---|---|
| `npm.cmd run device:test` | **80/80 통과**: 기기 55·UI 14·복원 입력 11. 시험 키로 실제 WebAuthn 서명을 검증하며 저장소/화면은 모형이다. 복원 입력 11개는 실제 복원 소스의 입력 검사와 기기 gate 결합 시험이며 복원 RPC 시험은 아니다. |
| `npm.cmd run pwa:test` | **13/13 통과**: 공개 캐시 제한·화면 회귀·원본 vendor/라이선스 일치·실제 ESM/UMD 로딩. 실브라우저 설치 시험은 아니다. |
| `npm.cmd run recovery` / `npm.cmd run policy` | **40/40**, **4/4 통과**. 기존 복원 시험은 기기 gate를 시험 전용 모형으로 분리하고 원래 백업·소유권 동작을 검사한다. |
| 기존 r5·8·9단계·정책 사본 목록·XDR 시험 | **14/14 통과**. |
| `npm.cmd run test:package` | **2개 통과·1개 기존 실패**. 시작 틀의 직계 API 2개 가정이 현재 구조와 다르다. 기준 HEAD의 원본 파일로도 같은 실패를 재현했으며 검사를 바꾸지 않았다. |
| 판정·탐지 | `npm.cmd run decider` 가상 4사례·`npm.cmd run detect` 가상 6사례 통과. 실제 엔진 연결이나 심판 통과 증거가 아니다. |
| 정책 CLI | `policy:diff`·`policy:restore`는 검증 통과·변경 범위 없음. `--apply` 없이 미리보기만 수행했다. |
| 정적 localhost HTTP | **15건 통과**: 공개 12경로 200, API 3경로 503. 실제 인증 서버는 아니다. |

위 Node 시험의 중복 없는 합계는 **154개 중 153개 통과·기존 시작 틀 실패 1개**다. 커밋을 생성하는 제출 묶음 시험은 실행하지 않았다.

별도 빈 시험 DB에서 만든 Neon PostgreSQL 브랜치에 **신규 기기 SQL만** 적용했다. 권한·상태 전이·감사 표 변경 금지·nonce/CAS 병렬 경쟁을 검사했고, 기존 메모·백업·정책·감사 데이터 및 운영 인증/HMAC 비밀키를 복사하지 않았다. 핵심 공격을 포함한 **HTTP 46건·22개 시나리오가 통과**했다. 서명 없음·경로/본문 변조는 403 및 메모 전후 해시 동일, 승인 기기의 정상 PUT와 독립 GET은 200, 타인 메모는 404, JWT 없음은 401이었다. nonce 동시 재사용은 200 하나·403 하나였다.

이 HTTP 시험은 실제 Node 서버·기존 JWT 검증 코드·실제 WebAuthn 암호 검증·실제 PostgreSQL RPC를 연결하지만 **PostgREST 전송은 SQL 어댑터**이고 인증장치는 일회성 소프트웨어 모형이다. JWT도 시험 발급자/키를 사용한다. 측정 시간에는 MCP SQL 브리지 대기가 포함되어 운영 Vercel 성능 자료로 사용할 수 없다. 시험 서버는 종료했다. 실제 브라우저/인증장치·운영 Supabase·Vercel 원시 본문 전달·실제 심판의 서명 계약은 미확인이다.

검증 중 신규 원시 본문 처리기가 잘못된 JSON을 빈 복원 명령처럼 해석하는 회귀를 발견해 수정했다. 이제 빈 본문과 `{}`만 기존대로 처리하며, `null`·잘못된 JSON·JSON 문자열은 400으로 거부한다. 원시 바이트는 보존하고 기존 API는 기존 파서, 신규 기기 API는 자체 파서로 각각 한 번만 해석한다. 수정 후 기기·UI·복원 입력 80개와 기존 복원 40개·정책 4개가 통과했다.

위 전체 22개 시나리오의 유효 JSON 흐름 검증 후, 본문 처리 수정이 반영된 **최종 소스로 핵심 8개 시나리오·HTTP 21건을 추가 재시험하여 통과**했다. 서명 없음·JWT 없음·경로/본문/쿼리/메서드 변경 거부와 정상 PUT·독립 GET을 다시 확인했다. 중복되는 조건이므로 전체 22개와 재시험 8개를 합쳐 30개 조건이라고 기록하지 않는다. 최종 소스의 잘못된 복원 입력 거부는 위 별도 11개 입력 회귀로 확인했으며, 그 입력 회귀가 실제 복원 RPC 시험이라는 뜻은 아니다.

## 10단계 실제 복원 구현 및 안전 조건

### 메모 복원 API

1. JWT를 검증하고 인증된 `sub`만 소유자 판단에 사용한다. 메모 요청 본문의 `owner_id`, `ownerId`, `userId`, `subjectId`, `role` 주장은 거부하며 DB의 메모 ID·소유자 필터를 유지한다.
2. 신규 메모는 생성 트랜잭션의 INSERT 트리거에서 비공개 `on_create` 최초 사본을 저장한다. PUT·DELETE와 삭제 후 재생성은 최초 사본을 덮어쓰지 않는다. 기존 B `legacy` 사본은 별도의 고정 지문·시각으로 검증한다.
3. 제출 경로는 `POST /api/restore/:id`이고 설정의 `restoreRoute` 값은 `/api/restore/:id`이다. `POST /api/restore`는 본문의 `id`를 같은 처리기로 전달하는 호환 경로다. 본문 생략·`{}`는 실제 복원, `{"preview":true}`는 읽기 전용 미리보기다. 선택적 `expectedVersion`·`expectedState`를 지원하며 그 외 필드와 `preview:false`는 400으로 거부한다.
4. 사본을 다시 읽어 소유자·SHA-256과 신뢰 근거를 확인한다. 신규 사본은 DB 내부 키의 HMAC을 검증하고, legacy 사본은 고정 버전·백업 시각을 대조한다. 사본 없음·타인 소유는 404, 무결성·신뢰 검증 실패는 409로 중단한다. 미인증은 401이다.
5. 미리보기에서 사본 버전·백업 시각·대상 상태 버전·변경 항목을 제공한다. 실제 복원은 실행 직전 사본을 재조회하고, DB 잠금 안에서도 사본·대상 상태를 재검증한다. 버전이나 상태가 달라지면 복원하지 않는다.
6. 검증된 사본으로 지정 ID 한 건만 수정하거나 같은 ID로 재생성한다. SQL 함수가 쓰기 후 실제 저장 행을 다시 읽어 ID·소유자·본문 SHA-256·사본 지문을 확인하고, API가 그 반환값을 추가 검사한다. API의 별도 GET 재조회와 혼동하지 않는다.
7. 성공 응답은 재조회한 `id`, `title`, `body`, 같은 소유자의 `ownerId`·`owner_id`, 같은 본문 해시의 `contentSha256`·`content_sha256`과 `snapshotSha256`, `backupVersion`, `verified:true`, `restored:true`를 포함한다. 본문 해시는 UTF-8 **본문만**의 SHA-256 소문자 64자리이며 사본 지문은 **제목+NUL+본문** 해시다.
8. 다른 메모·기존 사본·기존 감사 행을 보존하고 성공한 복원에 대해서만 감사 행을 추가한다. 운영 정책과 1~9단계 인증·접근제어·판정기·탐지 로직은 이 README 정리에서 변경하지 않는다.

### 운영에 반영된 UUID 소유권 수정

`api/memos.js`의 PUT 완료 후 소유권 비교 한 줄을 기존 `ownedBy()`로 통일했다. 동일 UUID의 대소문자는 같은 소유자로 처리하며 다른 UUID는 거부한다. `test/step10-memo-api.test.mjs`에는 소문자 동일·인증 ID 대문자·DB 소유자 대문자·타인·미인증·본문 신원 주장에 관한 회귀 시험 6개가 추가되어 있다. 코드와 회귀 시험의 커밋·운영 배포 반영은 확인했지만, 이 결함이 `UNV_AMBIGUOUS`의 원인이었다거나 수정으로 심판 문제가 해결됐다는 증거는 없다.

### 10단계 정책 복구 절차 — 사본 검증과 실패 시 중단

근거: `src/recovery/policy.mjs`, `scripts/policy-diff.mjs`, `scripts/policy-restore.mjs`.
이 절차는 로컬 `policy/test-policy.json`의 `services.notes` 시험 정책만 대상으로 하며 메모 복원 API와 별개이다.

1. 정책 사본 파일 `policy/safe-policy.json`의 존재를 확인한다. 복원 함수는 일반 파일인지도 검사하고 심볼릭 링크를 거부한다.
2. 사본을 파일에서 다시 읽어 SHA-256을 코드에 고정된 `TRUSTED_POLICY_SHA256`과 대조한다. 문자열의 CRLF는 LF로 정규화하여 계산한다.
3. 사본의 `capturedAt`, `verifiedAt` 형식과 시각을 확인한다. `capturedAt <= verifiedAt < RECOVERY_INCIDENT_AT`이어야 한다. 현재 기준 침해 시각은 `2026-10-13T00:00:00.000Z`이다.
4. 파일·지문·구조·시각 검증에 실패하면 복원을 실행하지 않고 중단한다. 실패한 사본을 새 지문으로 승인하지 않는다.
5. 검증된 경우에만 시험 정책의 현재 버전, 복원할 버전, 변경될 항목과 계획 확인값(`planSha256`)을 미리 보여준다.
6. 복원 실행에는 미리보기에서 받은 실제 계획 확인값을 사용한다. `restoreTestPolicy`는 확인값의 형식과 현재 계획과의 일치를 검사한다. CLI의 확인값 생략 예외는 아래 표를 따른다.
7. 실행 시 사본을 다시 읽어 지문·구조·침해 전 검증 조건을 재검증한다. 임시 파일 작성 후 원자적 교체 직전에도 사본을 다시 읽고 검증한다.
8. 그사이에 사본이 없어지거나 변조되면 복원을 중단한다. 재조회한 사본 원문이 달라져도 중단한다.
9. 시험 정책이 달라졌으면 중단한다. 이전 미리보기와 새 실행 사이 변경은 계획 확인값 불일치로, 같은 실행 안의 쓰기 직전 변경은 `POLICY_CHANGED_DURING_RESTORE`로 거부한다.
10. 모든 검증과 확인값 검사가 성공했을 때만 `services.notes`를 검증된 정책으로 교체한다.
11. 다른 서비스 정책과 기존 `audit` 배열은 보존한다.
12. 실제 운영 정책은 수정하지 않는다. 현재 시험 정책도 `stage9_verified`로 정상이며 차이가 없으므로 이번 작업에서 적용 명령을 실행하지 않는다.

| 실패 조건 | 실제 오류·동작 | 복원 결과 |
|---|---|---|
| 사본 파일 누락 | 복원 함수: `UNVERIFIED_POLICY_BACKUP` | 복원 중단 |
| 사본 SHA-256 불일치 | `UNVERIFIED_POLICY_BACKUP` | 복원 중단 |
| 침해 전 검증 근거 불충족 | 유효한 시각이지만 순서 조건 불충족: `NOT_VERIFIED_BEFORE_INCIDENT` | 복원 중단 |
| 확인값 누락·불일치 | `restoreTestPolicy`: `POLICY_PLAN_CONFIRMATION_REQUIRED` | 복원 중단 |
| 실행 직전 사본 변경·누락 | 지문 불일치·재조회 원문 변경·파일 누락: `UNVERIFIED_POLICY_BACKUP` | 복원 중단 |
| 시험 정책의 동시 변경 | 같은 실행 내 쓰기 직전 대조: `POLICY_CHANGED_DURING_RESTORE` | 복원 중단 |

실제 CLI와의 차이: `policy:diff`는 `readFile` 오류를 그대로 보고하므로 사본 누락 시 `정책 비교 중단: ENOENT ...`로 종료 코드 1을 반환한다. `policy:restore`의 확인값 **누락**은 `confirm=null`로 전달되어 `--apply`가 있어도 `applied=false` 미리보기만 수행한다(복원하지 않지만 위 확인값 오류를 내지는 않음). 빈 값·잘못된 값은 `POLICY_PLAN_CONFIRMATION_REQUIRED`로 중단한다. 시각 형식 오류는 `INVALID_BACKUP_TIME`, 사본 구조 오류는 `INVALID_POLICY_BACKUP` 또는 `INVALID_POLICY_STRUCTURE`로 중단한다. 읽기 도중의 파일 I/O 오류도 쓰기 전에 중단하며 원래 오류가 보고될 수 있다.

실행 전 비교와 미리보기(둘 다 적용하지 않음):

```powershell
npm.cmd run policy:diff
npm.cmd run policy:restore
```

복원이 필요한 시험 정책에서만, 표시된 실제 계획 확인값으로 아래 명령을 사용한다. 자리표시자를 그대로 실행하지 않는다.

```powershell
npm.cmd run policy:restore -- --apply --confirm=실제_계획_확인값
```

정상 결과는 사본 검증 통과, 현재/복원 버전 `stage9_verified`, 변경 범위 없음이다. 누락·변조 사본은 적용되지 않아야 한다. 정책 CLI에는 화면 버튼이 없으며 VS Code 터미널에서 실행한다.
### 운영 설정과 빌드

운영 비밀 설정은 Vercel의 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수로 받으며 값은 코드·문서·로그에 기록하지 않는다. Vercel은 `npm run build`로 `public`을 배포하고 `public/aleph.json`에 실제 배포 식별 정보를 생성한다. 일반 로컬 빌드는 Vercel Git·배포 식별 환경변수가 없으면 실패하도록 구현되어 있다. 이 검사를 제거하거나 가짜 값을 운영 배포 증거로 사용하지 않는다.

## 운영 검증 증거 (2026-10-15, 당시 배포 기준)

아래는 **당시 배포 `6bfddf6`에서 기존 B 계정의 legacy 사본 미리보기**에 대한 실제 Vercel 로그 증거다. 이후 배포의 재시험이나 신규 심판 메모의 실제 복원 시험과 구분한다.

| 항목 | 실제 확인값 |
|---|---|
| 시각 | 2026-10-15 12:36:33 KST |
| 배포 커밋 | `6bfddf6844c872492f34acde09c38c3779453f5d` |
| 요청 | `POST /api/restore/:id` — 대상 ID는 문서에서 생략 |
| 요청 본문 | `{"preview":true}` |
| 인증·사본 종류 | `student` · `legacy` |
| HTTP·처리 시간 | **200 · 692ms** |
| 사본 검사 | `structureValid:true`, `ownerMatches:true`, `trusted:true` |
| 고정 기준 검사 | `versionMatches:true`, `captureMatches:true` |
| 결과 | `verified:true`, `changedFields:[]` |
| traceId | `91c5d34d-ba04-4ebf-bc5e-12191fa65313` |
| 실제 복원 | **미실행 — 미리보기만 수행** |

당시 별도 읽기 전용 운영 DB 점검에서 저장된 `on_create` 사본 **2건 중 2건의 해시·HMAC 일치**를 확인했다. 이 사본이 심판이 생성한 특정 메모의 사본인지는 미확인이다. 당시 저장 사본의 무결성 점검을 이번 DB 재검증이나 신규 메모의 운영 복원 성공으로 기록하지 않는다.

## 격리 E2E 검증 결과

2026-10-15, 운영과 다른 Neon 프로젝트의 빈 기준 DB에서 만든 임시 브랜치에서 시험했다. 실행 코드는 **`6bfddf6` 기반 + 당시 로컬 UUID 수정본**이며 당시 운영 커밋 그대로의 시험이 아니다. 이후 UUID 수정이 배포됐어도 이 이력을 운영 서버의 재시험으로 바꾸지 않는다. 시험 데이터·인증키·HMAC 키는 운영 값을 복사하지 않고 구성했다.

- 환경: **Neon PostgreSQL 17.11 · PostgREST 16.4 · 로컬 HTTP 서버**.
- 초기 분리 확인: 애플리케이션 테이블 0개, 외부 DB 연결 0개, 복제 구독 0개. 기초 테이블·역할·권한은 시험용 bootstrap으로 구성했다.
- `step10-created-memo-backups.sql`과 `step10-verified-restore.sql`은 원문으로 설치했고 관련 함수 4개의 본문 일치를 확인했다.
- **실제 HTTP 요청 35건, 검사항목 91개 통과**. 91개는 테스트 러너 시험 개수가 아니라 E2E 내부 확인 항목 수다. 예상된 거부 응답도 통과 조건으로 검사했다.
- 시험 인증은 자체 ES256 토큰과 실제 검증기를 사용했다. issuer·공개키는 하네스에서 주입했으므로 **실제 심판 JWT·JWKS·요청은 검증하지 않았다**.

| 실제 요청 | HTTP | 실측 시간 |
|---|---|---|
| 신규 B 메모 POST | 201 | 860.5ms |
| 제목·본문 변조 PUT | 200 | 874.3ms |
| 복원 미리보기 POST | 200 | 874.9ms |
| 본문 없는 실제 복원 POST | 200 | 1,724.5ms |
| 복원 후 독립 GET | 200 | 856.9ms |
| 메모 DELETE | 204 | 866.2ms |
| 삭제 후 미리보기 POST | 200 | 862.6ms |
| 삭제 후 본문 없는 복원 POST | 200 | 1,728.2ms |
| 재생성된 메모 독립 GET | 200 | 855.3ms |

두 실제 복원 모두 `restored:true`, `verified:true`였으며 독립 GET·SQL 조회로 ID·소유자·원본 내용·SHA-256 일치를 확인했다. 최초 사본의 해시·HMAC·전체 지문은 생성→변조→복원→삭제→재생성 중 보존됐다. 대문자 인증 UUID의 PUT도 정상 처리됐다.

| 격리 환경의 실패 주입 | 실제 거부 결과 |
|---|---|
| 사본 누락 | 404 `MEMO_NOT_FOUND` |
| 사본 내용 변조·저장 해시 불일치 | 409 `BACKUP_UNVERIFIED` · `backup_hash_mismatch` |
| HMAC 불일치·내용과 해시 동시 변조 | 409 `BACKUP_UNVERIFIED` · `backup_seal_mismatch` |
| 다른 사용자의 조회·변경·삭제·미리보기·복원 | 모두 404 |
| 미인증·잘못된 서명·잘못된 audience | 모두 401 |
| 본문 소유권·역할 주장 | 403 `IDENTITY_CLAIM_FORBIDDEN` |
| 내부 미리보기 직후, 실제 복원 RPC 전 상태 변경 | 409 `RECOVERY_STATE_CHANGED` · `backup_or_target_changed` |

실패 요청은 대상 상태를 덮어쓰지 않았고 감사 행을 추가하지 않았다. 다른 메모·사본과 기존 감사 행 1개는 보존됐으며 성공한 복원 2회에 대해서만 감사 행 2개가 추가됐다. 이 시간은 로컬에서 미국 동부 Neon에 연결한 단발 실측이며 운영 Vercel·심판의 처리 시간으로 일반화하지 않는다. 시험 서버는 종료했고 임시 Neon compute의 `idle`을 확인했다.

### UUID 수정 배포 전 로컬 회귀 검사 (2026-10-15)

아래는 UUID 수정과 검증 증거 정리의 커밋·배포 전에 실제 실행한 로컬 검사 결과다. 이번 배포 후 README 상태 정정에서 새로 실행한 시험이 아니다. 격리 E2E·가상 요청 시험·운영 로그·심판 판정의 건수를 합산하지 않는다.

| 실행 명령 | 당시 실제 결과 |
|---|---|
| `npm.cmd run recovery:test` | **40개 통과 / 실패 0개**. UUID 회귀 6개 포함. 인증·DB/RPC 모의 시험과 시험 키 서명 검증 |
| `npm.cmd run policy:test` | **4개 통과 / 실패 0개**. 임시 정책 사본 누락·변조 거부와 보존 검사 |
| `npm.cmd run policy:diff` | 사본 검증 통과, 변경 범위 없음 |
| `npm.cmd run policy:restore` | `--apply` 없이 미리보기만 수행, 변경 범위 없음 |
| `npm.cmd run test:r5` | **4개 통과 / 실패 0개** |
| `npm.cmd run decider:test` | 가상 요청 **4사례 통과** |
| `npm.cmd run detect:test` | 가상 사건 **6사례 통과** |
| 추가 Node 회귀: 8·9단계, 정책 사본 목록, XDR | **10개 통과 / 실패 0개** |
| `npm.cmd run test:package` | **2개 통과 / 1개 실패**. 초기 API 파일 2개 가정과 현재 직계 파일 6개의 불일치 |
| `npm.cmd run build` (일반 로컬 환경) | **실패**, Vercel 배포 식별 환경변수 5개 누락으로 `deployment-identity.mjs:21`에서 중단 |
| `npm.cmd run build -- --local` | **성공**. 기존 로컬 전용 옵션으로 빈 공개 메모 파일을 생성하며 배포 식별 파일은 생성·갱신하지 않음 |
| 임시 폴더의 시험용 메타데이터 빌드 | **성공**. 원본 빌드 소스·설정을 복사해 실행하고 빈 공개 메모·메타데이터 확인. 운영 배포 검증은 아님 |
| `git diff --check` | 통과 |

당시 Node 테스트 러너의 중복 없는 합계는 **61개 중 60개 통과·1개 실패**다. 판정기 4사례·탐지 6사례와 비교·미리보기·빌드 명령은 이 합계에 더하지 않는다. 임시 Git 커밋을 만드는 `bundle-changes` 시험 1개는 당시 commit 금지 범위에 맞춰 실행하지 않았다. 기존 시작 틀 실패를 숨기거나 통과하도록 검사를 바꾸지 않았다.

당시 일반 로컬 환경에는 `VERCEL_GIT_PROVIDER`, `VERCEL_GIT_REPO_OWNER`, `VERCEL_GIT_REPO_SLUG`, `VERCEL_GIT_COMMIT_SHA`, `VERCEL_URL`이 없으므로 `npm.cmd run build`가 실패했다. 로컬에서는 기존 옵션인 **`npm.cmd run build -- --local`**로 실행하면 된다. 이 명령은 성공했으며 `public/aleph.json`의 배포 식별 정보 검증·생성은 수행하지 않는다. 식별 정보 생성 경로는 OS 임시 폴더에서 공개 시험 메타데이터를 주입해 별도로 검증했다. 식별 정보 검증 로직·프로젝트 설정은 변경하지 않았다. 이후 UUID 수정 반영 배포에서 실제 Vercel 빌드 성공·READY·운영 메타데이터 일치를 확인했으며 그 결과는 아래 배포 이력에 기록한다. Vercel의 빌드 명령은 기존 `npm run build`를 유지한다.

재확인은 VS Code의 **터미널 → 새 터미널**에서 `npm.cmd run recovery:test`로 실행한다. 동일 UUID 대소문자 PUT은 정상 처리되고, 타인 메모·미인증·본문 신원 주장은 기존 오류로 거부되어야 한다. 실행기·빌드 검증은 기존 Node/npm만 사용했고 이번 작업에서 프로그램을 설치하지 않았다.

## 미확인 항목과 검증 한계

- 실제 심판의 JWT 검증 결과, 메모 생성·변조·삭제·복원 요청의 URL·메서드·본문·HTTP 응답은 **미확인**이다. 반복 `UNV_AMBIGUOUS`를 코드 실패나 시간 초과로 해석하지 않는다.
- 당시 배포 `6bfddf6`의 legacy 미리보기와 UUID 수정본의 격리 복원 성공은 별개의 증거다. 이후 사용자가 확인한 10단계 100점과 이번 11단계 미판정 상태도 구분한다. 이번 작업에서는 운영 신규 메모 복원을 시험하지 않는다.
- 과제 가이드의 본문 없는 POST와 응답 권고 필드는 구현과 대조했지만, 확정된 심판의 전체 HTTP 스키마·restoreRoute 파싱·JWT 세부 계약은 확보하지 못했다. 근거 없이 입력 허용 범위나 인증을 완화하지 않는다.
- 실제 DB 쓰기 후 재조회 불일치에 따른 500 분기는 모의 시험으로 확인했으며, 이번 실제 E2E에서 그 실패를 강제로 주입한 것은 아니다. 1~9단계 로컬 회귀 통과도 최신 운영 심판의 전체 재시험 통과를 뜻하지 않는다.
- DB 함수 내부 검증 실패는 트랜잭션을 중단한다. **RPC 정상 완료 뒤 API 추가 검증에서 실패하면 500을 반환해도 이미 완료된 DB 변경은 롤백되지 않는다.**
- PostgreSQL IDENTITY 시퀀스 증가는 ROLLBACK으로 되돌아가지 않을 수 있다. 과거 시험 행의 롤백을 모든 DB 부작용의 원복으로 해석하지 않는다.
- UUID 수정·증거 정리의 커밋·배포는 승인 후 완료했다. 11단계 제작 1은 로컬 정적 화면·PWA와 시험만 대상으로 하며 운영 DB·메모 변경, 배포, 심판 제출은 수행하지 않는다.

## 과거 판정·시험 이력

### 2026-10-15 UUID 수정·증거 정리 배포 확인 (`646fd316`)

- 당시 배포 확인 커밋: `646fd316fd3a620554fbe93fd0f0eb33a8e1a434`. 현재 버전을 고정하는 값이 아니라 배포 검증 이력이다.
- 커밋 파일은 `README.md`, `api/memos.js`, `test/step10-memo-api.test.mjs` 세 개였다. GitHub `main` push와 Vercel Production **READY**, 운영 `/aleph.json`의 해당 커밋 일치를 확인했다.
- Vercel은 기존 `npm run build`로 빌드했다. 운영 `/data.json`은 `notes: []`였고 비로그인 메모 목록·단건 GET은 모두 **401 `AUTH_REQUIRED`**였다. 운영 메모의 생성·변조·삭제·복원은 수행하지 않았다.
- 당시 배포 확인 직후에는 심판 미제출 상태였다. 이후 사용자가 확인한 `9928c48`의 10단계 100점은 문서 상단에 별도로 기록한다. 아래 과거 판정과 격리 시험을 이 배포 시점의 심판 통과로 해석하지 않는다.

### 과거 판정: `74e6971` (2026-10-15 사용자 전달)

- 판정 커밋: `74e6971bafdd3479da681391eb3871e722ccaf0a`.
- 당시 결과: **36/100**, 실패 코드 **`S10_BACKUP_UNVERIFIED`**, 미통과 조건은 백업 검증. 당시 최고 점수는 48/100이었다.
- 이 결과를 바탕으로 정책 사본 누락·검증 실패 중단 분기와 과거 기록을 README에 정리했다. 이후 `6bfddf6`의 두 `UNV_AMBIGUOUS`와 구분한다.

### 2026-10-15 초기 DB 시험 중단 기록 (격리 HTTP E2E 이전)

- 운영 SQL 재시험은 `memos.id`의 IDENTITY 시퀀스 증가가 롤백되지 않는 점을 발견하여 **실행 전에 중단**했다. 운영 SQL 시험을 실행 완료로 기록하지 않는다.
- 당시 조회한 기존 Neon `s10_verification`에는 필요한 스키마·함수가 없어 SQL 복원 시험을 실행하지 않았다. 이후 위의 실제 HTTP E2E는 별도 임시 브랜치에 시험 스키마를 구성해 수행했다.

### 과거 로컬 검증 (2026-10-15, 코드 기준 `74e6971`)

| 실행 명령 | 실제 결과 |
|---|---|
| `npm.cmd run policy:test` | 4개 통과 / 실패 0개 |
| `npm.cmd run policy:diff` | 사본 검증 통과 / 변경 범위 없음 |
| `npm.cmd run policy:restore` | 적용 없는 미리보기 / 변경 범위 없음 |
| `npm.cmd run recovery:test` | 34개 통과 / 실패 0개 (인증·RPC 가상 응답 시험과 가상 JWT 서명 검증 포함) |
| `git diff --check` | 통과 |

정책 시험은 임시 디렉터리에서 사본 해시 변조·파일 삭제를 실제 수행하고 `UNVERIFIED_POLICY_BACKUP` 거부와 시험 정책 불변을 확인한다. 침해 전 검증 조건 거부 및 정상 복원 시 다른 서비스·감사 보존도 확인한다. 같은 호출의 마지막 재조회 순간에 변경을 주입하는 동시성 시험이나 모든 CLI 오류 분기를 시험한 것은 아니다. 합계 38개 테스트 통과 / 실패 0개이며 비교·미리보기 명령은 테스트 건수에 합산하지 않는다. 실제 `policy/test-policy.json` 적용, 운영 DB SQL 시험, 배포·심판 제출은 당시 작업에서 실행하지 않았다.
아래 기록은 당시 수행했다고 기록된 시험과 관찰을 보존한 이력이며 최신 배포·심판 성공을 뜻하지 않는다. 2026-10-14의 명시된 `39aefcb`, `5e6a50c`, `3a4e988` 등과 날짜·커밋 미상 기록을 구분한다. 정확한 날짜나 대상 커밋이 없는 기록은 이 문서만으로 특정할 수 없으므로 임의로 보충하지 않는다. 옛 테스트 개수는 당시 수치이며 UUID 수정 배포 전 로컬 실행 수치는 위의 날짜가 표시된 회귀 검사 기록을 따른다. 과거 SQL의 "롤백"은 시험 행 변경에 관한 기록으로 한정하며 IDENTITY 시퀀스까지 원복됐다는 뜻이 아니다.

### 과거 조건 재대조 (정확한 시험 날짜·대상 커밋 미상)

| 조건 | 구현/확인 | 당시 기록 |
|---|---|---|
| 안전 정책 사본 재검증·비교 | policy:diff 및 policy:test | 로컬 시험 통과 |
| 실행 전 버전·변경 범위 확인 | 로그인 화면의 복원 미리보기·확인 버튼 | **2026-10-14 실제 배포 B 계정에서 미리보기 실측**. 신규 시험 메모의 제목·내용 변조가 변경 항목으로 표시됨 |
| B 메모 한 건 복원 | POST /api/restore/:id · 잠금 후 사본/대상 재조회 | 실제 DB 제목·본문 변조 복원 및 삭제 복원 통과. 시험 변경 롤백 |
| 다른 자료·감사 이력 보존 | 다른 메모 전체 지문 유지·감사 추가 | 실제 DB 롤백 시험 통과 |
| 손상 사본 거부 | 기존 사본 고정 지문·신규 사본 해시/HMAC 재검증 | 내용과 저장 해시를 함께 바꾼 사본도 실제 DB에서 거부 확인 |
| 기존 정상·금지 요청 | 아래 회귀시험 순서 | **2026-10-14 배포 실측**: A/B 목록 분리, A의 B 백업 미리보기 거부, 로그아웃 후 UI 숨김 및 `/api/memos` `AUTH_REQUIRED` JSON 확인. 전체 회귀·HTTP 상태코드 일부는 별도 확인 필요 |
| step·요청 계약·ruleIds | step=10 및 기존 판정 계약 | 변경 없음. 판정기 시험 통과 |
| 신규 설치·제출 묶음 | npm install 및 npm run bundle | Vercel 설치·빌드 성공. 사용자 PC에서 5e6a50c 제출 JSON 생성 확인. 작업 환경의 외부 요청 403 때문에 일부 자기점검·캐시 없는 설치는 미완료 |

DB의 step10-created-memo-backups.sql 및 step10-verified-restore.sql 적용 완료. 구형 restore_memo_from_backup의 실행 권한 회수도 유지함.
복구 API 격리 시험 15개, 배포 정보/기본 자기점검 3개, 관련 회귀시험 12개, 판정기 4개, 탐지 6개 통과. API 시험의 인증·RPC는 가상 응답임.
머지 커밋도 첫 번째 부모 기준 변경 파일을 제출 묶음에 포함하도록 보완함.
이하 '실측 완료' 기록은 과거 실행 결과임. `74e6971` 판정도 과거 이력이며 이후 `6bfddf6`의 두 `UNV_AMBIGUOUS`와 구분함. 현재 운영 버전의 판정 상태는 문서 상단을 따르며 로컬/DB 시험을 심판 통과로 해석하지 않음.

### 2026-10-14 실제 운영 배포 수동 재시험 (기준 배포 커밋 `39aefcb0c2aa399660a1e76b5f56e3970843ce19`)

시험 당시 배포 주소: `https://choi-bujang-secret-vault-pink.vercel.app`. Vercel Production READY와 공개 `/aleph.json`의 커밋·`restoreRoute=/api/restore/:id` 일치를 별도로 확인함. 아래는 해당 배포에서 B/A 계정을 사용하여 브라우저 화면으로 **직접 관찰한 결과**이며, 이전 5e6a50c 실행이나 로컬 모의 시험과 구분함.

| 시험 | 실제 실행 및 관찰 결과 | 범위 |
|---|---|---|
| B 기존 사본 조회 | `훈련 행정 자료`(ID `a4d2a3cc-33be-481b-b479-a0bcd5f07bfb`)의 복원 미리보기에서 백업 버전·백업 시각과 `변경 항목: 없음` 표시 | 기존 메모는 변경·복원하지 않음 |
| B 시험 메모 생성 | `10단계 복원 검증용` / `원본 데이터 001 - 정상 백업` 생성 후 목록에 표시 | 신규 메모 ID `c93789a8-33fa-4bd2-9259-adbc25eedbc4` |
| 제목·내용 변조 감지 | 제목을 `10단계 복원 검증용 - 변조됨`, 내용을 `변조 데이터 999 - 복원 시험`으로 수정. 미리보기에서 `변경 항목: 제목, 내용` 표시 | 백업 버전과 생성 시각을 실제 화면에서 확인 |
| 확인 후 한 건 복원 | 시험 메모 미리보기의 `확인한 한 건 복원` 실행 후 `검증한 사본으로 한 건 복원 완료` 표시. 목록의 제목·내용이 생성 당시 값으로 돌아옴 | UI 응답 및 화면상 복원 확인 |
| 복원 뒤 재조회 | F5 새로고침 후에도 시험 메모의 원래 제목·내용 유지. 기존 `훈련 행정 자료`도 목록에 유지 | 서버 재조회 이후 화면 값 일치 확인 |
| A/B 목록 분리 | A 로그인 시 `과제`, `포트폴리오`, `아침 리추얼`만 표시되고 B의 기존·시험 메모는 보이지 않음 | 목록 수준 소유권 분리 |
| A의 B 사본 접근 | A 로그인 상태에서 B 기존 메모 ID의 `복원할 항목 확인` 실행 시 `BACKUP_UNVERIFIED` 표시, 복원 실행 버튼 없음 | 타 소유자 백업 미리보기 거부; 심판 오류 `S10_BACKUP_UNVERIFIED`의 원인과 동일하다고 판단하지 않음 |
| 로그아웃 후 UI/API | 로그아웃·새로고침 후 메모 목록과 복원 영역이 숨겨짐. 별도 탭에서 `/api/memos` 요청 시 `{"error":"AUTH_REQUIRED"}` 출력 | JSON 거부 확인. **HTTP 401 상태코드는 개발자 도구로 별도 확인하지 않음** |

### 2026-10-14 Vercel 운영 로그 재검증 (기존 배포 `39aefcb`)

화면 시험에 사용한 실제 복원 요청의 `BYTEBACK_TRACE`를 Vercel Production 로그에서 확인함. 토큰·비밀번호·본문·해시 원문은 기록하지 않음.

- 복원 요청: `POST /api/restore/c93789a8-33fa-4bd2-9259-adbc25eedbc4`
- 로그 시각: `2026-10-14T08:33:59Z` (KST 17:33:59); 요청 추적 ID: `8351c2f5-e7dd-4881-9633-0741becb138b`.
- `request_shape`: `hasExpectedVersion=true`, `hasExpectedState=true`. `backup_compared`: `structureValid=true`, `idMatches=true`, `ownerMatches=true`, `trusted=true`, `sealed=true`, `backupKind=on_create`, `changedFields=["title","content"]`.
- `confirmation_compared`: `versionMatches=true`, `stateMatches=true`. 복원 RPC HTTP 200.
- `restored_row_compared`: `idMatches=true`, `ownerMatches=true`, `ownerAliasMatches=true`, `versionMatches=true`, `hashAliasMatches=true`, `bodyHashMatches=true`, `snapshotHashMatches=true`, `verified=true`, `restored=true`.
- `completed`: HTTP `200`, `verified=true`, `restored=true`. 위의 값은 **서버 측 실제 비교 결과**이며 HTTP 응답 JSON에 포함된 원시 소유자·해시값 자체를 캡처한 것은 아님.
- 비로그인 `GET /api/memos`: `2026-10-14T08:40:33Z`(KST 17:40:33), 추적 ID `de55570b-12f1-4e51-abb9-67f3935f5226`, `completed.status=401`, `error=AUTH_REQUIRED`. 화면에 표시된 JSON 거부와 서버 상태 코드를 대조함.

이번 수동 재시험에서 **검증하지 않은 항목**: 복원 요청의 실제 HTTP 응답에 들어 있는 `ownerId`/`contentSha256` 값과 원본 해시의 직접 비교, 실제 손상 사본 주입/거부, 삭제 후 복원, 모든 1~9단계 공격의 최신 배포 재실행, 심판 100점 판정. 이 항목은 코드 또는 과거 시험 근거와 구별하여 미확인 상태로 유지함.

### 과거 구현·직접 확인 기록 (2026-10-14 기록, `5e6a50c`·`39aefcb`; SQL 시험 커밋 미상)

| 위치 | 변경 내용 |
|---|---|
| api/restore/[id].js | 사본의 소유자·해시와 복원 후 DB 응답을 대조하고 실제 메모를 반환함 |
| src/recovery/trusted-memo-backup.mjs | 기존 B 지문 유지, 신규 최초 사본은 DB 서명 검증을 요구함 |
| supabase/step10-created-memo-backups.sql | INSERT 시 사본 생성. PUT/DELETE로 덮어쓰지 않음. 서명 키·사본은 비공개 스키마에 보관함 |
| supabase/step10-verified-restore.sql | 잠금 안에서 사본 재조회·검증, 지정 ID 한 건 복원, DB 행 재조회와 결과 반환 |
| scripts/deployment-identity.mjs | 설정의 restoreRoute를 배포 /aleph.json에 포함하고 허용 POST 경로와 대조함 |
| public/recovery-check.js | B 로그인 후 생성→변조→복원 응답→GET→삭제→복원→GET을 직접 확인함 |

응답의 `ownerId`/`owner_id`는 같은 소유자이며 `contentSha256`/`content_sha256`은 UTF-8 **본문만**의 SHA-256임.
기존 백업 지문과 감사 기록에는 제목+NUL+본문 해시를 계속 사용하며, 응답의 `snapshotSha256`으로 구분함.
과거 DB 시험 기록: `supabase/step10-created-memo-test.sql` 및 기존 소유자 변조 시험을 실제 학습 DB에서 실행하여 통과했다고 기록되어 있음(정확한 실행 날짜·대상 커밋 미상). 시험 메모·사본·감사 행 변경의 롤백 기록이며, 모든 DB 부작용의 원복을 증명하지 않음. 2026-10-15 재시험은 실행 전 중단했으며 이 과거 기록과 별개임.
사본 없음, 손상 사본, 내용+저장 해시 동시 변조, 잘못된 소유자, 오래된 미리보기는 중단됨. 다른 메모와 기존 감사 기록 보존을 대조함.
비공개 사본/키에는 PUBLIC·anon·authenticated·service_role 직접 접근을 허용하지 않음. 공개 RPC는 검증된 서버의 service_role만 실행함.

로컬 재실행: `npm.cmd run recovery:test`.
사용자가 5e6a50c 배포에서 B 로그인 후 아래 도구를 실행하여 passed/contentHashMatches=true를 확인함. 서버의 복원 200 응답 2회, DB 감사 2건과 사본 서명 일치도 대조함. **39aefcb 배포에서는 2026-10-14 UI를 통해 신규 메모 생성→제목·내용 변조→복원 미리보기→복원 완료→새로고침 후 원본 유지까지 별도로 실측함.** 아래 자동화 도구를 최신 배포에서 재실행한 것은 아니며, 이번 수동 시험에서는 HTTP 복원 응답의 필드별 해시 일치를 별도로 수집하지 않음.

```js
await (await import('/recovery-check.js')).runRecoveryCheck()
```

정상 결과: `passed: true`, `contentHashMatches: true`. 비로그인 복원은 401이어야 함.
이 도구는 만든 시험 메모 한 건만 정리하며 사본·감사 기록은 유지함. `5e6a50c` 당시 심판 판정 기록은 36점/S10_BACKUP_UNVERIFIED이며 현재 최신 판정은 아님. 실제 B 시험 성공을 심판 통과로 기록하지 않음.

### 요청 흐름과 사본 비교 로그

- Vercel 프로젝트의 Logs에서 `BYTEBACK_TRACE`를 검색함. 하나의 HTTP 요청은 traceId로, 같은 메모/사용자/심판 실행은 memoRef/actorRef/runRef로 연결함. 참조는 UUID의 단방향 요약이며 원래 ID는 로그에 넣지 않음.
- 메모 생성·조회·수정·삭제와 두 복구 경로의 진입/인증/완료 HTTP 상태를 기록함. 잘못된 JSON·로그인 실패 등 조기 중단도 completed에 남음.
- backup_compared는 사본 구조, 대상 ID, 요청자 소유권, 고정 지문 또는 DB 서명 검증 결과를 기록함.
- restored_row_compared는 DB에서 다시 읽은 ID·소유자·본문 SHA-256·제목+본문 지문·사본 버전의 비교 결과를 true/false로 기록함. 실제 복구 조건은 변경하지 않음.
- request_shape는 알려진 제어 필드의 존재와 필드 수만 기록함. 본문·제목·비밀번호·토큰·헤더 값·해시 원문은 기록하지 않음.
- 응답 헤더 X-Byteback-Trace를 Network 탭에서 복사하면 그 요청의 로그를 찾을 수 있음.
- trace 없는 요청은 플랫폼 단계에서 차단됐거나 수집 범위 밖일 수 있으므로, 로그 부재를 성공/실패 근거로 삼지 않음.

### 공개 주소 대조와 9단계 기준

- 9단계 검증 커밋은 847972a71c0f469c330f58b67ea1dbc3893cfec3임. 로그 수정 전 판정기·탐지기·로그인 검증·자원 ID·메모/공지 API·Vercel 설정 7개 파일의 Git 지문이 해당 사본과 같았음.
- 5e6a50c의 /aleph.json은 publicAppUrl에 개별 배포 URL을 내보냈고, 이 주소의 /aleph.json 및 /api/memos는 외부 확인에서 login_required였음. 등록한 pink.vercel.app 공개 주소의 /aleph.json은 읽혔음.
- 10단계부터 배포 메타데이터 publicAppUrl은 aleph.config.json의 검증된 공개 HTTPS 원점을 사용함. 심판 토큰의 audience에 사용한 호스트와도 같은 주소임. Vercel 보호 설정과 인증 검증은 유지함.
- 이 주소 불일치가 심판 실패를 일으켰는지는 새 로그와 재판정으로 확인해야 함. 이번 변경을 심판 통과로 기록하지 않음.


### 과거 검증 이력: 10단계 제작 4 — 복구 뒤 1~9단계 회귀시험 (날짜·대상 커밋 미상)

복구가 끝난 뒤 아래 순서로 다시 확인합니다. **실제로 실행하지 않은 항목은 미실행으로 유지하며 통과로 기록하지 않습니다.**

### 회귀시험 순서

| 순서 | 대상 | 당시 실행/확인 방법 | 당시 기록 |
|---|---|---|---|
| 1 | 1~5단계 기본 배포·공개 경로 | `npm.cmd run test:r5` 실행 후 배포 식별과 공개 `data.json` 자기점검 코드가 정상 동작하는지 확인 | **통과 · pass 2 / fail 0** |
| 2 | 5단계 인증·소유권 | 브라우저에서 A 로그인 → 자기 메모 정상 조회, B 로그인 → 자기 메모 정상 조회, 로그아웃 후 `/api/memos` → 401 JSON 오류 확인 | **실측 완료** |
| 3 | 4·8단계 다른 사용자 자료 차단 | B가 A 메모 UUID로 GET/PUT/DELETE 시 403 또는 404이고 A 메모가 유지되는지 확인 | **GET 실측 완료 · `MEMO_NOT_FOUND`** |
| 4 | 6·7단계 기기·복합 이상 판정 | `npm.cmd run decider:test` 실행 → 등록 기기 허용, 미등록 기기 거부, 복합 이상 `step_up`, 재확인 후 허용 확인 | **통과 · 4개 모두 통과** |
| 5 | 8단계 자원 구역 | `node --test test/step8-resource.test.mjs` 실행 → 자기 메모 허용, 다른 구역·기능 경로 거부 확인 | **통과 · pass 2 / fail 0** |
| 6 | 9단계 다량 조회 탐지 | `npm.cmd run detect:test` 실행 → 정상 30/120건 유지, 121/200건만 `propose_revocation / burst_read` 확인 | **통과 · 6개 모두 통과** |
| 7 | 9단계 회수 제안 대상 | `node --test test/step9-revocation.test.mjs` 실행 → 확인된 기기 1개에만 제안, 정상 사건은 제안 없음 확인 | **통과 · pass 2 / fail 0** |
| 8 | 10단계 정책 복구 상태 | `npm.cmd run policy:diff` 실행 → 검증된 9단계 정책 사본과 정책 차이가 없는지 확인 | **통과 · 정책 차이 없음** |
| 9 | 10단계 메모 단건 복원 | B의 `훈련 행정 자료` 제목을 테스트용으로 수정한 뒤 `POST /api/restore` 실행, 응답과 새로고침 후 원상복구 확인 | **실측 완료** |

### 10단계 메모 복원 실측 결과

- 대상: B 시험 계정의 `훈련 행정 자료` 한 건
- 테스트 변경: 제목을 `훈련 행정 자료 (복구 테스트)`로 수정
- 복원 요청: `POST /api/restore`
- 복원 응답: HTTP 200
- `restored: true`
- `ownerMatches: true`
- `contentHashMatches: true`
- 새로고침 후 제목이 `훈련 행정 자료`로 복원됨
- 다른 메모와 감사 기록을 삭제하거나 초기화하지 않음
- 초기 RPC 실패 원인 `42883 undefined_function`은 Supabase `pgcrypto`가 `extensions` 스키마에 있어 복원 함수의 `search_path`에 `extensions`가 필요했던 것으로 확인하고 수정함

### 과거 검증 이력: 10단계 제작 3 — B 가상 메모 단건 복원 (날짜·대상 커밋 미상)

다음은 최초의 고정 B 사본·호환 경로 구현 당시 기록이다. 현재 제출 경로와 신규 최초 생성 사본 기능은 상단의 현재 계약을 따른다.

- 서비스: `notes`
- 복원 경로: `POST /api/restore`
- 요청 본문: `{ "id": "<복원할 B 메모 UUID>" }`만 허용
- 비공개 사본: Supabase `public.memo_restore_backups`에 B의 `훈련 행정 자료` 한 건만 저장하며 `PUBLIC`·`anon`·`authenticated` 직접 권한을 회수함
- 사본은 `backup_key=b_training_admin` 한 칸으로 고정하고 `ON CONFLICT DO NOTHING`으로 재실행 시 덮어쓰지 않음
- 복원 시 검증된 로그인 사용자와 사본의 `owner_id`를 대조하고, 사본의 내용 SHA-256을 다시 계산한 뒤 지정한 ID 한 건만 복원함
- 복원과 감사 기록 추가는 DB 함수 안에서 한 트랜잭션으로 처리하며 다른 메모를 삭제·수정하지 않음
- 감사 기록은 `memo_restore_audit`에 추가만 하며 기존 기록을 삭제하지 않음
- SQL을 실제 실행하기 전에는 백업 생성·복원 성공으로 기록하지 않음

이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

### 과거 단계 기록: 10단계 시작 시점 (날짜·대상 커밋 미상)

현재 기능 (5줄):
1. 기존 로그인·기기 등록·추가 확인·자원 구역 판정과 메모 소유자 검사를 유지
2. 탐지 입력은 `docs/DETECT_EVENTS.md` 계약의 `at`·`method`·`identity.sub`만 읽고 본문·토큰·실명을 보존하지 않음
3. 같은 가명 사용자의 GET이 연속된 10분 구간에서 120건을 초과할 때만 `propose_revocation / burst_read`를 제안
4. 정확히 120건, 다른 사용자 합산, 10분 밖 사건, GET이 아닌 요청은 `observe`로 유지
5. 별도 회수 제안은 탐지된 가명과 엔진이 확인한 `subjectId`가 일치하고 유효한 기기 ID 1개가 있을 때만 생성

### 9단계 확인 순서

1. `npm.cmd run detect:test` 실행
2. 정상 30건·정확히 120건·다른 사용자 각 100건·10분 밖 200건은 `observe` 확인
3. 10분 안 121건과 폭주 200건은 `propose_revocation / burst_read` 확인
4. `node --test test/step9-revocation.test.mjs` 실행
5. 의심 사건은 확인된 기기 1개에만 회수 제안, 정상 사건은 제안 없음 확인

### 9단계 제출 전 보완

로컬 `npm.cmd run bundle` 중 원본 Supabase API DNS 조회가 `ENOTFOUND`로 실패함. 프로젝트 설정의 Supabase URL과 `aleph.config.json.originalApiUrl`을 대조해 주소 일치를 확인했고, 원본 API 자기점검만 네트워크 실패를 `점검 미완료`로 기록하도록 변경함. Vercel 자기점검은 기존처럼 실패 시 bundle을 중단함.

### 9단계 검증 범위

- 현재 `DETECT_EVENTS.md` 기본 사건 계약에는 네트워크·기기·판정 필드가 없음
- 따라서 `detect(events)`에 계약 밖 값을 임의로 추가하지 않았으며, 네트워크 복합 이상 판정은 기존 7단계 판정 규칙을 유지
- `proposeRevocation()`은 회수 제안 객체만 만들며 실제 회수 API 호출이나 기기 권한 변경은 하지 않음
- 실제 회수와 첫 의심 요청부터 회수까지의 시간 측정은 심판 환경에서 확인해야 함
- 로컬 테스트 통과를 실제 운영 회수나 심판 통과 증거로 표시하지 않음


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

### 과거 단계 기록: 8단계 — 자료마다 갈 수 있는 구역을 나눕니다 (날짜·대상 커밋 미상)

현재 기능 (5줄):
1. 기존 로그인·메모 CRUD와 6단계 등록 기기·7단계 추가 확인 규칙을 유지
2. 판정기는 검증된 `subjectId`·`deviceId`·`service`·`method`·`route`·정확한 `path`로 자원 구역을 판단
3. 자기 메모의 배정된 GET/PUT만 허용하고 다른 주체·알 수 없는 경로·기능 경로·쿼리 선택은 `resource_not_allowed`로 거부
4. 메모 API는 DB 조회 결과의 `owner_id`를 검증된 로그인 사용자와 다시 대조하며 요청 본문의 role/userId/owner_id를 권한 근거로 사용하지 않음
5. 강사 공지 API는 저장된 강사 권한이 확인될 때만 허용하고, 현재 권한 테이블이 없는 환경에서는 기본 403으로 거부

### 8단계 확인 순서

1. `npm.cmd run decider:test` → 등록 정상/미등록/복합 이상/재확인 복합 이상 4개 통과
2. `npm.cmd run test:r5` → 기존 회귀 테스트 2개 통과
3. `node --test test/step8-resource.test.mjs` 실행
4. 자기 메모 허용, 다른 사용자 메모 거부, 일반 학생 공지 수정 거부 확인
5. `/notes/export` 같은 기능 경로와 쿼리 기반 선택이 거부되는지 확인

### 8단계 S08_OTHER_ZONE_ALLOWED 보완

첫 심판 제출에서 다른 구역 자료 API 조회 조건 1건이 실패함. 심판 피드백에 따라 판정 요청 계약에는 강사 역할 정보가 없으므로 `notices` 쓰기(POST/PUT/PATCH/DELETE)는 판정기에서 누구에게나 허용하지 않도록 수정함. 메모 단건의 실제 소유자 비교는 API의 검증된 사용자와 저장된 `owner_id` 대조를 유지함. 자원 바인딩에 `instructor: true`가 있어도 공지 PUT이 `deny / resource_not_allowed`인지 회귀 테스트에 추가했고 `node --test test/step8-resource.test.mjs`에서 pass 2 / fail 0을 확인함.

### 8단계 검증 범위

- 로컬 가상 판정 시험은 통과했으며 실제 심판 판정과는 별개임
- 기존 Supabase에는 현재 `memos` 테이블만 확인됨
- `vault_instructors` / `vault_notices`가 준비되지 않은 상태에서는 강사 공지 API가 fail-closed(403)로 동작함
- 실제 강사 권한 부여 및 공지 정상 수정은 저장된 권한 데이터가 준비된 환경에서 별도 확인해야 함
- 토큰 원문·비밀번호·서버 전용 키는 기록하지 않음


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

### 과거 단계 기록: 7단계 — 평소와 다른 접속은 다시 확인합니다 (날짜·대상 커밋 미상)

현재 기능 (5줄):
1. 기존 Vercel/Supabase 자료실과 6단계 등록 기기 판정 규칙을 유지
2. 판정기는 계약의 `signals`·`recentEvents`만 읽고 불명확한 값을 정상값으로 보정하지 않음
3. 새벽 시간·처음 보는 네트워크·최근 다량 읽기 신호가 함께 있으면 `step_up / step_up_required`
4. 지역 하나만으로 차단하지 않으며 정상 조합은 `allow / approved`
5. 엔진이 `stepUp.verified=true`와 유효한 `authAgeSeconds`를 넘긴 새 요청은 다시 허용

### 7단계 확인 순서

1. `npm.cmd run fixture:7` 실행 → 정상 사건 `allow`, 복합 이상 사건 `step_up` 확인
2. `npm.cmd run decider:test` 실행
3. 등록 기기의 정상 요청 통과
4. 미등록 기기의 가상 요청 통과
5. 복합 이상 접속과 다시 확인한 복합 이상 접속 모두 통과

`npm run fixture:7`과 `npm run decider:test`는 가상 요청 연습이며 실제 심판 판정이나 운영 접속 증거가 아님. 토큰 원문은 기록하지 않음.


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

### 과거 단계 기록: 6단계 — 등록한 기기만 자료실에 들어옵니다 (날짜·대상 커밋 미상)

현재 기능 (5줄):
1. 기존 Vercel/Supabase 자료실과 브라우저 화면은 그대로 유지
2. 판정기는 `request.deviceRegistered` 값만 사용해 기기 등록 여부를 판단
3. 등록 기기(`true`)는 `allow / approved`로 허용
4. 미등록 또는 값이 없는 기기는 `deny / device_not_registered`로 거부
5. `RULE_IDS`에는 실제 구현한 `device_registered` 규칙만 등록

### 6단계 제작 3 확인 순서

1. 저장소 최신 상태를 받은 뒤 `npm.cmd run decider:test` 실행
2. `통과 · 등록 기기의 정상 요청` 확인
3. `통과 · 미등록 기기의 가상 요청` 확인
4. 미등록 요청은 판정기에서 `deny`, 이유 코드는 `device_not_registered`
5. 이 명령은 가상 요청 연습이며 실제 심판 통과 증거가 아님

이번 단계에는 별도 접속 프로그램 설치가 없으며, 인증서·CA·서명 키·기기 개인키를 새로 만들거나 Git에 저장하지 않음.


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

### 과거 단계 기록: 5단계 — 자료 요청을 서버 한곳으로 모읍니다 (날짜·대상 커밋 미상)

현재 기능 (5줄):
1. 로그인·로그아웃은 Vercel `/api/auth`에서 공식 Supabase Auth SDK 사용
2. 브라우저는 `/api/memos` 서버 함수로만 메모 조회·추가·수정·삭제
3. JWT는 HttpOnly Secure SameSite=Strict 쿠키, 서버는 원본 `src/verify-login.mjs`로 검증
4. 모든 메모 요청은 서버에서 검증한 사용자 ID와 소유자를 비교
5. 비로그인 시 JSON 401, `/data.json` 메모 0건, `/aleph.json` (allowedRoutes 포함) 및 nosniff 유지

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

### 배포 확인

5단계 빌드에서 `scripts/deployment-identity.mjs`가 `/aleph.json`에 `allowedRoutes`, `originalApiUrl`을 포함함. 브라우저에는 Supabase 공개 키가 없고 `api/auth.js`의 Supabase SDK에만 키가 있음. Vercel 서버 인증은 쿠키로 유지하되 기존 심판 Bearer 인증 요청도 지원함.

### 5단계 저장점 및 제출 묶음

```powershell
git status
git pull
npm.cmd run bundle
```

#### Step 12 bundle commit evidence

The Bundle uses only the checked-out Git commit as submission evidence. It reads local `.git` metadata for HEAD, then uses public GitHub HTTPS GET requests to verify the same commit SHA, changed files, and committed `aleph.config.json`. It stops if Git metadata, network access, or committed configuration verification fails.

Uncommitted files are not used as evidence and are not reported as clean. The Bundle compares its four executable source files with the selected GitHub commit and stops if their code differs; unrelated dirty files remain outside the submission evidence instead of being labelled clean. Check `git status`, commit intended changes, then generate the bundle. Do not commit `bundle-notes.json` or `artifacts/submission.json`.

로컬 `bundle-notes.json`의 explanation을 5단계로 바꿔 저장. `artifacts/submission.json` 및 `bundle-notes.json`은 커밋하지 않음.
SQL 권한 회수와 A/B 로그인·CRUD 검증은 실제 실행 전 통과했다고 기록하지 않음.

### 4단계 저장점 — 로그인해도 내 자료만

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

### 3단계 저장점 — 로그인 및 가상 메모 CRUD

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

### 2단계 저장점

정적 파일에 있던 가상 메모를 학습용 Supabase로 옮기고, 화면은 Vercel 서버 함수 `/api/memos`를 통해 읽도록 변경했습니다.

- `supabase/step2-memos.sql`: `owner_id uuid`, RLS 활성화, `anon`·`authenticated` 직접 권한 제거, `auth.users` 외래키 없음
- `data.json`, `public/data.json`: 메모 0건 유지
- `scripts/build-public.mjs`: 2단계 이후 빌드에서 공개 메모를 다시 복사하지 않음
- `api/memos.js`: 서버에서 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수를 읽어 학습용 메모 조회
- `public/index.html`: 브라우저는 서버 API만 호출해 카드 표시
- `aleph.config.json`: 2단계와 실제 GitHub/Vercel 주소 반영
- `vercel.json`: 첫 화면을 포함한 응답에 `X-Content-Type-Options: nosniff` 헤더 적용

### Vercel 환경변수

Vercel 프로젝트 설정의 비밀 입력란에 아래 이름을 사용합니다. 값 자체는 GitHub, 브라우저 파일, 응답, 로그에 넣지 않습니다.

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY`

### 앞 단계 약점의 보완

2단계 공개 API는 3단계에 인증을 적용했고, 3단계 단건 IDOR는 4단계에 서버 측 owner_id 필터를 추가함. 데이터베이스 최소 권한/RLS 적용 여부는 SQL을 실행한 뒤 별도로 확인해야 함.

### 과거 검증 이력: 2단계 파일 확인 결과 (날짜·대상 커밋 미상)

GitHub 기본 브랜치에서 아래 1단계 가상 메모 본문 문장을 각각 검색했습니다.

- `실습용 가상 과제 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 포트폴리오 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 리추얼 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 행정 기록`: 최신 파일 검색 결과 없음

배포 주소의 `/data.json`도 `notes: []` 상태인지 직접 확인합니다. 첫 화면은 정적 파일이 아니라 `/api/memos`를 통해 Supabase의 가상 메모를 읽습니다.

### 과거 공개 이력의 한계

최신 GitHub 파일과 현재 정적 배포에서 메모 문장을 제거했더라도, 이미 만들어진 과거 공개 커밋이나 옛 Vercel 배포가 남아 있는 동안 과거 노출 자체가 해소됐다고 표현하지 않습니다. 2단계에서 확인한 것은 최신 파일과 현재 배포의 정적 노출 경로를 제거한 상태입니다.

### 2단계 당시 직접 확인 절차

1. 배포 주소의 `/`에서 Supabase의 가상 메모 네 건이 표시되는지 확인합니다.
2. `/data.json`을 직접 열어 `notes`가 0건인지 확인합니다.
3. `/aleph.json`을 열어 저장소·커밋·배포 정보가 현재 배포와 맞는지 확인합니다.
4. GitHub 최신 파일에서 위 네 가상 메모 본문 문장을 각각 검색해 결과가 없는지 확인합니다.
5. 2단계 당시 `/api/memos` 비로그인 접근 가능 약점을 기록. 3단계 이후에는 401 JSON 오류로 거부함.
6. 첫 화면 응답 헤더에 `X-Content-Type-Options: nosniff`가 있는지 확인합니다.

### 빌드

Vercel은 `vercel.json`의 `npm run build`를 실행하고 `public`을 배포합니다. 빌드 과정에서 `public/aleph.json`을 자동 생성합니다.


### 과거 검증 이력: 10단계 보완 재시험 결과 (날짜·대상 커밋 미상)
- 정책 사본 신뢰 기준 시험 재확인: `node --test test/step10-policy-backup.test.mjs` → pass 3 / fail 0


- 정책 사본 검증: `npm.cmd run policy:diff`에서 검증 사본과 정책 차이 없음 확인
- 정책 복원 미리보기: `npm.cmd run policy:restore`에서 되돌릴 항목 없음 확인
- 메모 복원 사본 해시: 제목 UTF-8 + NUL(0x00) + 본문 UTF-8의 SHA-256으로 검증
- B 시험 메모 제목을 `훈련 행정 자료 (복구 재시험)`으로 변경 후 `POST /api/restore` 실행
- 실제 배포 응답: HTTP 200, `restored: true`, `contentSha256` 반환
- 새로고침 후 제목이 `훈련 행정 자료`로 원상복구됨
- 복원 전 비공개 사본을 다시 읽어 ID·소유자·내용 해시를 검증하고, 복원 후 DB를 다시 읽어 동일성을 확인함


### 과거 검증 이력: 10단계 정책 복구 재시험 (날짜·대상 커밋 미상)

- `policy:test`: pass 4 / fail 0
- 검증 사본 SHA-256 확인 후 복원 버전·변경 범위 미리보기 확인
- 시험 정책을 `unsafe_v2`로 변경한 뒤 확인값을 사용해 `stage9_verified`로 복원
- 복원 후 `policy:diff`에서 변경 범위 없음 확인
- 실제 운영 정책과 다른 서비스·감사 이력은 변경하지 않음


### 과거 검증 이력: 10단계 복구 API 재검증 (날짜·대상 커밋 미상)

- B 시험 메모를 변조한 뒤 `POST /api/restore` 미리보기에서 HTTP 200, `verified: true`, 백업 `version`, 현재 상태 `stateVersion`, `changedFields: ["title"]` 확인
- 실제 복원 호출에서 미리보기의 `version/stateVersion`을 전달하고, DB 트랜잭션에서 백업과 대상 상태를 다시 읽어 동일할 때만 복원
- 실제 복원 응답 HTTP 200, `restored: true`, `verified: true` 확인
- 새로고침 후 B 메모 제목이 `훈련 행정 자료`로 원상복구됨


### 과거 검증 이력: 10단계 복구 검증 보완 (2026-10-14, 개별 시험 커밋 미상)

- POST /api/restore/:id가 제출용 복구 경로임. {preview:true}는 읽기 전용 미리보기이며 백업 version, 현재 stateVersion, changedFields를 반환함.
- POST /api/restore는 본문의 id를 같은 처리기로 전달함. 당시에는 두 경로 모두 Git에 고정한 백업 ID·버전·시각을 확인함. 현재는 기존 B 사본에만 고정 기준을 적용하고 신규 사본은 해시·HMAC으로 검증함.
- 복원 실행은 백업을 다시 조회하고, DB 잠금 후 재검증하며, 복원 내용 해시를 확인한 뒤 감사 기록을 추가함.
- 미리보기의 version/stateVersion은 expectedVersion/expectedState로 전달 가능함. 현재 호환 인터페이스는 두 값 생략 시 서버에서 실행 직전 조회한 버전을 사용함.
- 잘못된 JSON·null JSON은 400으로 거부함. DB 문법 오류는 백업 무결성 거부와 구분함. 인증 신원 진단 로그는 제거함.
- SQL 해시 구분자는 decode('00','hex')로 명시함. 변경 항목은 jsonb_build_array로 생성함.
- 구형 restore_memo_from_backup RPC의 실행 권한을 폐기함. step10-verified-restore.sql을 실제 DB에 적용 완료함.
- API 격리 시험: npm.cmd run recovery:test → 9개 통과. 인증과 RPC는 가상 응답으로 대체한 시험이며 실제 배포/심판 시험과 구분함.
- 실제 DB 시험: B 메모 제목·본문 임시 변조 후 검증 복원 성공. 손상 백업 복원 거부 및 메모·감사 이력 보존 확인. 시험 변경은 트랜잭션 롤백함.
- 당시 심판 기록: DB JSON 보완 후에도 48점/S10_BACKUP_UNVERIFIED 지속(대상 커밋 미상). 당시 API 보완 직후의 판정은 이 기록에서 미확인이었음. `74e6971` 편집 당시의 판정은 36점이었다. 이후 판정 이력과 현재 운영 버전의 미제출 상태는 문서 상단에서 구분한다.
- 실행하지 않은 실제 배포 API 인증 시험, 전체 심판 공격, 저장소 신규 npm install 시험은 통과로 기록하지 않음.

### 과거 검증 이력: 36점 판정 이후의 제한된 보완 (`3a4e98846b94`, 판정 날짜 미상)
- 심판 커밋 3a4e98846b94는 36점/S10_BACKUP_UNVERIFIED. 12점 하락의 세부 조건은 확인되지 않음.
- API가 verified=true, restored=false인 가상 RPC 응답을 복원 성공으로 잘못 표시하는 실패 시험을 재현함.
- 실제 복원 응답에서 restored=true도 반드시 검사하도록 한 가지 오류를 수정함.
- 당시 RESTORE_TRACE는 도달 단계·인증 종류·고정 지문 일치 여부·허용한 오류 코드만 기록함. 토큰·메모 본문·소유자/요청 ID·해시 원문은 기록하지 않음. `74e6971`에서 사용한 로그 이름은 `BYTEBACK_TRACE`이며 항목별 불리언 진단을 제공함.
- 진단 로그는 다음 심판 요청이 어떤 단계에서 실패하는지 확인하기 위한 것임. 이번 보완을 심판 실패 원인 해결로 단정하지 않음.
- 사전 확인값 생략 허용, 사본의 침해 전 검증 근거, 심판 시험 대상과 고정 B 사본 일치는 여전히 추가 확인 대상임.

### 과거 검증 이력: 소유자 변조 복구 분기 보완 (`3a4e98846b94` 이후, 정확한 날짜·적용 커밋 미상)
- 3a4e98846b94의 36점 화면에서도 변조 복원만 실패하고 삭제 복원·기존 공격 재검사는 통과한 것으로 확인됨.
- 실제 B 메모의 owner_id와 content를 롤백 트랜잭션에서 임시 변조하면 기존 preview_memo_recovery가 owner_mismatch로 중단됨을 재현함.
- 복구 권한은 검증된 사본의 owner_id와 인증된 요청자를 대조함. 변조된 현재 메모의 owner_id는 변경 항목으로 표시하고, 승인된 사본의 원래 소유자로 복원함.
- 미리보기 stateVersion에는 현재 소유자가 포함되므로 미리보기 뒤 소유자/내용이 다시 바뀌면 복원 중단이 유지됨.
- 당시 API와 화면의 변경 항목 목록에 owner_id를 추가했고 복구 대상은 기존 고정 B 사본 한 건이었음. 이후 신규 메모 최초 생성 사본 기능이 추가되어 현재는 그 한 건으로 제한하지 않음.
- 실제 DB에서 원래 백업 소유자의 복원 성공, 다른 소유자의 사본 요청 거부, 다른 메모와 기존 감사 기록 보존, 감사 추가, 손상 사본 거부를 확인함. 시험 변경은 모두 롤백함.
- 재실행 SQL: supabase/step10-owner-recovery-test.sql. B 시험 사본이 존재하는 해당 학습 DB에서만 실행함.
- API 격리 시험 11개 통과. 심판이 실제로 소유자까지 변조하는지는 아직 미확인이므로 이번 보완을 심판 통과로 기록하지 않음.
