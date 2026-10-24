// XDR 제작 3 — T1110 탐지 전용 판단기.
// 아래 PATTERNS는 제작 2의 patterns.json 내용을 그대로 옮긴 상수다.
// 이 모듈은 단독 실행 가능하며 파일·네트워크·ZTNA 정책을 변경하지 않는다.
const PATTERNS = Object.freeze([
  {
    name: '동일 주소·계정의 단시간 로그인 실패 반복',
    mitreId: 'T1110.001',
    condition: {
      sourceAddressField: 'data.srcip',
      accountField: 'data.srcuser',
      failureCountField: 'data.count',
      summaryField: 'rule.description',
      sameSourceAddress: true,
      sameAccount: true,
      windowSeconds: 180,
      minimumFailures: 30,
      requireExplicitFailureAndWindowEvidence: true,
    },
    evidence: 'MITRE ATT&CK T1110.001: 같은 계정에 비밀번호를 반복 추측하면 단시간에 연속된 인증 실패가 발생할 수 있다.',
  },
  {
    name: '여러 계정에 동일 비밀번호 대입',
    mitreId: 'T1110.003',
    condition: {
      sourceAddressField: 'data.srcip',
      accountListField: 'data.accounts',
      summaryField: 'rule.description',
      minimumDistinctAccounts: 8,
      sameSourceAddress: true,
      requireExplicitSamePasswordEvidence: true,
      inspectOrStorePasswordValue: false,
    },
    evidence: 'MITRE ATT&CK T1110.003: 동일하거나 소수의 비밀번호를 여러 계정에 반복 대입하는 방식은 패스워드 스프레잉에 해당한다.',
  },
]);

const readField = (source, dottedPath) => dottedPath.split('.').reduce(
  (value, segment) => (value && typeof value === 'object' ? value[segment] : undefined),
  source,
);

function positiveInteger(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return 0;
  const raw = String(value);
  if (!/^[0-9]{1,8}$/.test(raw)) return 0;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n > 0 ? n : 0;
}

function intervalSeconds(description) {
  // 설명에 실제 시간 창이 명시되어 있을 때만 유효하게 처리한다.
  const m = description.match(/(\d{1,4})\s*(초|분|시간)\s*(?:안에?|이내|동안)/u);
  if (!m) return null;
  const n = positiveInteger(m[1]);
  if (!n) return null;
  return n * ({ 초: 1, 분: 60, 시간: 3600 })[m[2]];
}

function accountCount(alert, description, pattern) {
  // 비밀번호 자체는 읽지 않으며 계정 식별자의 개수만 계산한다.
  const raw = readField(alert, pattern.condition.accountListField);
  if (Array.isArray(raw)) {
    return new Set(raw.filter((v) => typeof v === 'string' && v.trim()).map((v) => v.trim())).size;
  }
  if (typeof raw === 'string') {
    return new Set(raw.split(',').map((v) => v.trim()).filter(Boolean)).size;
  }
  const textCount = description.match(/(?:계정\s*(\d+)\s*개|(?:서로\s*다른\s*)?계정\s*(\d+)\s*개|(?:서로\s*다른\s*)?계정\s*(\d+)\s*곳)/u);
  return textCount ? positiveInteger(textCount[1] || textCount[2] || textCount[3]) : 0;
}

export function decide(alert) {
  const noMatch = { action: 'record', confidence: 0, reason: '일치하는 공격 패턴 없음' };
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return noMatch;

  const description = readField(alert, PATTERNS[0].condition.summaryField);
  const summary = typeof description === 'string' ? description : '';
  const source = readField(alert, PATTERNS[0].condition.sourceAddressField);
  const account = readField(alert, PATTERNS[0].condition.accountField);
  // 출발 주소·계정 확인이 불가능하면 자동 차단 판단을 내리지 않는다.
  if (typeof source !== 'string' || !source.trim()
      || typeof account !== 'string' || !account.trim()) return noMatch;

  const mitre = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some(
    (id) => typeof id === 'string' && (id === 'T1110' || /^T1110\.\d{3}$/.test(id)),
  );
  const failure = /실패/u.test(summary);
  const successOnly = !failure && /성공|로그아웃|유지|열렸/u.test(summary);
  // Password spraying 경보는 실패라는 단어 없이도 반복 대입을 서술할 수 있다.
  const explicitSpraying = /(?:같은|동일)(?:\s*\S+){0,2}\s*비밀번호/u.test(summary)
    && (/여러\s*계정|서로\s*다른\s*계정/u.test(summary)
      || accountCount(alert, summary, PATTERNS[1]) >= PATTERNS[1].condition.minimumDistinctAccounts);
  if (successOnly || (!failure && !explicitSpraying)) return noMatch;

  const count = positiveInteger(readField(alert, PATTERNS[0].condition.failureCountField));
  const window = intervalSeconds(summary);
  const shortWindow = window !== null && window <= PATTERNS[0].condition.windowSeconds;
  const highCount = count >= PATTERNS[0].condition.minimumFailures;
  const ruleLevel = typeof alert?.rule?.level === 'number' ? alert.rule.level : 0;
  const explicitlyMulti = /여러\s*계정|서로\s*다른\s*계정|계정\s*이름을\s*바꿔|계정\s*\d+\s*개|두\s*계정/u.test(summary);
  const multiCount = accountCount(alert, summary, PATTERNS[1]);
  const isMulti = explicitlyMulti || multiCount >= 2;
  const samePassword = /(?:같은|동일)(?:\s*\S+){0,2}\s*비밀번호/u.test(summary);
  const explicitlySameAccount = /같은\s*(?:주소와\s*)?같은\s*계정|한\s*계정/u.test(summary);
  const guessingVariants = /비밀번호를\s*한\s*글자씩\s*바꿔/u.test(summary);
  const regularAutomation = /같은\s*간격/u.test(summary);
  const noSuccess = /성공은\s*없/u.test(summary);

  let repeated = 0;
  let spraying = 0;

  // T1110.001: 직접 확인한 단시간·다회·단일 계정 실패를 우선한다.
  if (highCount && shortWindow && !isMulti) {
    repeated = mitre ? 0.97 : 0.89;
  } else if (count >= 60 && explicitlySameAccount && !isMulti) {
    repeated = mitre ? 0.91 : 0.85;
  } else if (count >= 40 && guessingVariants && !isMulti) {
    repeated = mitre ? 0.88 : 0.83;
  } else if (count >= 90 && noSuccess && !isMulti && ruleLevel >= 10) {
    repeated = mitre ? 0.86 : 0.81;
  } else if (highCount && shortWindow) {
    // 계정 변경이 관찰되면 단일 계정 조건이 없어 차단하지 않는다.
    repeated = 0.79;
  } else if (highCount) {
    repeated = mitre ? 0.74 : 0.61;
  } else if (count >= 8) {
    repeated = mitre ? 0.64 : 0.45;
  } else if (count > 0 && mitre) {
    repeated = count >= 5 ? 0.59 : 0.53;
  }

  // T1110.003: 동일 비밀번호의 '값'을 보지 않고 경보에 명시된 근거만 사용한다.
  if (multiCount >= PATTERNS[1].condition.minimumDistinctAccounts && samePassword) {
    spraying = mitre ? 0.97 : 0.9;
  } else if (isMulti && samePassword) {
    spraying = mitre ? 0.7 : 0.55;
  } else if (isMulti && multiCount >= 15 && regularAutomation) {
    // 여러 계정의 자동화 정황일 뿐 동일 비밀번호는 미확인: 알림만.
    spraying = mitre ? 0.82 : 0.68;
  } else if (isMulti && highCount && shortWindow) {
    spraying = mitre ? 0.8 : 0.68;
  } else if (isMulti && count > 0 && mitre) {
    spraying = count >= 4 ? 0.57 : 0.52;
  }

  const matchedIndex = spraying > repeated ? 1 : 0;
  const confidence = Math.max(repeated, spraying);
  if (confidence < 0.5) return noMatch;
  return {
    action: confidence >= 0.85 ? 'block' : 'alert',
    confidence,
    reason: PATTERNS[matchedIndex].name,
  };
}
