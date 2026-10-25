// Mirrors patterns.json so this module remains standalone for the evaluator.
const PATTERNS = Object.freeze({
  UNSIGNED_SERVICE: {
    name: '서명 없는 새 서비스 등록 또는 실행 파일 변경',
    techniques: ['T1543'],
    minimumRuleLevel: 10,
  },
  TEMPORARY_TASK: {
    name: '낯선 예약 작업의 임시 폴더 실행 파일',
    techniques: ['T1053'],
    minimumRuleLevel: 10,
  },
  STARTUP_REGISTRATION: {
    name: '시작 폴더 또는 시작 프로그램의 비정상 등록',
    techniques: ['T1543', 'T1053'],
    minimumRuleLevel: 10,
  },
  PERSISTENT_SERVICE: {
    name: '평소 목록에 없는 서비스의 재시작 지속 등록',
    techniques: ['T1543'],
    minimumRuleLevel: 10,
  },
});

const NO_MATCH = Object.freeze({
  action: 'record',
  confidence: 0,
  reason: '지속성 공격 근거 없음',
});

function text(value) {
  return typeof value === 'string' ? value : '';
}

function positiveInteger(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return 0;
  const source = String(value);
  if (!/^\d{1,8}$/u.test(source)) return 0;
  const count = Number(source);
  return Number.isSafeInteger(count) && count > 0 ? count : 0;
}

function hasTechnique(mitre, technique) {
  return Array.isArray(mitre) && mitre.some((item) => item === technique);
}

function hasPersistenceTechnique(mitre) {
  return hasTechnique(mitre, 'T1543') || hasTechnique(mitre, 'T1053');
}

function isTemporaryPath(path) {
  return /(?:^|[\\/])(?:temp|tmp)(?:[\\/]|$)|임시\s*폴더|temporary\s*(?:folder|directory)/iu.test(path);
}

function isExplicitBenign(description) {
  return /운영체제\s*업데이트.*평소\s*시각.*그대로|기존.*서비스.*서명된.*실행\s*중|기존\s*예약\s*작업.*수업\s*자료\s*복사|(?:existing|approved).{0,40}(?:signed\s+service|scheduled\s+task)|operating\s*system\s*update.*usual/iu.test(description);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return NO_MATCH;

  const description = text(alert?.rule?.description);
  const path = text(alert?.data?.path);
  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
    ? alert.rule.level
    : 0;
  const count = positiveInteger(alert?.data?.count);
  const mitre = alert?.rule?.mitre;
  const service = /서비스|service/iu.test(description);
  const scheduledTask = /예약\s*작업|scheduled\s*task/iu.test(description);
  const startup = /시작\s*(?:폴더|프로그램|항목)|startup/iu.test(description);
  const unsigned = /서명(?:이|은|는)?\s*(?:없는|없(?:습니다|음|다)?|미확인)|unsigned/iu.test(description);
  const temporary = isTemporaryPath(path) || /임시\s*폴더|temporary\s*(?:folder|directory)/iu.test(description);
  const unfamiliarTask = /처음\s*보는|낯선|임의\s*문자열|random/iu.test(description);
  const newOrRegisteredService = /(?:새|신규).{0,20}서비스|서비스.{0,20}(?:등록|추가)|new\s+service|service\s+(?:registration|added)/iu.test(description);
  const executableChanged = /실행\s*파일.{0,20}(?:바뀌|변경)|(?:executable|binary).{0,20}(?:changed|modified)/iu.test(description);
  const repeatedRemoteRegistration = /원격\s*주소|remote/iu.test(description)
    && /서비스.{0,20}등록|service.{0,20}registration/iu.test(description)
    && count >= 3;
  const unexpectedStartup = /평소\s*목록에\s*없는|예상\s*밖|unexpected|unfamiliar/iu.test(description)
    && /추가|등록|added|registered/iu.test(description);
  const sharedTemporaryExecutable = scheduledTask && temporary
    && /같은.{0,20}임시|임시.{0,20}같은|shared.{0,20}temp/iu.test(description);
  const survivesRestart = /다시\s*켜도\s*남도록|재시작.{0,30}(?:남|등록)|surviv(?:e|es).{0,30}restart/iu.test(description);
  const unexpectedService = service && /평소\s*목록에\s*없는|unexpected|unfamiliar/iu.test(description);

  // Evaluate concrete persistence evidence before any educational-context wording.
  const matches = [];
  if (hasTechnique(mitre, 'T1543') && level >= PATTERNS.UNSIGNED_SERVICE.minimumRuleLevel
      && service && unsigned
      && ((newOrRegisteredService && temporary) || executableChanged || repeatedRemoteRegistration)) {
    matches.push(PATTERNS.UNSIGNED_SERVICE);
  }
  if (hasTechnique(mitre, 'T1053') && level >= PATTERNS.TEMPORARY_TASK.minimumRuleLevel
      && scheduledTask && unfamiliarTask && temporary) {
    matches.push(PATTERNS.TEMPORARY_TASK);
  }
  if ((hasTechnique(mitre, 'T1543') || hasTechnique(mitre, 'T1053'))
      && level >= PATTERNS.STARTUP_REGISTRATION.minimumRuleLevel && startup
      && (unexpectedStartup || sharedTemporaryExecutable)) {
    matches.push(PATTERNS.STARTUP_REGISTRATION);
  }
  if (hasTechnique(mitre, 'T1543') && level >= PATTERNS.PERSISTENT_SERVICE.minimumRuleLevel
      && unexpectedService && survivesRestart) {
    matches.push(PATTERNS.PERSISTENT_SERVICE);
  }

  if (matches.length) {
    return {
      action: 'block',
      confidence: matches.length > 1 ? 0.96 : 0.91,
      reason: matches.map((pattern) => pattern.name).join(' / '),
    };
  }

  if (isExplicitBenign(description)) return NO_MATCH;

  if (hasPersistenceTechnique(mitre)) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: 'T1543/T1053 경보: 자동 차단 근거가 부족한 지속성 의심',
    };
  }

  return NO_MATCH;
}
