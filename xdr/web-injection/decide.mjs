// These constants mirror patterns.json so this decision module remains standalone.
const PATTERNS = Object.freeze([
  {
    name: '반복된 명시적 SQL 주입 구문 탐지',
    condition: { minimumRuleLevel: 10, minimumCount: 10, requireMitreTechnique: 'T1190' },
  },
  {
    name: '반복된 명시적 스크립트 삽입 표식 탐지',
    condition: { minimumRuleLevel: 10, minimumCount: 9, requireMitreTechnique: 'T1190' },
  },
  {
    name: '반복된 상위 경로 탐색 표식 탐지',
    condition: { minimumRuleLevel: 11, minimumCount: 8, requireMitreTechnique: 'T1190' },
  },
  {
    name: '반복된 명령 구분자 주입 표식 탐지',
    condition: { minimumRuleLevel: 11, minimumCount: 10, requireMitreTechnique: 'T1190' },
  },
]);

const NO_MATCH = Object.freeze({
  action: 'record',
  confidence: 0,
  reason: '일치하는 웹 주입 공격 패턴 없음',
});

function positiveInteger(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return 0;
  const text = String(value);
  if (!/^[0-9]{1,8}$/u.test(text)) return 0;
  const count = Number(text);
  return Number.isSafeInteger(count) && count > 0 ? count : 0;
}

function hasT1190(value) {
  return Array.isArray(value) && value.some((item) => item === 'T1190');
}

function patternMatches(pattern, { level, count, mitre, evidence }) {
  return mitre
    && evidence
    && level >= pattern.condition.minimumRuleLevel
    && count >= pattern.condition.minimumCount;
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return NO_MATCH;

  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
    ? alert.rule.level
    : 0;
  const count = positiveInteger(alert?.data?.count);
  const mitre = hasT1190(alert?.rule?.mitre);
  if (!description) return NO_MATCH;

  // data.url may contain educational doc-* labels. It is deliberately not used as payload proof.
  const sqlEvidence = /(?:SQL\s*(?:주입(?:\s*구문)?|표식|형식)|SQL\s*구문.*(?:이어\s*붙|표(?:식|기)|요청)|데이터베이스\s*조회.*이어\s*붙)/iu.test(description);
  const scriptEvidence = /스크립트\s*(?:삽입|표식|형식)/u.test(description);
  const pathEvidence = /(?:경로.*(?:거슬러\s*올라|이탈)|상위\s*경로|\.\.\/).*표(?:식|기)/u.test(description);
  const commandEvidence = /명령\s*구분자.*표(?:식|기)/u.test(description);
  const evidence = [sqlEvidence, scriptEvidence, pathEvidence, commandEvidence];
  const matches = PATTERNS.filter((pattern, index) => patternMatches(pattern, {
    level,
    count,
    mitre,
    evidence: evidence[index],
  }));

  if (matches.length) {
    return {
      action: 'block',
      confidence: matches.length > 1 ? 0.96 : 0.91,
      reason: matches.map((pattern) => pattern.name).join(' / '),
    };
  }

  const explicitBenignContext = /정상\s*조회|삽입\s*형식.*아닙|공격\s*표식.*없|normal\s*search|not\s*(?:an\s*)?injection|no\s*attack\s*marker/iu.test(description);
  const suspiciousSignal = /특수\s*문자|따옴표|이상한\s*검색|주입처럼|구분\s*문자|suspicious\s*(?:query|input)|injection[- ]?like|delimiter|\b(?:sql|script|path|command)\s*(?:injection|traversal|separator)\b/iu.test(description);
  if (mitre && (suspiciousSignal
    || (!explicitBenignContext && (sqlEvidence || scriptEvidence || pathEvidence || commandEvidence)))) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: '반복 또는 명시적 공격 근거가 부족한 웹 주입 의심',
    };
  }

  // A valid T1190 Wazuh finding without block-grade evidence remains reviewable.
  // This preserves an ambiguous detector signal without promoting it to a denial rule.
  if (mitre && count > 0) {
    return {
      action: 'alert',
      confidence: 0.5,
      reason: 'T1190 경보: 차단 근거가 부족한 웹 주입 의심',
    };
  }

  return NO_MATCH;
}
