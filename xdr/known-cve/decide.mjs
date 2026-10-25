// Mirrors patterns.json so this module stays standalone for the evaluator.
const PATTERNS = Object.freeze({
  HEADER_JNDI: '머리글의 명시적 JNDI 원격 조회 구문',
  URL_JNDI: 'URL 또는 요청 인자의 명시적 JNDI 원격 조회 구문',
  SCANNER_TRACE: '명시적 Log4Shell 취약점 점검 도구 흔적',
});

const NO_MATCH = Object.freeze({
  action: 'record',
  confidence: 0,
  reason: '알려진 취약점 악용 근거 없음',
});

function text(value) {
  return typeof value === 'string' ? value : '';
}

function hasT1190(mitre) {
  return Array.isArray(mitre) && mitre.some((item) => item === 'T1190');
}

function hasJndiRemoteLookup(value) {
  // A bare "jndi" word or braces are not enough: require a complete remote lookup form.
  return /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nis)\s*:/iu.test(value);
}

function isExplicitScannerTrace(description) {
  return /알려진\s*취약점\s*점검\s*흔적|(?:log4shell|cve[- ]?2021[- ]?44228).{0,40}(?:점검|scanner|scan)/iu.test(description);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return NO_MATCH;

  const mitre = hasT1190(alert?.rule?.mitre);
  const description = text(alert?.rule?.description);
  const header = text(alert?.data?.useragent);
  const url = text(alert?.data?.url);
  const headerLookup = hasJndiRemoteLookup(header);
  const urlLookup = hasJndiRemoteLookup(url);

  // Explicit payload evidence has priority over educational or documentation wording.
  if (mitre && urlLookup && isExplicitScannerTrace(description)) {
    return {
      action: 'block',
      confidence: 0.96,
      reason: PATTERNS.SCANNER_TRACE,
    };
  }

  if (mitre && headerLookup) {
    return {
      action: 'block',
      confidence: 0.93,
      reason: PATTERNS.HEADER_JNDI,
    };
  }

  if (mitre && urlLookup) {
    return {
      action: 'block',
      confidence: 0.91,
      reason: PATTERNS.URL_JNDI,
    };
  }

  // Preserve T1190 detector signals for review when no block-grade payload is present.
  if (mitre) {
    return {
      action: 'alert',
      confidence: 0.55,
      reason: 'T1190 경보: 명시적 JNDI 원격 조회 구문 미확인',
    };
  }

  return NO_MATCH;
}
